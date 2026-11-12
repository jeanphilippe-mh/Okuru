package suite

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newCheckout creates a small isolated project; no real checkout is changed.
func newCheckout(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.test/okuru\n\ngo 1.27.4\n\nignore ./tests/go\n")
	writeFixture(t, root, "controllers/controller.go", "package controllers\n")
	writeFixture(t, root, "tests/go/root/main_test.go", "package main\n")
	writeFixture(t, root, "tests/go/root/README.md", "Root suite\n")
	writeFixture(t, root, "tests/go/controllers/controller_test.go", "package controllers\n")
	writeFixture(t, root, "tests/go/controllers/README.md", "Controller suite\n")
	writeFixture(t, root, "tests/suites.manifest", "root/main_test.go\ncontrollers/controller_test.go\n")
	return root
}

func writeFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got error %v; want an error containing %q", err, want)
	}
}

func TestOverlayMapsSuitesAndPermitsDocumentation(t *testing.T) {
	root := newCheckout(t)
	got, packages, err := Overlay(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{"main_test.go", "tests/go/root/main_test.go"},
		{"controllers/controller_test.go", "tests/go/controllers/controller_test.go"},
	} {
		target := filepath.Join(root, filepath.FromSlash(pair[0]))
		backing := filepath.Join(root, filepath.FromSlash(pair[1]))
		if got[target] != backing {
			t.Errorf("overlay[%q] = %q; want %q", target, got[target], backing)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d overlay entries, want 2", len(got))
	}
	if len(packages) < 2 || packages[0] != "." || packages[1] != "./controllers" {
		t.Fatalf("unexpected package list: %v", packages)
	}
}

func TestOverlayRejectsMissingOrUnlistedTests(t *testing.T) {
	t.Run("missing manifest", func(t *testing.T) {
		root := newCheckout(t)
		if err := os.Remove(filepath.Join(root, "tests", "suites.manifest")); err != nil {
			t.Fatal(err)
		}
		_, _, err := Overlay(root)
		requireError(t, err, "manifest")
	})
	t.Run("manifest entry missing", func(t *testing.T) {
		root := newCheckout(t)
		writeFixture(t, root, "tests/suites.manifest", "root/main_test.go\ncontrollers/missing_test.go\n")
		_, _, err := Overlay(root)
		requireError(t, err, "missing")
	})
	t.Run("unlisted file", func(t *testing.T) {
		root := newCheckout(t)
		writeFixture(t, root, "tests/go/controllers/new_test.go", "package controllers\n")
		_, _, err := Overlay(root)
		requireError(t, err, "not listed")
	})
}

func TestOverlayRejectsScatteredTestsAndDuplicateTargets(t *testing.T) {
	t.Run("physical test outside tests", func(t *testing.T) {
		root := newCheckout(t)
		writeFixture(t, root, "controllers/unmigrated_test.go", "package controllers\n")
		_, _, err := Overlay(root)
		requireError(t, err, "outside tests/")
	})
	t.Run("duplicate projection", func(t *testing.T) {
		root := newCheckout(t)
		writeFixture(t, root, "tests/go/root/controllers/controller_test.go", "package controllers\n")
		writeFixture(t, root, "tests/suites.manifest", "root/main_test.go\ncontrollers/controller_test.go\nroot/controllers/controller_test.go\n")
		_, _, err := Overlay(root)
		requireError(t, err, "Duplicate test destination")
	})
}

func TestOverlayRejectsSymlinksAndRunnerRecursion(t *testing.T) {
	t.Run("symbolic link", func(t *testing.T) {
		root := newCheckout(t)
		target := filepath.Join(root, "tests", "go", "root", "main_test.go")
		link := filepath.Join(root, "tests", "go", "root", "link_test.go")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("Symbolic link creation is unavailable: %v", err)
		}
		_, _, err := Overlay(root)
		requireError(t, err, "Symbolic links")
	})
	t.Run("case insensitive runner path", func(t *testing.T) {
		root := newCheckout(t)
		writeFixture(t, root, "tests/go/Tests/recurse_test.go", "package tests\n")
		writeFixture(t, root, "tests/suites.manifest", "root/main_test.go\ncontrollers/controller_test.go\nTests/recurse_test.go\n")
		_, _, err := Overlay(root)
		requireError(t, err, "cannot target its own runner")
	})
}

func TestRunRejectsUnsafeFlagsAndPackageSelection(t *testing.T) {
	root := newCheckout(t)
	for _, args := range [][]string{
		{"-overlay=/tmp/empty.json"},
		{"-overlay", "/tmp/empty.json"},
		{"--overlay=/tmp/empty.json"},
		{"./..."},
		{"--", "./..."},
		{"--", "./tests"},
		{"-args"},
		{"-C=/tmp"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if err := Run(root, "test", args, io.Discard, io.Discard); err == nil {
				t.Fatalf("Run accepted unsafe arguments %q", args)
			}
		})
	}
	if err := Run(root, "tidy", []string{"--", "./controllers"}, io.Discard, io.Discard); err == nil {
		t.Fatal("Tidy accepted a package selection")
	}
}

func goBinary() string {
	name := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func TestModuleIgnoreExcludesCentralizedSourcesFromPackagePatterns(t *testing.T) {
	root := newCheckout(t)
	writeFixture(t, root, "main.go", "package main\n")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "")
	cmd := exec.Command(goBinary(), "list", "./...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "tests/go") || !strings.Contains(string(out), "example.test/okuru/controllers") {
		t.Fatalf("unexpected package list: %s", out)
	}
}

func TestTidyRetainsTestOnlyDependency(t *testing.T) {
	root := newCheckout(t)
	writeFixture(t, root, "go.mod", "module example.test/okuru\n\ngo 1.27.4\n\nignore ./tests/go\n\nrequire example.test/dep v0.0.0\n\nreplace example.test/dep => ./dep\n")
	writeFixture(t, root, "main.go", "package main\n")
	writeFixture(t, root, "dep/go.mod", "module example.test/dep\n\ngo 1.27.4\n")
	writeFixture(t, root, "dep/dep.go", "package dep\nconst Want = 42\n")
	writeFixture(t, root, "tests/go/root/main_test.go", "package main\nimport (\"testing\"; \"example.test/dep\")\nfunc TestDependency(t *testing.T) { if dep.Want != 42 { t.Fatal(\"unexpected value\") } }\n")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOFLAGS", "")
	before, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	// Plain tidy cannot see the centralized test and proposes deleting the
	// only dependency it imports. -diff observes the result without writing.
	cmd := exec.Command(goBinary(), "mod", "tidy", "-diff")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "-require example.test/dep v0.0.0") {
		t.Fatalf("plain tidy did not propose removing the test-only dependency: %v\n%s", err, out)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(root, "tidy", []string{"-diff"}, &stdout, &stderr); err != nil {
		t.Fatalf("overlay tidy failed: %v\n%s%s", err, stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("tidy -diff changed go.mod: %v", err)
	}
}
