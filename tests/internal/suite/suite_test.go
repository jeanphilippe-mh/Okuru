package suite

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newCheckout creates a small isolated project; no real checkout is changed.
func newCheckout(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.test/okuru\ngo 1.27.4\n")
	writeFixture(t, root, "controllers/controller.go", "package controllers\n")
	writeFixture(t, root, "tests/_suites/root/main_test.go", "package main\n")
	writeFixture(t, root, "tests/_suites/root/README.md", "Root suite\n")
	writeFixture(t, root, "tests/_suites/controllers/controller_test.go", "package controllers\n")
	writeFixture(t, root, "tests/_suites/controllers/README.md", "Controller suite\n")
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
		{"main_test.go", "tests/_suites/root/main_test.go"},
		{"controllers/controller_test.go", "tests/_suites/controllers/controller_test.go"},
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
		writeFixture(t, root, "tests/_suites/controllers/new_test.go", "package controllers\n")
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
		writeFixture(t, root, "tests/_suites/root/controllers/controller_test.go", "package controllers\n")
		writeFixture(t, root, "tests/suites.manifest", "root/main_test.go\ncontrollers/controller_test.go\nroot/controllers/controller_test.go\n")
		_, _, err := Overlay(root)
		requireError(t, err, "Duplicate test destination")
	})
}

func TestOverlayRejectsSymlinksAndRunnerRecursion(t *testing.T) {
	t.Run("symbolic link", func(t *testing.T) {
		root := newCheckout(t)
		target := filepath.Join(root, "tests", "_suites", "root", "main_test.go")
		link := filepath.Join(root, "tests", "_suites", "root", "link_test.go")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("Symbolic link creation is unavailable: %v", err)
		}
		_, _, err := Overlay(root)
		requireError(t, err, "Symbolic links")
	})
	t.Run("case insensitive runner path", func(t *testing.T) {
		root := newCheckout(t)
		writeFixture(t, root, "tests/_suites/Tests/recurse_test.go", "package tests\n")
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
}
