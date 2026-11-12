// Package suite projects centralized tests into their original Go packages.
package suite

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// FindRoot locates the checkout when invoked from the root or a subdirectory.
func FindRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		_, modErr := os.Stat(filepath.Join(dir, "go.mod"))
		st, suitesErr := os.Stat(filepath.Join(dir, "tests", "go"))
		if modErr == nil && suitesErr == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("Cannot locate the Okuru test suites")
		}
		dir = parent
	}
}

// Overlay maps each stored _test.go file to its original package directory.
// It refuses ambiguous or missing package destinations and physical tests at
// destination paths, so a partial migration cannot silently hide tests.
func Overlay(root string) (map[string]string, []string, error) {
	// Guard the centralization invariant after future merges. Ignore directories
	// the Go tool excludes and common generated or local data directories.
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root {
			name := d.Name()
			if path == filepath.Join(root, "tests") || strings.HasPrefix(name, ".") ||
				strings.HasPrefix(name, "_") || name == "vendor" || name == "node_modules" ||
				(filepath.Dir(path) == root && (name == "data" || name == "work")) {
				return filepath.SkipDir
			}
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), "_test.go") {
			return fmt.Errorf("Go test outside tests/: %s", path)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	suites := filepath.Join(root, "tests", "go")
	manifest, err := os.ReadFile(filepath.Join(root, "tests", "suites.manifest"))
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot read the test suite manifest: %w", err)
	}
	expected := make(map[string]bool)
	for _, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if expected[line] {
			return nil, nil, fmt.Errorf("Duplicate manifest entry: %s", line)
		}
		expected[line] = true
	}
	entries, err := os.ReadDir(suites)
	if err != nil {
		return nil, nil, err
	}
	replacements := make(map[string]string)
	packages := make(map[string]bool)
	found := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("Unexpected test suite entry %q", entry.Name())
		}
		base := root
		if entry.Name() != "root" {
			base = filepath.Join(root, entry.Name())
		}
		dir := filepath.Join(suites, entry.Name())
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("Symbolic links are not allowed in test suites: %s", path)
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() == "README.md" {
				return nil
			}
			if !strings.HasSuffix(d.Name(), "_test.go") {
				return fmt.Errorf("Unexpected file in test suites: %s", path)
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			target := filepath.Join(base, rel)
			targetRel, err := filepath.Rel(root, target)
			if err != nil {
				return err
			}
			if strings.EqualFold(strings.Split(targetRel, string(filepath.Separator))[0], "tests") {
				return fmt.Errorf("Test suite cannot target its own runner: %s", target)
			}
			info, err := os.Stat(filepath.Dir(target))
			if err != nil || !info.IsDir() {
				return fmt.Errorf("Missing destination package for %s", path)
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				return fmt.Errorf("Test destination already exists or cannot be checked: %s", target)
			}
			if _, exists := replacements[target]; exists {
				return fmt.Errorf("Duplicate test destination: %s", target)
			}
			replacements[target] = path
			manifestName, err := filepath.Rel(suites, path)
			if err != nil {
				return err
			}
			found[filepath.ToSlash(manifestName)] = true
			pkg, err := filepath.Rel(root, filepath.Dir(target))
			if err != nil {
				return err
			}
			if pkg == "." {
				packages["."] = true
			} else {
				packages["./"+filepath.ToSlash(pkg)] = true
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if len(replacements) == 0 {
		return nil, nil, fmt.Errorf("No Go tests found in the centralized suites")
	}
	for name := range expected {
		if !found[name] {
			return nil, nil, fmt.Errorf("Manifest test is missing: %s", name)
		}
	}
	for name := range found {
		if !expected[name] {
			return nil, nil, fmt.Errorf("Test is not listed in tests/suites.manifest: %s", name)
		}
	}
	list := make([]string, 0, len(packages))
	for name := range packages {
		list = append(list, name)
	}
	// The runner's own tests already live under tests/ and need no projection.
	list = append(list, "./tests/internal/suite")
	sort.Strings(list)
	return replacements, list, nil
}

// Run invokes go test, go vet, or go mod tidy with a temporary overlay.
// Individual test package paths avoid recursively executing the harness.
func Run(root, command string, args []string, stdout, stderr io.Writer) error {
	if command != "test" && command != "vet" && command != "tidy" {
		return fmt.Errorf("Unsupported Go command %q", command)
	}
	replace, packages, err := Overlay(root)
	if err != nil {
		return err
	}
	flags := args
	selected := []string(nil)
	for i, arg := range args {
		if arg != "--" {
			continue
		}
		flags, selected = args[:i], args[i+1:]
		if command == "tidy" {
			return fmt.Errorf("Package selection is not supported for go mod tidy")
		}
		if len(selected) == 0 {
			return fmt.Errorf("Specify at least one package after --")
		}
		valid := make(map[string]bool, len(packages))
		for _, name := range packages {
			valid[name] = true
		}
		for j, name := range selected {
			if name == "./" {
				name, selected[j] = ".", "."
			}
			if !valid[name] {
				return fmt.Errorf("Unknown test package %q", name)
			}
		}
		break
	}
	valueFlags := map[string]bool{
		"-run": true, "-skip": true, "-count": true, "-parallel": true, "-timeout": true,
		"-shuffle": true, "-cpu": true, "-tags": true, "-bench": true, "-benchtime": true,
		"-covermode": true, "-coverpkg": true, "-coverprofile": true, "-fuzz": true,
		"-fuzztime": true, "-fuzzminimizetime": true, "-list": true, "-vet": true,
		"-p": true, "-gcflags": true, "-ldflags": true, "-asmflags": true,
		"-mod": true, "-modfile": true, "-o": true, "-exec": true, "-outputdir": true,
		"-go": true, "-compat": true,
	}
	for _, arg := range flags {
		if !strings.HasPrefix(arg, "-") {
			return fmt.Errorf("Use -flag=value for option values and put packages after --: %q", arg)
		}
		name := strings.SplitN(arg, "=", 2)[0]
		if name == "-overlay" || name == "--overlay" || name == "-C" || name == "-args" {
			return fmt.Errorf("Go option %q is not supported by the centralized runner", name)
		}
		if valueFlags[name] && !strings.Contains(arg, "=") {
			return fmt.Errorf("Use %s=value for this Go option", name)
		}
	}
	f, err := os.CreateTemp("", "okuru-test-overlay-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := json.NewEncoder(f).Encode(struct {
		Replace map[string]string
	}{replace}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	argv := []string{command, "-overlay", f.Name()}
	if command == "tidy" {
		argv = []string{"mod", "tidy", "-overlay", f.Name()}
	} else if command == "vet" && len(selected) == 0 {
		argv = append(argv, "./...")
	} else {
		if command == "test" {
			argv = append(argv, "-count=1")
		}
		if len(selected) != 0 {
			argv = append(argv, selected...)
		} else {
			argv = append(argv, packages...)
		}
	}
	argv = append(argv, flags...)
	name := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	cmd := exec.Command(name, argv...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = root, stdout, stderr
	return cmd.Run()
}
