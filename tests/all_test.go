package tests

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/tests/internal/suite"
)

var childArgs []string

// TestMain avoids a cached green result for the harness after source or fixture
// changes. A failing test is never cached, so the explicit requirement remains
// effective for every plain `go test` invocation.
func TestMain(m *testing.M) {
	flag.Parse()
	explicitCount := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "test.count" && f.Value.String() == "1" {
			explicitCount = true
		}
	})
	if !explicitCount {
		fmt.Fprintln(os.Stderr, "Use go test -count=1 ./... or go run ./tests/cmd/okurutest test; cached wrapper results are unsafe")
		os.Exit(1)
	}
	for _, name := range []string{"test.list", "test.bench", "test.fuzz", "test.coverprofile", "test.run", "test.skip"} {
		if f := flag.Lookup(name); f != nil && f.Value.String() != "" {
			fmt.Fprintln(os.Stderr, "Use go run ./tests/cmd/okurutest test for filters, list, benchmark, fuzz, or coverage options")
			os.Exit(1)
		}
	}
	if testing.CoverMode() != "" {
		fmt.Fprintln(os.Stderr, "Use go run ./tests/cmd/okurutest test for coverage")
		os.Exit(1)
	}
	childArgs = append(childArgs, "-count=1")
	if raceEnabled {
		childArgs = append(childArgs, "-race")
	}
	// Forward supported execution options to the projected suites.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "test.parallel", "test.timeout", "test.shuffle", "test.cpu":
			childArgs = append(childArgs, "-"+f.Name[5:]+"="+f.Value.String())
		case "test.short", "test.failfast":
			if f.Value.String() == "true" {
				childArgs = append(childArgs, "-"+f.Name[5:])
			}
		case "test.v":
			if f.Value.String() != "false" {
				childArgs = append(childArgs, "-v")
			}
		}
	})
	os.Exit(m.Run())
}

func TestSuiteHarness(t *testing.T) {
	root, err := suite.FindRoot()
	if err == nil {
		err = suite.Run(root, "test", childArgs, os.Stdout, os.Stderr)
	}
	if err != nil {
		t.Fatal(err)
	}
}
