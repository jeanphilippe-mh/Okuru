// okurutest runs centralized tests in their original Go packages.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/jeanphilippe-mh/Okuru/tests/internal/suite"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "test" && os.Args[1] != "vet" && os.Args[1] != "tidy") {
		fmt.Fprintln(os.Stderr, "Usage: go run ./tests/cmd/okurutest {test|vet|tidy} [Go flags]")
		os.Exit(2)
	}
	root, err := suite.FindRoot()
	if err == nil {
		err = suite.Run(root, os.Args[1], os.Args[2:], os.Stdout, os.Stderr)
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() > 0 {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
