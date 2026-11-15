package main

import (
	"os"
	"strings"
	"testing"
)

// The supervisor must be the main process: systemd's mixed kill mode delivers
// SIGTERM to it first, so it can stop the worker and drain its output.
func TestServiceUsesLogSupervisor(t *testing.T) {
	unit, err := os.ReadFile("okuru.service")
	if err != nil {
		t.Fatal(err)
	}
	content := string(unit)
	for _, line := range []string{
		"ExecStart=/home/freebox/Okuru/Okuru --internal-log-supervisor",
		"KillMode=mixed",
		"StandardOutput=journal",
		"StandardError=journal",
	} {
		if !strings.Contains(content, "\n"+line+"\n") {
			t.Errorf("service does not contain %q", line)
		}
	}
}
