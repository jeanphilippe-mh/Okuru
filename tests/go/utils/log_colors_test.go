package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestColorLogPrefixUsesExactRequestedColors(t *testing.T) {
	for _, tc := range []struct {
		name, input, prefix string
	}{
		{"info blue", `[INFO] {"level":"info"}`, "\x1b[34m[INFO]\x1b[0m "},
		{"warning orange", `[WARNING] {"level":"warning"}`, "\x1b[38;2;255;165;0m[WARNING]\x1b[0m "},
		{"error red", `[ERROR] {"level":"error"}`, "\x1b[31m[ERROR]\x1b[0m "},
		{"action bold yellow", `[ACTION] {"category":"user_action","level":"info"}`, "\x1b[1;33m[ACTION]\x1b[0m "},
		{"security bold gray", `[SECURITY] {"category":"security","level":"warning"}`, "\x1b[1;38;2;180;180;180m[SECURITY]\x1b[0m "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input + "\n")
			original := append([]byte(nil), input...)
			colored := colorLogPrefix(input)
			if !bytes.HasPrefix(colored, []byte(tc.prefix)) {
				t.Fatalf("incorrect prefix: %q", colored)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("coloring modified the input or JSON payload")
			}
			if stripLogFileColors(string(colored)) != string(original) {
				t.Fatalf("coloring changed data beyond the prefix: %q", colored)
			}
		})
	}
	for _, input := range []string{"[INFO]forged", "[DEBUG] {}", "unstructured input", ""} {
		if got := string(colorLogPrefix([]byte(input))); got != input {
			t.Errorf("unexpected coloration for %q: %q", input, got)
		}
	}
}

func TestColorLogPrefixPreservesLargeRecord(t *testing.T) {
	input := `[SECURITY] {"category":"security","level":"warning","msg":"` + strings.Repeat("x", maxProcessOutputFragment-128) + `"}` + "\n"
	colored := colorLogPrefix([]byte(input))
	if !bytes.HasPrefix(colored, []byte("\x1b[1;38;2;180;180;180m[SECURITY]\x1b[0m ")) {
		t.Fatal("large security record lost its color prefix")
	}
	if got := stripLogFileColors(string(colored)); got != input {
		t.Fatal("coloring changed a large structured record")
	}
}

func TestLogSupervisorColorFileAndPlainJournal(t *testing.T) {
	for _, tc := range []struct {
		name, noColor string
		color         bool
	}{
		{"default colors", "", true},
		{"NO_COLOR disables ANSI", "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tc.noColor)
			binary, args := supervisorTestCommand(t, "colors")
			path := filepath.Join(t.TempDir(), "okuru.log")
			if err := os.WriteFile(path, []byte("previous\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var journal bytes.Buffer
			code, err := RunLogSupervisor(binary, args, path, &journal)
			if err != nil || code != 0 {
				t.Fatalf("supervisor exit: %d, %v", code, err)
			}
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(journal.Bytes(), []byte("\x1b")) {
				t.Fatalf("journald received ANSI sequences: %q", journal.String())
			}
			if strings.Contains(stripLogFileColors(string(file)), "\x1b") || !strings.Contains(journal.String(), `\u001b[2J`) {
				t.Fatalf("untrusted terminal control was not safely escaped: %q", journal.String())
			}
			if strings.Count(journal.String(), "\n[ACTION] ") != 1 {
				t.Fatalf("untrusted stderr impersonated an action: %q", journal.String())
			}
			if stripLogFileColors(string(file)) != "previous\n"+journal.String() {
				t.Fatalf("file payload does not match journal: %q", string(file))
			}
			if tc.color {
				for _, prefix := range []string{"\x1b[34m[INFO]\x1b[0m", "\x1b[38;2;255;165;0m[WARNING]\x1b[0m", "\x1b[31m[ERROR]\x1b[0m", "\x1b[1;33m[ACTION]\x1b[0m", "\x1b[1;38;2;180;180;180m[SECURITY]\x1b[0m"} {
					if !strings.Contains(string(file), prefix) {
						t.Errorf("file is missing requested color %q", prefix)
					}
				}
			} else if bytes.Contains(file, []byte("\x1b")) {
				t.Fatalf("NO_COLOR still emitted ANSI sequences: %q", string(file))
			}
		})
	}
}
