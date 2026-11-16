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
		{"error bold red", `[ERROR] {"level":"error"}`, "\x1b[1;31m[ERROR]\x1b[0m "},
		{"action bold purple", `[ACTION] {"category":"user_action","level":"info"}`, "\x1b[1;38;2;180;120;255m[ACTION]\x1b[0m "},
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

func TestBoldStructuredMessagePreservesJSONBytes(t *testing.T) {
	for _, tc := range []struct {
		name, input, styled string
	}{
		{"error msg first", `[ERROR] {"msg":"Failure","event":"test"}`, `"msg":"\x1b[1mFailure\x1b[22m"`},
		{"action msg last", `[ACTION] {"event":"test","msg":"Secret viewed"}`, `"msg":"\x1b[1mSecret viewed\x1b[22m"`},
		{"security utf8 and escaped", `[SECURITY] {"nested":{"msg":"decoy"},"msg":"Détecté : \"test\" \\path","event":"test"}`, `"msg":"\x1b[1mDétecté : \"test\" \\path\x1b[22m"`},
		{"escaped field name", `[ERROR] {"m\u0073g" : "error\\nnext","nested":{"msg":"decoy"}}`, `"m\u0073g" : "\x1b[1merror\\nnext\x1b[22m"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.input + "\n"
			colored := string(colorLogPrefix([]byte(original)))
			want := strings.ReplaceAll(tc.styled, `\x1b`, "\x1b")
			if !strings.Contains(colored, want) {
				t.Fatalf("message was not correctly styled: %q", colored)
			}
			if got := stripLogFileColors(colored); got != original {
				t.Fatalf("ANSI removal changed the record: %q", got)
			}
		})
	}
}

func TestBoldStructuredMessageSkipsAmbiguousOrNonStringFields(t *testing.T) {
	for _, input := range []string{
		`[ERROR] {"nested":{"msg":"decoy"},"event":"test"}`,
		`[ACTION] {"msg":null}`,
		`[SECURITY] {"msg":123}`,
		`[ERROR] {"msg":{"msg":"nested"}}`,
		`[ERROR] {"msg":"first","msg":"second"}`,
		`[ERROR] {"msg":"first"} {"msg":"second"}`,
		`[ERROR] {"msg":"unterminated}`,
		`[INFO] {"msg":"not bold"}`,
		`[WARNING] {"msg":"not bold"}`,
	} {
		t.Run(input, func(t *testing.T) {
			colored := string(colorLogPrefix([]byte(input + "\n")))
			if strings.Contains(colored, "\x1b[1m") || strings.Contains(colored, "\x1b[22m") {
				t.Fatalf("unexpected message bolding: %q", colored)
			}
			if got := stripLogFileColors(colored); got != input+"\n" {
				t.Fatalf("ANSI removal changed record: %q", got)
			}
		})
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
				for _, prefix := range []string{"\x1b[34m[INFO]\x1b[0m", "\x1b[38;2;255;165;0m[WARNING]\x1b[0m", "\x1b[1;31m[ERROR]\x1b[0m", "\x1b[1;38;2;180;120;255m[ACTION]\x1b[0m", "\x1b[1;38;2;180;180;180m[SECURITY]\x1b[0m"} {
					if !strings.Contains(string(file), prefix) {
						t.Errorf("file is missing requested color %q", prefix)
					}
				}
				for _, message := range []string{"Error detail", "Action detail", "Security detail"} {
					if !strings.Contains(string(file), "\x1b[1m"+message+"\x1b[22m") {
						t.Errorf("file message is not bold: %q", message)
					}
				}
			} else if bytes.Contains(file, []byte("\x1b")) {
				t.Fatalf("NO_COLOR still emitted ANSI sequences: %q", string(file))
			}
		})
	}
}
