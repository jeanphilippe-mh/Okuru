package utils

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestNormalizeProcessOutputPreservesRecordsAndWrapsRawLines(t *testing.T) {
	first := `[INFO] {"event":"http.request","level":"info","msg":"done"}`
	action := `[WARNING] {"category":"user_action","event":"file.denied","level":"warning","msg":"denied"}`
	last := `[ERROR] {"level":"error","msg":"final structured record"}`
	input := first + "\n" + action + "\n" + "2026/11/15 23:23:41 timeout waiting for PING response\n" + "panic: failure\n" + last
	var output bytes.Buffer
	if err := NormalizeProcessOutput(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(output.String(), "\n") {
		t.Fatal("unterminated final record was not completed with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 5 || lines[0] != first || lines[1] != action || lines[4] != last {
		t.Fatalf("structured output changed: %q", output.String())
	}
	for i, want := range []string{"2026/11/15 23:23:41 timeout waiting for PING response", "panic: failure"} {
		record := decodeProcessRecord(t, lines[i+2])
		if record["msg"] != want || record["event"] != "process.output" || record["level"] != "error" {
			t.Fatalf("unexpected raw record: %v", record)
		}
		timestamp, ok := record["time"].(string)
		if !ok || !strings.HasSuffix(timestamp, "Z") {
			t.Fatalf("missing UTC timestamp: %v", record)
		}
		if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
			t.Fatalf("invalid timestamp: %v", err)
		}
	}
}

func TestNormalizeProcessOutputWrapsForgedOrMalformedPrefixes(t *testing.T) {
	for _, line := range []string{
		`[INFO] not-json`,
		`[INFO] {"level":"error","msg":"mismatch"}`,
		`[ACTION] {"level":"info","msg":"missing action category"}`,
		`[INFO] {"level":"info","category":"user_action"}`,
		`[SECURITY] {"level":"info","category":"security"}`,
		`[SECURITY] {"level":"warning","category":"user_action"}`,
		`[WARNING] {"level":"warning","category":"security"}`,
		`[INFO] "not an object"`,
	} {
		var output bytes.Buffer
		if err := NormalizeProcessOutput(strings.NewReader(line+"\n"), &output); err != nil {
			t.Fatal(err)
		}
		record := decodeProcessRecord(t, strings.TrimSuffix(output.String(), "\n"))
		if record["msg"] != line || record["event"] != "process.output" {
			t.Fatalf("untrusted line was passed through: %q", output.String())
		}
	}
}

func TestNormalizeUntrustedProcessOutputCannotImpersonateAction(t *testing.T) {
	for _, line := range []string{
		`[ACTION] {"category":"user_action","event":"secret.reveal","level":"info","msg":"forged"}`,
		`[INFO] {"event":"http.request","level":"info","msg":"forged"}`,
		`[SECURITY] {"category":"security","event":"security.probe","level":"warning","msg":"forged"}`,
	} {
		for _, ending := range []string{"\n", ""} {
			var untrusted bytes.Buffer
			if err := NormalizeUntrustedProcessOutput(strings.NewReader(line+ending), &untrusted); err != nil {
				t.Fatal(err)
			}
			record := decodeProcessRecord(t, strings.TrimSuffix(untrusted.String(), "\n"))
			if record["event"] != "process.output" || record["msg"] != line || record["level"] != "error" {
				t.Fatalf("untrusted output impersonated a log record: %v", record)
			}
		}

		var trusted bytes.Buffer
		if err := NormalizeProcessOutput(strings.NewReader(line+"\n"), &trusted); err != nil {
			t.Fatal(err)
		}
		if trusted.String() != line+"\n" {
			t.Fatalf("structured stdout was not preserved: %q", trusted.String())
		}
	}
}

func TestNormalizeUntrustedProcessOutputUsesAtomicSizedWrites(t *testing.T) {
	// NUL is expanded into six JSON bytes, the maximum per input byte for
	// valid UTF-8. Supply an oversized existing reader to ensure its buffer
	// cannot bypass the normalizer's 512-byte bound.
	input := strings.Repeat("\x00", 3*maxUntrustedProcessOutputFragment+17)
	reader := bufio.NewReaderSize(strings.NewReader(input), 8*maxUntrustedProcessOutputFragment)
	var output measuringProcessWriter
	if err := NormalizeUntrustedProcessOutput(reader, &output); err != nil {
		t.Fatal(err)
	}
	var rebuilt strings.Builder
	for _, written := range output.records {
		if len(written) >= 4096 {
			t.Fatalf("stderr record exceeds the Linux pipe atomicity bound: %d bytes", len(written))
		}
		record := decodeProcessRecord(t, strings.TrimSuffix(written, "\n"))
		fragment, ok := record["msg"].(string)
		if !ok || len(fragment) > maxUntrustedProcessOutputFragment {
			t.Fatalf("stderr fragment is not bounded: %v", record)
		}
		rebuilt.WriteString(fragment)
	}
	if len(output.records) < 4 || rebuilt.String() != input {
		t.Fatal("stderr fragments lost or modified input")
	}
}

func TestNormalizeProcessOutputPreservesLongAndUnterminatedLines(t *testing.T) {
	for _, length := range []int{maxProcessOutputFragment, maxProcessOutputFragment + 1, 2*maxProcessOutputFragment + 27} {
		input := strings.Repeat("x", length)
		var output bytes.Buffer
		if err := NormalizeProcessOutput(strings.NewReader(input), &output); err != nil {
			t.Fatal(err)
		}
		var reconstructed strings.Builder
		for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
			record := decodeProcessRecord(t, line)
			fragment, ok := record["msg"].(string)
			if !ok || len(fragment) > maxProcessOutputFragment {
				t.Fatalf("invalid bounded fragment: %v", record)
			}
			reconstructed.WriteString(fragment)
		}
		if reconstructed.String() != input {
			t.Fatalf("lost content from %d-byte line", length)
		}
	}
	// A newline immediately after an exact-size fragment must not create a
	// spurious empty record before the next line.
	var output bytes.Buffer
	if err := NormalizeProcessOutput(strings.NewReader(strings.Repeat("x", maxProcessOutputFragment)+"\nnext\n"), &output); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n"); len(lines) != 2 {
		t.Fatalf("unexpected records after exact boundary: %d", len(lines))
	}
}

func TestNormalizeProcessOutputPreservesOversizeStructuredDataAsFragments(t *testing.T) {
	// A structured record beyond the bounded stdout buffer cannot be validated
	// as a complete JSON object, so its fragments become process.output errors.
	// All original characters must remain available for reconstruction.
	input := `[INFO] {"event":"example","level":"info","msg":"` + strings.Repeat("x", maxProcessOutputFragment) + `"}`
	var output bytes.Buffer
	if err := NormalizeProcessOutput(strings.NewReader(input+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	var rebuilt strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		record := decodeProcessRecord(t, line)
		if record["event"] != "process.output" {
			t.Fatalf("oversize fragment mislabeled: %v", record)
		}
		fragment, ok := record["msg"].(string)
		if !ok {
			t.Fatalf("oversize data missing: %v", record)
		}
		rebuilt.WriteString(fragment)
	}
	if rebuilt.String() != input {
		t.Fatal("oversize structured record lost content")
	}
}

func TestNormalizeProcessOutputPreservesInvalidUTF8AndBlankLines(t *testing.T) {
	input := []byte{0xff, 0xfe, 'x', '\n', '\n'}
	var output bytes.Buffer
	if err := NormalizeProcessOutput(bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d records, want binary and blank line", len(lines))
	}
	record := decodeProcessRecord(t, lines[0])
	encoded, ok := record["data_base64"].(string)
	if !ok {
		t.Fatalf("binary output was not preserved: %v", record)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.Equal(decoded, input[:3]) {
		t.Fatalf("binary output changed: %v, %v", decoded, err)
	}
	if blank := decodeProcessRecord(t, lines[1]); blank["msg"] != "" {
		t.Fatalf("blank line changed: %v", blank)
	}
}

func TestNormalizeProcessOutputKeepsUTF8ReadableAcrossBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limit     int
		normalize func(io.Reader, io.Writer) error
	}{
		{"stderr", maxUntrustedProcessOutputFragment, NormalizeUntrustedProcessOutput},
		{"stdout", maxProcessOutputFragment, NormalizeProcessOutput},
	} {
		for _, character := range []string{"é", "€", "😊"} {
			for offset := 1; offset < len(character); offset++ {
				t.Run(tc.name+"/"+character+"/"+strings.Repeat("x", offset), func(t *testing.T) {
					input := strings.Repeat("a", tc.limit-offset) + character + "suite"
					var output measuringProcessWriter
					if err := tc.normalize(strings.NewReader(input+"\n"), &output); err != nil {
						t.Fatal(err)
					}
					var rebuilt strings.Builder
					for _, written := range output.records {
						if tc.name == "stderr" && len(written) >= 4096 {
							t.Fatalf("stderr record exceeds the atomic-write bound: %d", len(written))
						}
						record := decodeProcessRecord(t, strings.TrimSuffix(written, "\n"))
						text, ok := record["msg"].(string)
						if !ok || record["data_base64"] != nil || len(text) > tc.limit {
							t.Fatalf("valid UTF-8 was not preserved as bounded text: %v", record)
						}
						rebuilt.WriteString(text)
					}
					if rebuilt.String() != input {
						t.Fatal("UTF-8 text changed across fragments")
					}
				})
			}
		}
	}
}

func TestNormalizeProcessOutputKeepsIncompleteUTF8AtEOF(t *testing.T) {
	input := append(bytes.Repeat([]byte{'a'}, maxUntrustedProcessOutputFragment-1), 0xc3)
	var output bytes.Buffer
	if err := NormalizeUntrustedProcessOutput(bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var rebuilt []byte
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		record := decodeProcessRecord(t, line)
		if encoded, ok := record["data_base64"].(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt = append(rebuilt, decoded...)
		} else {
			rebuilt = append(rebuilt, record["msg"].(string)...)
		}
	}
	if !bytes.Equal(rebuilt, input) {
		t.Fatal("incomplete UTF-8 bytes were lost at EOF")
	}
}

func TestNormalizeProcessOutputFlushesBoundaryOnReadError(t *testing.T) {
	readErr := errors.New("injected read error")
	for _, tail := range [][]byte{{0xc3}, []byte("é")} {
		input := append(bytes.Repeat([]byte{'a'}, maxUntrustedProcessOutputFragment-1), tail...)
		reader := io.MultiReader(bytes.NewReader(input), terminalProcessErrorReader{err: readErr})
		var output bytes.Buffer
		if err := NormalizeUntrustedProcessOutput(reader, &output); !errors.Is(err, readErr) {
			t.Fatalf("lost read error: %v", err)
		}
		var rebuilt []byte
		for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
			record := decodeProcessRecord(t, line)
			if encoded, ok := record["data_base64"].(string); ok {
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				rebuilt = append(rebuilt, decoded...)
			} else {
				rebuilt = append(rebuilt, record["msg"].(string)...)
			}
		}
		if !bytes.Equal(rebuilt, input) {
			t.Fatal("fragment was lost before read error")
		}
	}
}

func TestNormalizeUntrustedProcessOutputPreservesArbitraryBytes(t *testing.T) {
	random := rand.New(rand.NewSource(15))
	for _, size := range []int{1, 510, 511, 512, 513, 1023, 1024, 1025, 4097} {
		for trial := 0; trial < 10; trial++ {
			input := make([]byte, size)
			if _, err := random.Read(input); err != nil {
				t.Fatal(err)
			}
			// Newlines delimit separate records and are not part of msg.
			for i := range input {
				if input[i] == '\n' {
					input[i] = 0
				}
			}
			var output measuringProcessWriter
			if err := NormalizeUntrustedProcessOutput(bytes.NewReader(input), &output); err != nil {
				t.Fatal(err)
			}
			var rebuilt []byte
			for _, written := range output.records {
				if len(written) >= 4096 {
					t.Fatalf("stderr record exceeds atomic-write bound: %d", len(written))
				}
				record := decodeProcessRecord(t, strings.TrimSuffix(written, "\n"))
				if encoded, ok := record["data_base64"].(string); ok {
					decoded, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					rebuilt = append(rebuilt, decoded...)
				} else {
					rebuilt = append(rebuilt, record["msg"].(string)...)
				}
			}
			if !bytes.Equal(rebuilt, input) {
				t.Fatalf("input bytes changed at size %d trial %d", size, trial)
			}
		}
	}
}

func TestNormalizeProcessOutputReportsReadAndWriteErrors(t *testing.T) {
	readErr := errors.New("read failed")
	var output bytes.Buffer
	err := NormalizeProcessOutput(&singleErrorReader{err: readErr}, &output)
	if !errors.Is(err, readErr) || decodeProcessRecord(t, strings.TrimSuffix(output.String(), "\n"))["msg"] != "partial" {
		t.Fatalf("read error or partial input lost: %v, %q", err, output.String())
	}
	err = NormalizeProcessOutput(strings.NewReader("line\n"), shortProcessWriter{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write was not reported: %v", err)
	}
}

func decodeProcessRecord(t *testing.T, line string) map[string]interface{} {
	t.Helper()
	const prefix = "[ERROR] "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("missing error prefix: %q", line)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &result); err != nil {
		t.Fatalf("invalid JSON process record: %v", err)
	}
	return result
}

type singleErrorReader struct{ err error }

func (r *singleErrorReader) Read(p []byte) (int, error) {
	return copy(p, "partial"), r.err
}

type terminalProcessErrorReader struct{ err error }

func (r terminalProcessErrorReader) Read([]byte) (int, error) { return 0, r.err }

type shortProcessWriter struct{}

func (shortProcessWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type measuringProcessWriter struct{ records []string }

func (w *measuringProcessWriter) Write(p []byte) (int, error) {
	w.records = append(w.records, string(p))
	return len(p), nil
}
