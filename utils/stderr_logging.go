package utils

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"
)

// Bounds are per fragment. The strict stderr bound keeps even maximally
// JSON-escaped records below Linux's 4096-byte PIPE_BUF.
const (
	maxProcessOutputFragment          = 64 * 1024
	maxUntrustedProcessOutputFragment = 512
)

// NormalizeProcessOutput preserves already structured records and wraps other
// process output as structured error records. Long lines are split into bounded
// fragments; arbitrary bytes that are not UTF-8 are preserved as base64.
//
// This preserves diagnostic text. As with the original stderr, that text may
// contain secrets or attacker-controlled content; callers must restrict access
// to its destination. The input stream itself cannot authenticate a prefix.
func NormalizeProcessOutput(input io.Reader, output io.Writer) error {
	return normalizeProcessOutput(input, output, true, maxProcessOutputFragment)
}

// NormalizeUntrustedProcessOutput wraps every input line, even if it resembles
// a structured log record. Use it for stderr, where panic values and other
// output can contain attacker-controlled text.
func NormalizeUntrustedProcessOutput(input io.Reader, output io.Writer) error {
	return normalizeProcessOutput(input, output, false, maxUntrustedProcessOutputFragment)
}

func normalizeProcessOutput(input io.Reader, output io.Writer, preserveStructured bool, fragmentLimit int) error {
	// Wrap input so a caller-supplied bufio.Reader with a larger buffer cannot
	// bypass this normalizer's fragment bound.
	reader := bufio.NewReaderSize(struct{ io.Reader }{input}, fragmentLimit)
	fragment := 0
	var pending []byte // small UTF-8 boundary fragment carried across reads
	for {
		line, readErr := reader.ReadSlice('\n')
		terminated := len(line) > 0 && line[len(line)-1] == '\n'
		if len(line) == 0 && len(pending) > 0 && readErr != nil {
			// EOF after a partial rune makes it truly invalid; retain its bytes.
			if err := writeUnstructuredProcessOutput(output, pending, fragment, false); err != nil {
				return err
			}
			pending = nil
		}
		if len(line) > 0 {
			if preserveStructured && fragment == 0 && len(pending) == 0 && !errors.Is(readErr, bufio.ErrBufferFull) && isStructuredProcessRecord(line) {
				record := line
				if !terminated {
					// Ensure the next process append cannot merge two records.
					record = append(append([]byte(nil), line...), '\n')
				}
				if err := writeProcessOutput(output, record); err != nil {
					return err
				}
			} else {
				content := line
				if terminated {
					content = content[:len(content)-1]
				}
				if len(pending) > 0 {
					combined := make([]byte, 0, len(pending)+len(content))
					combined = append(combined, pending...)
					content = append(combined, content...)
					pending = nil
				}
				// A carried partial rune can make the next read larger than the
				// fragment limit. Split it first at a UTF-8 boundary.
				for len(content) > fragmentLimit {
					cut := completeUTF8Prefix(content[:fragmentLimit])
					if cut == 0 {
						cut = fragmentLimit
					}
					if err := writeUnstructuredProcessOutput(output, content[:cut], fragment, true); err != nil {
						return err
					}
					fragment++
					content = content[cut:]
				}
				if errors.Is(readErr, bufio.ErrBufferFull) {
					if len(content) < fragmentLimit {
						pending = append(pending, content...)
						continue
					}
					cut := completeUTF8Prefix(content)
					if cut > 0 {
						if err := writeUnstructuredProcessOutput(output, content[:cut], fragment, true); err != nil {
							return err
						}
						fragment++
					}
					pending = append(pending, content[cut:]...)
					continue
				}
				// A newline after an exact-size fragment closes that same line.
				if len(content) != 0 || fragment == 0 {
					if err := writeUnstructuredProcessOutput(output, content, fragment, false); err != nil {
						return err
					}
				}
			}
		}
		fragment = 0
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// completeUTF8Prefix withholds only an incomplete final rune, not malformed
// complete sequences. Truly invalid bytes remain available for base64 output.
func completeUTF8Prefix(content []byte) int {
	start := len(content) - 1
	lower := max(0, len(content)-(utf8.UTFMax-1))
	for start >= lower && !utf8.RuneStart(content[start]) {
		start--
	}
	if start >= lower && !utf8.FullRune(content[start:]) {
		return start
	}
	return len(content)
}

func writeUnstructuredProcessOutput(output io.Writer, content []byte, fragment int, hasMore bool) error {
	record := map[string]interface{}{
		"event": "process.output",
		"level": "error",
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if fragment > 0 || hasMore {
		record["fragment"] = fragment + 1
	}
	if utf8.Valid(content) {
		record["msg"] = string(content)
	} else {
		record["msg"] = "Non-UTF-8 process output"
		record["data_base64"] = base64.StdEncoding.EncodeToString(content)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	result := append([]byte("[ERROR] "), encoded...)
	result = append(result, '\n')
	return writeProcessOutput(output, result)
}

func writeProcessOutput(output io.Writer, line []byte) error {
	n, err := output.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return nil
}

// isStructuredProcessRecord checks the complete prefix and JSON object; it
// never trusts a bare prefix or a JSON string supplied as process output.
func isStructuredProcessRecord(line []byte) bool {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	labels := []struct {
		prefix string
		levels []string
	}{
		{"[INFO] ", []string{"info"}},
		{"[WARNING] ", []string{"warning"}},
		{"[ERROR] ", []string{"error", "fatal", "panic"}},
		{"[DEBUG] ", []string{"debug"}},
		{"[TRACE] ", []string{"trace"}},
	}
	for _, label := range labels {
		if !bytes.HasPrefix(line, []byte(label.prefix)) {
			continue
		}
		payload := line[len(label.prefix):]
		action := bytes.HasPrefix(payload, []byte("[ACTION] "))
		if action {
			payload = payload[len("[ACTION] "):]
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(payload, &fields) != nil || fields == nil {
			return false
		}
		var level, category string
		if json.Unmarshal(fields["level"], &level) != nil {
			return false
		}
		_ = json.Unmarshal(fields["category"], &category)
		if action != (category == "user_action") {
			return false
		}
		for _, permitted := range label.levels {
			if level == permitted {
				return true
			}
		}
		return false
	}
	return false
}
