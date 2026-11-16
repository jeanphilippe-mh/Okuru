package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// logFileColorsEnabled is deliberately independent of TTY detection: the
// output is an append-only file, often followed later in a terminal. Set a
// nonempty NO_COLOR to keep the file free of ANSI escape sequences.
func logFileColorsEnabled() bool {
	return os.Getenv("NO_COLOR") == ""
}

// colorLogPrefix colors a recognized severity label and makes prominent
// messages bold in the text file. Removing ANSI codes restores the original
// record byte for byte. It is called only on normalized process output.
func colorLogPrefix(record []byte) []byte {
	for _, style := range []struct{ label, ansi string }{
		{"[INFO]", "\x1b[34m"},
		{"[WARNING]", "\x1b[38;2;255;165;0m"},
		{"[ERROR]", "\x1b[1;31m"},
		{"[ACTION]", "\x1b[1;38;2;180;120;255m"},
		{"[SECURITY]", "\x1b[1;38;2;180;180;180m"},
	} {
		prefix := []byte(style.label)
		if !bytes.HasPrefix(record, prefix) || len(record) <= len(prefix) || record[len(prefix)] != ' ' {
			continue
		}
		if style.label == "[ERROR]" || style.label == "[ACTION]" || style.label == "[SECURITY]" {
			record = boldStructuredMessage(record, len(prefix)+1)
		}
		// Avoid arithmetic on an input-dependent length when allocating. The
		// append operations grow the slice with Go's checked runtime logic.
		colored := []byte(style.ansi)
		colored = append(colored, prefix...)
		colored = append(colored, "\x1b[0m"...)
		return append(colored, record[len(prefix):]...)
	}
	return record
}

// boldStructuredMessage adds display-only ANSI codes inside the top-level
// JSON msg string without decoding or rewriting its original bytes. This makes
// the file record invalid JSON until ANSI codes are removed; journald and
// NO_COLOR output remain unchanged. Ambiguous or invalid records are left as-is.
func boldStructuredMessage(record []byte, payloadOffset int) []byte {
	if payloadOffset < 0 || payloadOffset > len(record) {
		return record
	}
	dec := json.NewDecoder(bytes.NewReader(record[payloadOffset:]))
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') {
		return record
	}
	start, end, seen := 0, 0, false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return record
		}
		name, ok := key.(string)
		if !ok {
			return record
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return record
		}
		if name != "msg" {
			continue
		}
		if seen {
			return record
		}
		seen = true
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			continue
		}
		end = payloadOffset + int(dec.InputOffset()) - 1
		start = end - len(value) + 2
	}
	close, err := dec.Token()
	if err != nil || close != json.Delim('}') {
		return record
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF || !seen || start <= 0 || start > end || end > len(record) {
		return record
	}
	result := append([]byte(nil), record[:start]...)
	result = append(result, "\x1b[1m"...)
	result = append(result, record[start:end]...)
	result = append(result, "\x1b[22m"...)
	return append(result, record[end:]...)
}
