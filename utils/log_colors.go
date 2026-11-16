package utils

import (
	"bytes"
	"os"
)

// logFileColorsEnabled is deliberately independent of TTY detection: the
// output is an append-only file, often followed later in a terminal. Set a
// nonempty NO_COLOR to keep the file free of ANSI escape sequences.
func logFileColorsEnabled() bool {
	return os.Getenv("NO_COLOR") == ""
}

// colorLogPrefix colors only a recognized, already-normalized severity label.
// The JSON payload and the remainder of the line are preserved byte for byte.
// It is called only on records from the stdout/stderr normalizers.
func colorLogPrefix(record []byte) []byte {
	for _, style := range []struct{ label, ansi string }{
		{"[INFO]", "\x1b[34m"},
		{"[WARNING]", "\x1b[38;2;255;165;0m"},
		{"[ERROR]", "\x1b[31m"},
		{"[ACTION]", "\x1b[1;33m"},
		{"[SECURITY]", "\x1b[1;38;2;180;180;180m"},
	} {
		prefix := []byte(style.label)
		if !bytes.HasPrefix(record, prefix) || len(record) <= len(prefix) || record[len(prefix)] != ' ' {
			continue
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
