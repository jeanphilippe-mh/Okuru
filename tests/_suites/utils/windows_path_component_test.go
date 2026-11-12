package utils

import "testing"

func TestSafeWindowsPathComponent(t *testing.T) {
	bad := []string{"", ".", "..", "name.", "name ", "bad/name", `bad\name`, "bad:name", "a?b", "a\x00b", "CON", "con.txt", "NUL .txt", "COM1", "com0.txt", "LPT9.log", "COM¹.zip", "LPT².txt", "conin$", "CONOUT$.txt", "clock$"}
	for _, value := range bad {
		if safeWindowsPathComponent(value) {
			t.Errorf("accepted ambiguous component %q", value)
		}
	}
	good := []string{"Users", "storage", "échantillon.txt", "COM10", "LPT11.txt", "container", "clockwork", "file name.zip", "~name"}
	for _, value := range good {
		if !safeWindowsPathComponent(value) {
			t.Errorf("rejected unambiguous component %q", value)
		}
	}
}
