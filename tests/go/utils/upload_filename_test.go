package utils

import (
	"strings"
	"testing"
)

func TestUploadFilenameKey(t *testing.T) {
	for _, name := range []string{
		"fichier.txt", "re\u0301sume\u0301.txt", "résumé.txt", "🔐 + & #.txt", "rapport..txt",
	} {
		if _, ok := UploadFilenameKey(name); !ok {
			t.Errorf("ordinary file name %q rejected", name)
		}
	}
	for _, name := range []string{
		"", ".", "..", "a/../b", `a\b`, "bad:name.txt", "bad?.txt", "NUL.txt", "com¹.txt", "name.", "name ",
		"a\x00b", "a\u0085b", "name\u202etxt.exe", string([]byte{0xff}), strings.Repeat("a", 256),
	} {
		if _, ok := UploadFilenameKey(name); ok {
			t.Errorf("unsafe file name %q accepted", name)
		}
	}
	for _, pair := range [][2]string{
		{"Report.TXT", "report.txt"},
		{"résumé.txt", "re\u0301sume\u0301.txt"},
		{"É.txt", "é.txt"},
		{"Straße.txt", "STRASSE.TXT"},
		{"ΟΣ.txt", "ος.txt"},
		{"İ.txt", "i\u0307.txt"},
	} {
		a, aOK := UploadFilenameKey(pair[0])
		b, bOK := UploadFilenameKey(pair[1])
		if !aOK || !bOK || a != b {
			t.Errorf("equivalent file names did not collide: %q, %q", pair[0], pair[1])
		}
	}
}
