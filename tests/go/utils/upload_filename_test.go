package utils

import (
	"strings"
	"testing"
)

func TestUploadFilenameKey(t *testing.T) {
	for _, name := range []string{
		"fichier.txt", "re\u0301sume\u0301.txt", "résumé.txt", "🔐 + & #.txt", "rapport..txt", "report~final.txt", "report~.txt",
		"report~2025.txt", "a~1.document", "verylongfilename~1.txt", "a~1.x.pdf",
	} {
		if _, ok := UploadFilenameKey(name); !ok {
			t.Errorf("ordinary file name %q rejected", name)
		}
	}
	for _, name := range []string{
		"", ".", "..", "a/../b", `a\b`, "bad:name.txt", "bad?.txt", "NUL.txt", "com¹.txt", "name.", "name ",
		"a\x00b", "a\u0085b", "name\u202etxt.exe", string([]byte{0xff}), strings.Repeat("a", 256),
		// These can be confused with NTFS-generated short aliases. Reject them
		// independent of case, extension, file ordering or long-name spelling.
		"LONGFI~1.TXT", "longfi~1.txt", "REPORT~2", "PROGRA~1.XLS", "é~1.txt", "e\u0301~1.txt", "FILE.D~1", "file~12.txt",
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
