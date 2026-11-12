package utils

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// safeWindowsPathComponent rejects names for which Win32 path normalization
// and NT relative opens may refer to different objects. It deliberately errs
// on the side of refusing unusual DOS-device-style names.
func safeWindowsPathComponent(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") || strings.ContainsAny(name, `<>:"/\|?*`) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return false
	}
	if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(stem, "COM"), "LPT")
		switch suffix {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return false
		}
	}
	return true
}
