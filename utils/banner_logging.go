package utils

import (
	"bytes"
	"strings"

	"github.com/labstack/echo/v5"
)

// echoBannerLines is a fixed startup-only decoration. All lines carry an INFO
// prefix even though they intentionally are not JSON: this preserves Echo's
// original, genuinely multiline ASCII artwork in a text log.
func echoBannerLines() []string {
	return []string{
		"[INFO] ",
		"[INFO] ---------------------------------------------",
		"[INFO] ",
		"[INFO]    ____    __",
		"[INFO]   / __/___/ /  ___",
		`[INFO]  / _// __/ _ \/ _ \`,
		`[INFO] /___/\__/_//_/\___/ ` + echo.Version,
		"[INFO] High performance, minimalist Go web framework",
		"[INFO] https://echo.labstack.com",
		"[INFO] ____________________________________O/_______",
		`[INFO]                                     O\`,
		"[INFO] ",
		"[INFO] ---------------------------------------------",
		"[INFO] ",
	}
}

// EchoStartupBanner returns Echo's original ASCII artwork with a blank spacer
// and separator on each side. A single write keeps its short lines together.
func EchoStartupBanner() string {
	return strings.Join(echoBannerLines(), "\n") + "\n"
}

// IsEchoBannerLine accepts only a line from the fixed startup decoration.
// It is intended solely for the trusted stdout normalizer: never use it to
// admit raw stderr, user input, arbitrary INFO lines, or changing text.
func IsEchoBannerLine(line []byte) bool {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	for _, expected := range echoBannerLines() {
		if bytes.Equal(line, []byte(expected)) {
			return true
		}
	}
	return false
}
