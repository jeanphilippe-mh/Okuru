package utils

import (
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// UploadFilenameKey validates an archive entry name as a single portable path
// component and returns its comparison key. The original name is retained in
// the archive; canonical Unicode equivalents and Unicode case-fold aliases collide.
func UploadFilenameKey(name string) (string, bool) {
	if len(name) > 255 || !utf8.ValidString(name) || !safeWindowsPathComponent(name) {
		return "", false
	}
	for _, r := range name {
		// These controls can hide or reverse the apparent extension of a file.
		if r == '\u061c' || r == '\u200e' || r == '\u200f' ||
			(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			return "", false
		}
	}
	canonical := norm.NFC.String(name)
	if len(canonical) > 255 {
		return "", false
	}
	// Unicode folding also handles expansions and context-sensitive case forms,
	// such as ß/ss and Greek final sigma. Fold can itself introduce combining
	// marks, so normalise again to compare canonically equivalent results.
	return norm.NFC.String(cases.Fold().String(canonical)), true
}
