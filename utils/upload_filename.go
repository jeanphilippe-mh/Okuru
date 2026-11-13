package utils

import (
	"strings"
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
	// A short-name-looking entry can resolve to the 8.3 alias of a distinct
	// long entry during Windows extraction. Actual aliases depend on the target
	// volume and extraction order, so reject plausible aliases rather than try
	// to predict them. Also inspect extensions and conservatively count Unicode
	// code points, not UTF-8 bytes. Longer ordinary names remain available.
	if looksLikeWindowsShortAlias(canonical) {
		return "", false
	}
	// Unicode folding also handles expansions and context-sensitive case forms,
	// such as ß/ss and Greek final sigma. Fold can itself introduce combining
	// marks, so normalise again to compare canonically equivalent results.
	return norm.NFC.String(cases.Fold().String(canonical)), true
}

func looksLikeWindowsShortAlias(name string) bool {
	stem, extension, hasExtension := strings.Cut(name, ".")
	if utf8.RuneCountInString(stem) > 8 ||
		(hasExtension && (strings.Contains(extension, ".") || utf8.RuneCountInString(extension) > 3)) {
		return false
	}
	for i := 0; i+1 < len(name); i++ {
		if name[i] == '~' && name[i+1] >= '0' && name[i+1] <= '9' {
			return true
		}
	}
	return false
}
