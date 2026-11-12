package controllers

import (
	"unicode"
	"unicode/utf8"
)

// displayError capitalizes messages at the user interface boundary, without
// changing internal errors or the API contract.
func displayError(message string) string {
	first, size := utf8.DecodeRuneInString(message)
	if size == 0 {
		return message
	}
	return string(unicode.ToUpper(first)) + message[size:]
}
