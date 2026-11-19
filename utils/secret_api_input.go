package utils

import (
	"io"
	"net/http"
	"unicode/utf8"
)

// SecretAPIInput is the complete public creation document. The web form has
// independent field names and its own duration mapping.
type SecretAPIInput struct {
	Password   string
	TTLSeconds int
	Views      int
	Deletable  bool
}

func ReadSecretAPIInput(r io.Reader) (SecretAPIInput, int) {
	const maxDocumentBytes = 64 << 10
	var input = SecretAPIInput{TTLSeconds: 3600, Views: 1}
	data, err := io.ReadAll(io.LimitReader(r, maxDocumentBytes+1))
	if len(data) > maxDocumentBytes {
		return input, http.StatusRequestEntityTooLarge
	}
	if err != nil || !utf8.Valid(data) || !decodeDirectObject(data, map[string]any{
		"password": &input.Password, "ttl_seconds": &input.TTLSeconds, "views": &input.Views, "deletable": &input.Deletable,
	}) || input.Password == "" || ValidateAPILimits(input.TTLSeconds, input.Views) != nil {
		return input, http.StatusBadRequest
	}
	if ValidateSecretLength(input.Password) != nil {
		return input, http.StatusRequestEntityTooLarge
	}
	return input, 0
}
