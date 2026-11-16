package router

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// newCSPNonce creates an unpredictable value for exactly one HTML response.
func newCSPNonce() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate CSP nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func contentSecurityPolicy(nonce string) string {
	return "default-src 'none'; script-src 'nonce-" + nonce + "'; " +
		"worker-src 'self'; require-trusted-types-for 'script'; " +
		"form-action 'self'; connect-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; manifest-src 'self'; font-src 'self'; " +
		"base-uri 'none'; child-src 'none'; frame-src 'none'; " +
		"frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests"
}
