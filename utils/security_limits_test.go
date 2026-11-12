package utils

import (
	"strings"
	"testing"
)

func TestSecretLengthIsMeasuredInBytes(t *testing.T) {
	if err := ValidateSecretLength(strings.Repeat("a", MaxSecretBytes)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecretLength(strings.Repeat("é", MaxSecretBytes/2+1)); err == nil {
		t.Fatal("expected a multibyte secret above the byte limit to be rejected")
	}
}

func TestParseWebNumberDoesNotExposeInput(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("9", MaxWebNumberBytes+1), "invalid-secret-marker"} {
		_, err := ParseWebNumber(input)
		if err == nil || (input != "" && strings.Contains(err.Error(), input)) {
			t.Fatalf("unexpected error for invalid field: %v", err)
		}
	}
	if n, err := ParseWebNumber("100"); err != nil || n != 100 {
		t.Fatalf("valid number rejected: %d, %v", n, err)
	}
}
