package utils

import "testing"

func TestTokenIdentifierCannotSelectAnotherResourceNamespace(t *testing.T) {
	id := "123e4567-e89b-42d3-a456-426614174000"
	for _, value := range []string{"file_" + id, "../" + id, "{" + id + "}", "123E4567-e89b-42d3-a456-426614174000", "123e4567e89b42d3a456426614174000", ""} {
		if _, _, err := ParseToken(value + TOKEN_SEPARATOR + "key"); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if got, key, err := ParseToken(id + TOKEN_SEPARATOR + "key"); err != nil || got != id || key != "key" {
		t.Fatalf("canonical token broken: %q %q %v", got, key, err)
	}
}
