package utils

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestArchiveWorkFactorAndLegacyCompatibility(t *testing.T) {
	const password = "test-phrase-with-sufficient-entropy"
	const content = "synthetic legacy archive content"
	var current bytes.Buffer
	writer, err := EncryptArchive(context.Background(), &current, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	header := string(current.Bytes())
	if !strings.Contains(header, " 18\n") {
		t.Fatal("new age archive does not use the intended work factor")
	}
	reader, err := DecryptArchive(context.Background(), bytes.NewReader(current.Bytes()), password)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil || string(plain) != content {
		t.Fatalf("new archive failed round trip: %v", err)
	}

	legacyRecipient, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	legacyRecipient.SetWorkFactor(17)
	var legacy bytes.Buffer
	legacyWriter, err := age.Encrypt(&legacy, legacyRecipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(legacyWriter, content); err != nil {
		t.Fatal(err)
	}
	if err := legacyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy.Bytes()), " 17\n") {
		t.Fatal("legacy fixture does not use factor 17")
	}
	reader, err = DecryptArchive(context.Background(), bytes.NewReader(legacy.Bytes()), password)
	if err != nil {
		t.Fatalf("legacy factor-17 archive rejected: %v", err)
	}
	plain, err = io.ReadAll(reader)
	if err != nil || string(plain) != content {
		t.Fatalf("legacy archive failed round trip: %v", err)
	}

	// Changing just the public header gives an intentionally unauthentic file;
	// its unsupported factor must be rejected before an expensive derivation.
	tooExpensive := strings.Replace(header, " 18\n", " 19\n", 1)
	if _, err := DecryptArchive(context.Background(), strings.NewReader(tooExpensive), password); err == nil || !strings.Contains(err.Error(), "work factor too large") {
		t.Fatalf("unsupported work factor not rejected: %v", err)
	}
}
