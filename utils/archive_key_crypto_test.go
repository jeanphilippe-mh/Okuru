package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestArchiveIdentityEncryptDecryptAndRejectTampering(t *testing.T) {
	identity, err := GenerateArchiveIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateArchiveIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity == other || !strings.HasPrefix(identity, "AGE-SECRET-KEY-") {
		t.Fatal("independent X25519 identities were not generated")
	}
	const plaintext = "synthetic confidential ZIP contents"
	var encrypted bytes.Buffer
	writer, err := EncryptArchiveWithIdentity(context.Background(), &encrypted, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(writer, plaintext); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	ciphertext := encrypted.Bytes()
	if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) || !bytes.Contains(ciphertext, []byte("\n-> X25519 ")) {
		t.Fatal("archive has an unexpected format")
	}
	if bytes.Contains(ciphertext, []byte(plaintext)) || bytes.Contains(ciphertext, []byte(identity)) {
		t.Fatal("archive exposes its contents or secret identity")
	}
	reader, err := DecryptArchiveWithIdentity(context.Background(), bytes.NewReader(ciphertext), identity)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != plaintext {
		t.Fatalf("decryption failed: %v", err)
	}
	if _, err := DecryptArchiveWithIdentity(context.Background(), bytes.NewReader(ciphertext), other); err == nil {
		t.Fatal("wrong identity accepted")
	}
	corrupted := bytes.Clone(ciphertext)
	corrupted[len(corrupted)-1] ^= 1
	reader, err = DecryptArchiveWithIdentity(context.Background(), bytes.NewReader(corrupted), identity)
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if err == nil {
		t.Fatal("corrupted encrypted payload accepted")
	}
	truncated := ciphertext[:len(ciphertext)-1]
	reader, err = DecryptArchiveWithIdentity(context.Background(), bytes.NewReader(truncated), identity)
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if err == nil {
		t.Fatal("truncated encrypted payload accepted")
	}
}

func TestArchiveIdentityRejectsInvalidAndCanceledRequests(t *testing.T) {
	invalid := "sensitive-invalid-secret-value"
	if _, err := EncryptArchiveWithIdentity(context.Background(), io.Discard, invalid); err == nil || strings.Contains(err.Error(), invalid) {
		t.Fatal("invalid identity accepted or revealed in an error")
	}
	if _, err := DecryptArchiveWithIdentity(context.Background(), strings.NewReader(""), invalid); err == nil || strings.Contains(err.Error(), invalid) {
		t.Fatal("invalid identity accepted or revealed in an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EncryptArchiveWithIdentity(ctx, io.Discard, invalid); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled encryption: %v", err)
	}
	if _, err := DecryptArchiveWithIdentity(ctx, strings.NewReader(""), invalid); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled decryption: %v", err)
	}
}

func BenchmarkArchiveIdentityRoundTrip(b *testing.B) {
	identity, err := GenerateArchiveIdentity()
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("synthetic content"), 65536)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var ciphertext bytes.Buffer
		writer, err := EncryptArchiveWithIdentity(context.Background(), &ciphertext, identity)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			b.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			b.Fatal(err)
		}
		reader, err := DecryptArchiveWithIdentity(context.Background(), &ciphertext, identity)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
	}
}
