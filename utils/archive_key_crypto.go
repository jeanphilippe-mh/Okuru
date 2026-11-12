package utils

import (
	"context"
	"errors"
	"io"

	"filippo.io/age"
)

// ArchiveFormatAgeX25519 identifies archives encrypted to a randomly generated
// X25519 identity. The identity is sensitive and must be stored only encrypted
// under the Fernet key in the share link; it must never be logged or returned to
// an upload recipient. It is not a password supplied by the user.
const ArchiveFormatAgeX25519 = "age-x25519-v1"

// GenerateArchiveIdentity creates an independent, cryptographically random age
// identity for an upload that has no user-supplied password.
func GenerateArchiveIdentity() (string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	return identity.String(), nil
}

func parseArchiveIdentity(secret string) (*age.X25519Identity, error) {
	identity, err := age.ParseX25519Identity(secret)
	if err != nil {
		// Do not accidentally expose malformed secret material through an error.
		return nil, errors.New("Invalid archive identity")
	}
	return identity, nil
}

// EncryptArchiveWithIdentity creates a streaming authenticated age envelope.
// The caller must close the returned writer and check its Close error.
func EncryptArchiveWithIdentity(ctx context.Context, dst io.Writer, secret string) (io.WriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identity, err := parseArchiveIdentity(secret)
	if err != nil {
		return nil, err
	}
	return age.Encrypt(dst, identity.Recipient())
}

// DecryptArchiveWithIdentity authenticates the age header before returning a
// streaming reader. Payload authentication errors can occur while it is read.
func DecryptArchiveWithIdentity(ctx context.Context, src io.Reader, secret string) (io.Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identity, err := parseArchiveIdentity(secret)
	if err != nil {
		return nil, err
	}
	return age.Decrypt(src, identity)
}
