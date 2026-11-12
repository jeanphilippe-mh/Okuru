package utils

import (
	"context"
	"io"

	"filippo.io/age"
)

const ArchiveFormatAge = "age-v1"

// Use the highest work factor already accepted by the existing reader. This
// raises the cost of offline password guessing without changing the format or
// invalidating previously created factor-17 and factor-18 archives.
const archiveWriteWorkFactor = 18
const archiveMaxReadWorkFactor = 18

// Scrypt consumes roughly 256 MiB at factor 18. Bound concurrency per process;
// multiple processes, garbage collection and other services still need RAM.
var archiveKDF = make(chan struct{}, 1)

func withArchiveKDF(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case archiveKDF <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-archiveKDF }()
	return fn()
}

func EncryptArchive(ctx context.Context, dst io.Writer, password string) (io.WriteCloser, error) {
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(archiveWriteWorkFactor)
	var encrypted io.WriteCloser
	err = withArchiveKDF(ctx, func() error { var e error; encrypted, e = age.Encrypt(dst, recipient); return e })
	return encrypted, err
}

func DecryptArchive(ctx context.Context, src io.Reader, password string) (io.Reader, error) {
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(archiveMaxReadWorkFactor)
	var plaintext io.Reader
	err = withArchiveKDF(ctx, func() error { var e error; plaintext, e = age.Decrypt(src, identity); return e })
	return plaintext, err
}
