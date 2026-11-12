package utils

import (
	"context"
	"io"

	"filippo.io/age"
)

// Seekable archive readers authenticate the age header and final chunk before
// exposing a size; each other chunk is authenticated independently on read.
func DecryptArchiveReaderAt(ctx context.Context, src io.ReaderAt, size int64, password string) (io.ReaderAt, int64, error) {
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, 0, err
	}
	identity.SetMaxWorkFactor(archiveMaxReadWorkFactor)
	var reader io.ReaderAt
	var plainSize int64
	err = withArchiveKDF(ctx, func() error {
		var e error
		reader, plainSize, e = age.DecryptReaderAt(src, size, identity)
		return e
	})
	return reader, plainSize, err
}

func DecryptArchiveIdentityReaderAt(ctx context.Context, src io.ReaderAt, size int64, secret string) (io.ReaderAt, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	identity, err := parseArchiveIdentity(secret)
	if err != nil {
		return nil, 0, err
	}
	return age.DecryptReaderAt(src, size, identity)
}
