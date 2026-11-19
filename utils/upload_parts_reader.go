package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"filippo.io/age"
)

// Finalization holds the session lock until all source readers are closed.
func UploadPartSources(ctx context.Context, s *UploadSession, bearer string) ([]UploadArchiveSource, error) {
	set, err := getUploadParts(s)
	if err != nil {
		return nil, err
	}
	if err := set.reconcile(ctx, s.ID, bearer); err != nil {
		return nil, err
	}
	sources := make([]UploadArchiveSource, 0, len(set.files))
	for index, spec := range s.Metadata.Files {
		offset, err := ConfirmedUploadOffset(ctx, s.ID, bearer, index)
		if err != nil {
			return nil, err
		}
		var end int64
		parts := set.files[index]
		for _, p := range parts {
			if p.start != end || p.end <= p.start || p.index != index {
				return nil, uploadSessionError("unavailable")
			}
			end = p.end
		}
		if end != offset || end != spec.Size {
			return nil, uploadSessionError("not_ready")
		}
		sources = append(sources, UploadArchiveSource{Filename: spec.Name, Size: spec.Size, Open: func() (io.ReadCloser, error) {
			return &uploadPartsReader{ctx: ctx, identity: set.identity, parts: parts}, nil
		}})
	}
	return sources, nil
}

type uploadPartsReader struct {
	ctx      context.Context
	identity *age.X25519Identity
	parts    []uploadPart
	file     *os.File
	plain    io.Reader
	left     int64
	closed   bool
}

func (r *uploadPartsReader) open() error {
	if len(r.parts) == 0 {
		return io.EOF
	}
	p := r.parts[0]
	r.parts = r.parts[1:]
	f, err := OpenStorageArchive(p.path)
	if err != nil {
		return err
	}
	plain, err := age.Decrypt(f, r.identity)
	if err == nil {
		var header [16]byte
		_, err = io.ReadFull(plain, header[:])
		want := p.header()
		if err == nil && !bytes.Equal(header[:], want[:]) {
			err = errors.New("invalid upload block position")
		}
	}
	if err != nil {
		_ = f.Close()
		return err
	}
	r.plain, r.file, r.left = plain, f, p.end-p.start
	return nil
}

func (r *uploadPartsReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	for {
		if r.closed {
			return 0, os.ErrClosed
		}
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if r.file == nil {
			if err := r.open(); err != nil {
				return 0, err
			}
		}
		n, err := r.plain.Read(dst)
		if int64(n) > r.left {
			return 0, errors.New("upload block length changed")
		}
		r.left -= int64(n)
		if err == io.EOF {
			closeErr := r.file.Close()
			r.file, r.plain = nil, nil
			if r.left != 0 {
				return n, io.ErrUnexpectedEOF
			}
			if closeErr != nil {
				return n, closeErr
			}
			if n == 0 {
				continue
			}
			return n, nil
		}
		return n, err
	}
}

func (r *uploadPartsReader) Close() error {
	r.closed = true
	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		return err
	}
	return nil
}
