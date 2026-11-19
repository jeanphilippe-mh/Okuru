package controllers

import (
	"archive/zip"
	"context"
	"errors"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"io"
	"os"
)

type contextArchiveReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextArchiveReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func multipartArchiveSources(files []*SecureMultipartFile, names []string) []UploadArchiveSource {
	sources := make([]UploadArchiveSource, len(files))
	for i, file := range files {
		sources[i] = UploadArchiveSource{Filename: names[i], Size: file.Size, Open: file.Open}
	}
	return sources
}
func writeUploadArchive(ctx context.Context, path, password string, files []UploadArchiveSource, format string, releaseKDF func()) (resultErr error) {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	var encrypted io.WriteCloser
	switch format {
	case ArchiveFormatAgeUserPassword:
		encrypted, err = EncryptArchive(ctx, out, password)
	case ArchiveFormatAgeX25519:
		encrypted, err = EncryptArchiveWithIdentity(ctx, out, password)
	default:
		return errors.New("Unsupported archive format")
	}
	// The expensive key derivation is finished once the age writer is created.
	// Do not retain its single global slot while streaming a potentially large ZIP.
	if releaseKDF != nil {
		releaseKDF()
	}
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, encrypted.Close())
		if resultErr == nil {
			resultErr = out.Sync()
		}
	}()
	zw := zip.NewWriter(encrypted)
	defer func() { resultErr = errors.Join(resultErr, zw.Close()) }()
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		header := &zip.FileHeader{Name: file.Filename, Method: getZipMethodForSize(file.Size)}
		header.SetMode(0600)
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return errors.Join(err, in.Close())
		}
		n, copyErr := io.Copy(writer, io.LimitReader(contextArchiveReader{ctx, in}, file.Size+1))
		closeErr := in.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if n != file.Size {
			return errors.New("Multipart file size changed")
		}
	}
	return nil
}
