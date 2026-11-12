package controllers

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/jeanphilippe-mh/Okuru/utils"
)

func TestEncryptedUploadArchive(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("files", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(strings.Repeat("private test data\n", 256))
	if _, err = part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	form, err := ParseSecureMultipart(req, t.TempDir(), 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer form.Close()
	files := form.Files
	old := MaxFileSize
	MaxFileSize = 1 << 20
	defer func() { MaxFileSize = old }()
	names, err := validateUploadFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "encrypted")
	if err = writeEncryptedUploadArchive(context.Background(), path, "test password", files, names, ArchiveFormatAge); err != nil {
		t.Fatal(err)
	}
	if err := writeEncryptedUploadArchive(context.Background(), path, "test password", files, names, ArchiveFormatAge); err == nil {
		t.Fatal("existing archive overwritten")
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, payload[:64]) || bytes.HasPrefix(ciphertext, []byte("PK\x03\x04")) {
		t.Fatal("archive exposed plaintext")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
	if _, err := DecryptArchive(context.Background(), bytes.NewReader(ciphertext), "wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	decrypt := func(data []byte) ([]byte, error) {
		reader, err := DecryptArchive(context.Background(), bytes.NewReader(data), "test password")
		if err != nil {
			return nil, err
		}
		return io.ReadAll(reader)
	}
	plain, err := decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 1 || z.File[0].Name != "test.txt" || z.File[0].Mode().Perm() != 0600 || z.File[0].Method != zip.Store {
		t.Fatal("ZIP metadata changed")
	}
	in, err := z.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(in)
	if err != nil || !bytes.Equal(contents, payload) {
		t.Fatalf("contents mismatch: %v", err)
	}
	_ = in.Close()
	corrupted := append([]byte(nil), ciphertext...)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := decrypt(corrupted); err == nil {
		t.Fatal("corruption accepted")
	}
	if _, err := decrypt(ciphertext[:len(ciphertext)-1]); err == nil {
		t.Fatal("truncation accepted")
	}
}

func TestArchiveKDFWaitHonorsCancellation(t *testing.T) {
	// A canceled request must not wait for another in-flight derivation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EncryptArchive(ctx, io.Discard, "test password"); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestStreamArchiveAbortsOnIntegrityError(t *testing.T) {
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(httptest.NewRequest("GET", "/", nil), rec)
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("stream was not aborted")
		}
		if rec.Body.String() != "partial" {
			t.Fatal("partial response was not exercised")
		}
	}()
	_ = streamDecryptedArchive(c, &partialArchiveReader{})
}

type partialArchiveReader struct{ sent bool }

func (r *partialArchiveReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "partial"), nil
	}
	return 0, errors.New("authentication failed")
}

func BenchmarkEncryptedArchiveRoundTrip(b *testing.B) {
	payload := bytes.Repeat([]byte("synthetic content"), 65536)
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		var encrypted bytes.Buffer
		out, err := EncryptArchive(context.Background(), &encrypted, "synthetic password")
		if err != nil {
			b.Fatal(err)
		}
		zw := zip.NewWriter(out)
		entry, err := zw.Create("synthetic.txt")
		if err != nil {
			b.Fatal(err)
		}
		if _, err = entry.Write(payload); err != nil {
			b.Fatal(err)
		}
		if err = zw.Close(); err != nil {
			b.Fatal(err)
		}
		if err = out.Close(); err != nil {
			b.Fatal(err)
		}
		reader, err := DecryptArchive(context.Background(), bytes.NewReader(encrypted.Bytes()), "synthetic password")
		if err != nil {
			b.Fatal(err)
		}
		if _, err = io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
		if rss, ok := benchmarkPeakRSS(); ok {
			b.Logf("peak process RSS: %d bytes", rss)
		}
	}
}
