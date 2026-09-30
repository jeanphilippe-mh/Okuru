package controllers

import (
	"archive/zip"
	"bytes"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"io"
	"mime/multipart"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type uploadValidator struct{}

func (uploadValidator) Validate(interface{}) error { return nil }
func TestMultipleFilesCreateOneArchive(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix, oldFolder, oldSize := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER, MaxFileSize
	t.Cleanup(func() {
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER, MaxFileSize = oldHost, oldPort, oldDB, oldPassword, oldPrefix, oldFolder, oldSize
	})
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	REDIS_HOST = host
	REDIS_PORT = port
	REDIS_DB = "0"
	REDIS_PASSWORD = ""
	REDIS_PREFIX = "test_multi_"
	FILEFOLDER = t.TempDir()
	MaxFileSize = 1024
	spillDir, err := os.MkdirTemp("", "okuru-multipart-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(spillDir) })
	t.Setenv("TMPDIR", spillDir)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("ttl", "1")
	writer.WriteField("ttlViews", "1")
	expected := map[string]string{"first.txt": "first contents", "second.txt": "second contents"}
	for name, text := range expected {
		part, err := writer.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(part, text)
	}
	writer.Close()
	e := echo.New()
	e.Renderer = testRenderer{}
	e.Validator = uploadValidator{}
	req := httptest.NewRequest("POST", "/file", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// Force even this small request to spill to disk, then verify its location.
	if err := req.ParseMultipartForm(1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { req.MultipartForm.RemoveAll() })
	spillFiles, err := os.ReadDir(spillDir)
	if err != nil || len(spillFiles) == 0 {
		t.Fatalf("multipart files not stored in the configured temporary directory: %v, %v", spillFiles, err)
	}
	if os.TempDir() != spillDir {
		t.Fatalf("unexpected temporary directory: %s", os.TempDir())
	}
	rec := httptest.NewRecorder()
	if err := AddFile(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	archives, err := filepath.Glob(filepath.Join(FILEFOLDER, "*.zip"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("archives=%v error=%v status=%d", archives, err, rec.Code)
	}
	z, err := zip.OpenReader(archives[0])
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 2 {
		t.Fatalf("got %d entries", len(z.File))
	}
	for _, f := range z.File {
		reader, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || string(data) != expected[f.Name] {
			t.Fatalf("bad archive entry %s", f.Name)
		}
	}
	entries, err := os.ReadDir(FILEFOLDER)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary directory retained: %v", entries)
	}
	spillFiles, err = os.ReadDir(spillDir)
	if err != nil || len(spillFiles) != 0 {
		t.Fatalf("multipart temporary files retained: %v, %v", spillFiles, err)
	}
}
