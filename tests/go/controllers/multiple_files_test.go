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
	"net/url"
	"strings"

	"github.com/flosch/pongo2"
	"github.com/jeanphilippe-mh/Okuru/models"
	"os"
	"path/filepath"
	"testing"
)

type captureUploadRenderer struct{ link string }

func (r *captureUploadRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	if name == "confirm_file.html" {
		r.link = data.(pongo2.Context)["f"].(*models.File).Link
	}
	_, err := io.WriteString(w, name)
	return err
}

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
	renderer := &captureUploadRenderer{}
	e.Renderer = renderer
	e.Validator = uploadValidator{}
	req := httptest.NewRequest("POST", "/file", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
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
	ciphertext, err := os.ReadFile(archives[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) {
		t.Fatal("archive is not an age envelope")
	}
	for _, text := range expected {
		if bytes.Contains(ciphertext, []byte(text)) {
			t.Fatal("archive exposes file contents")
		}
	}
	if _, err := zip.NewReader(bytes.NewReader(ciphertext), int64(len(ciphertext))); err == nil {
		t.Fatal("stored archive is an unencrypted ZIP")
	}
	link, err := url.Parse(renderer.link)
	if err != nil || !strings.HasPrefix(link.Path, "/file/") {
		t.Fatalf("missing download link: %v", err)
	}
	token := strings.TrimPrefix(link.Path, "/file/")
	name, err := archiveNameFromToken(token)
	if err != nil || filepath.Base(archives[0]) != name {
		t.Fatalf("download link does not match stored archive: %v", err)
	}
	key := strings.Split(token, TOKEN_SEPARATOR)[0]
	t.Cleanup(func() { c := NewPool().Get(); defer c.Close(); _, _ = c.Do("DEL", "test_multi_file_"+key) })
	downloadReq := httptest.NewRequest("POST", link.Path, nil)
	downloadRec := httptest.NewRecorder()
	ctx := e.NewContext(downloadReq, downloadRec)
	ctx.SetParamNames("file_key")
	ctx.SetParamValues(token)
	if err := DownloadFile(ctx); err != nil || downloadRec.Code != 200 {
		t.Fatalf("download failed: status=%d error=%v", downloadRec.Code, err)
	}
	plaintext := downloadRec.Body.Bytes()
	z, err := zip.NewReader(bytes.NewReader(plaintext), int64(len(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
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
	spillFiles, err := os.ReadDir(spillDir)
	if err != nil || len(spillFiles) != 0 {
		t.Fatalf("multipart temporary files retained: %v, %v", spillFiles, err)
	}
}
