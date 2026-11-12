package router

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flosch/pongo2"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

type uploadE2ERenderer struct {
	csrf string
	link string
}

func (r *uploadE2ERenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	ctx, ok := data.(pongo2.Context)
	if !ok {
		return fmt.Errorf("unexpected render context")
	}
	if token, ok := ctx["csrfToken"].(string); ok && token != "" {
		r.csrf = token
	}
	if name == "confirm_file.html" {
		f, ok := ctx["f"].(*models.File)
		if !ok {
			return fmt.Errorf("missing confirmation data")
		}
		r.link = f.Link
	}
	_, err := io.WriteString(w, name)
	return err
}

type uploadE2EGatedBody struct {
	prefix  *bytes.Reader
	suffix  *bytes.Reader
	waiting chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (b *uploadE2EGatedBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	b.once.Do(func() { close(b.waiting) })
	<-b.resume
	return b.suffix.Read(p)
}

func uploadE2EMultipart(t *testing.T, password, csrf string, includeCSRF bool, payload []byte) ([]byte, int, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("files", "confidential-e2e.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	// File contents precede the password and CSRF token, as in the browser form.
	if err := mw.WriteField("password", password); err != nil {
		t.Fatal(err)
	}
	split := body.Len()
	if includeCSRF {
		if err := mw.WriteField("_csrf", csrf); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.WriteField("ttl", "1"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("ttlViews", "2"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), split, mw.FormDataContentType()
}

func TestUploadEndToEndEncryptedMultipartAndCSRF(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := redis.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "okuru_e2e_" + strings.ReplaceAll(uuid.NewString(), "-", "") + "_"
	oldHost, oldPort, oldDB, oldPassword, oldPrefix := utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD, utils.REDIS_PREFIX
	oldFolder, oldMax := utils.FILEFOLDER, utils.MaxFileSize
	_ = utils.CloseRedisPool()
	utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD, utils.REDIS_PREFIX = host, port, "0", "", prefix
	utils.FILEFOLDER, utils.MaxFileSize = t.TempDir(), 4<<20
	t.Cleanup(func() {
		keys, _ := redis.Strings(conn.Do("KEYS", prefix+"*"))
		for _, key := range keys {
			_, _ = conn.Do("DEL", key)
		}
		_ = conn.Close()
		_ = utils.CloseRedisPool()
		utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD, utils.REDIS_PREFIX = oldHost, oldPort, oldDB, oldPassword, oldPrefix
		utils.FILEFOLDER, utils.MaxFileSize = oldFolder, oldMax
	})
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "268435456")
	e := NewWithTimeouts(time.Minute, time.Minute, time.Minute)
	renderer := &uploadE2ERenderer{}
	e.Renderer = renderer

	get := httptest.NewRequest(http.MethodGet, "https://example.test/file", nil)
	getRec := httptest.NewRecorder()
	e.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK || renderer.csrf == "" {
		t.Fatalf("could not obtain CSRF form: status=%d", getRec.Code)
	}
	var cookie *http.Cookie
	for _, c := range getRec.Result().Cookies() {
		if c.Name == "_csrf" {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != renderer.csrf {
		t.Fatal("CSRF cookie missing or different from rendered token")
	}
	csrf := renderer.csrf
	payload := bytes.Repeat([]byte("sensitive-upload-fixture-"), 32768)
	const password = "unique fixture archive password"

	// A missing token must fail before any record or archive is published.
	badBody, _, badType := uploadE2EMultipart(t, password, csrf, false, payload)
	badReq := httptest.NewRequest(http.MethodPost, "https://example.test/file", bytes.NewReader(badBody))
	badReq.Header.Set(echo.HeaderContentType, badType)
	badReq.AddCookie(cookie)
	badRec := httptest.NewRecorder()
	e.ServeHTTP(badRec, badReq)
	if badRec.Code < 400 || badRec.Code >= 500 {
		t.Fatalf("upload without CSRF was not rejected: %d", badRec.Code)
	}
	keys, err := redis.Strings(conn.Do("KEYS", prefix+"*"))
	if err != nil || len(keys) != 0 {
		t.Fatalf("rejected upload created Redis metadata: count=%d err=%v", len(keys), err)
	}

	body, split, contentType := uploadE2EMultipart(t, password, csrf, true, payload)
	gate := &uploadE2EGatedBody{prefix: bytes.NewReader(body[:split]), suffix: bytes.NewReader(body[split:]), waiting: make(chan struct{}), resume: make(chan struct{})}
	var release sync.Once
	resume := func() { release.Do(func() { close(gate.resume) }) }
	defer resume()
	req := httptest.NewRequest(http.MethodPost, "https://example.test/file", gate)
	req.ContentLength = int64(len(body))
	req.Header.Set(echo.HeaderContentType, contentType)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { e.ServeHTTP(rec, req); close(done) }()
	select {
	case <-gate.waiting:
	case <-time.After(10 * time.Second):
		resume()
		<-done
		t.Fatal("upload did not reach the staged-file boundary")
	}
	// Inspect disk while the request is paused after its file part and before
	// all form fields arrive. The temporary directory must not contain plaintext.
	foundStage := false
	walkErr := filepath.WalkDir(utils.FILEFOLDER, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.Contains(entry.Name(), "confidential-e2e") {
			return fmt.Errorf("temporary filename exposes original name")
		}
		// LockFileEx on Windows prevents other handles from reading a locked
		// marker; content-bearing encrypted staging files use the .age suffix.
		if !strings.HasSuffix(entry.Name(), ".age") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("sensitive-upload-fixture-")) {
			return fmt.Errorf("plaintext file content written to storage")
		}
		foundStage = true
		return nil
	})
	if walkErr != nil || !foundStage {
		resume()
		<-done
		t.Fatalf("encrypted staging verification failed: found=%v err=%v", foundStage, walkErr)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		resume()
		<-done
		t.Fatalf("plaintext multipart spill in system temporary directory: count=%d err=%v", len(entries), err)
	}
	resume()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("upload did not finish")
	}
	if rec.Code != http.StatusOK || renderer.link == "" {
		t.Fatalf("upload failed: status=%d body=%q", rec.Code, rec.Body.String())
	}
	archives, err := filepath.Glob(filepath.Join(utils.FILEFOLDER, "*.zip"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("expected one archive: count=%d err=%v", len(archives), err)
	}
	stored, err := os.ReadFile(archives[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("sensitive-upload-fixture-")) || bytes.Contains(stored, []byte("confidential-e2e.txt")) {
		t.Fatal("stored archive exposed plaintext")
	}
	if _, err := zip.NewReader(bytes.NewReader(stored), int64(len(stored))); err == nil {
		t.Fatal("stored archive is an unencrypted ZIP")
	}
	link, err := url.Parse(renderer.link)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"password": {password}, "_csrf": {csrf}}
	download := httptest.NewRequest(http.MethodPost, "https://example.test"+link.RequestURI(), strings.NewReader(values.Encode()))
	download.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	download.AddCookie(cookie)
	downloadRec := httptest.NewRecorder()
	e.ServeHTTP(downloadRec, download)
	if downloadRec.Code != http.StatusOK {
		t.Fatalf("download failed: status=%d", downloadRec.Code)
	}
	zipBytes := downloadRec.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "confidential-e2e.txt" {
		t.Fatalf("download is not the expected ZIP: %v", err)
	}
	in, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(in)
	closeErr := in.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("download content mismatch: read=%v close=%v", readErr, closeErr)
	}
}
