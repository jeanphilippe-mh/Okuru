package router

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type fileSessionFixture struct {
	t                *testing.T
	e                *echo.Echo
	cookie           *http.Cookie
	csrf, bearer, id string
}

func newFileSessionFixture(t *testing.T) *fileSessionFixture {
	p := configureLeaseTestRedis(t)
	folder, max := utils.FILEFOLDER, utils.MaxFileSize
	utils.FILEFOLDER = t.TempDir()
	utils.MaxFileSize = 500_000_000
	t.Cleanup(func() { utils.FILEFOLDER, utils.MaxFileSize = folder, max })
	t.Setenv("OKURU_UPLOAD_CHUNKS", "true")
	t.Setenv("OKURU_SHORTLINK_PUBLIC_ORIGIN", "")
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "4294967296")
	c := utils.NewPool().Get()
	_, err := c.Do("HSET", p+"upload_v2_admission", "api", "open", "blocks", "open")
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	stop, err := utils.StartPreparedUploads(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	f := &fileSessionFixture{t: t, e: New(), bearer: base64.RawURLEncoding.EncodeToString(secret[:]), id: uuid.NewString()}
	f.e.Renderer = &uploadE2ERenderer{}
	ConfigureErrorHandler(f.e, t.TempDir())
	b := f.call("GET", uploadBootstrapPath, "", nil)
	if b.Code != 200 {
		t.Fatal(b.Code)
	}
	f.csrf = b.Header().Get("X-CSRF-Token")
	f.cookie = b.Result().Cookies()[0]
	return f
}

func (f *fileSessionFixture) call(method, path, content string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://example.test"+path, body)
	r.RemoteAddr = "127.0.0.1:39003"
	if f.cookie != nil {
		r.AddCookie(f.cookie)
		r.Header.Set("X-CSRF-Token", f.csrf)
	}
	if content != "" {
		r.Header.Set("Content-Type", content)
	}
	r.Header.Set("Authorization", "Bearer "+f.bearer)
	r.Header.Set("Idempotency-Key", f.id)
	r.Header.Set("Upload-Id", f.id)
	rec := httptest.NewRecorder()
	f.e.ServeHTTP(rec, r)
	return rec
}
func (f *fileSessionFixture) prepare(mode string) {
	f.t.Helper()
	for i, want := range []int{201, 200} {
		raw := `{"mode":"` + mode + `","ttl_seconds":3600,"views":2,"files":[{"name":"test.bin","size":6},{"name":"empty","size":0}]}`
		rec := f.call("POST", sessionPath, "application/json", strings.NewReader(raw))
		if rec.Code != want {
			f.t.Fatalf("prepare[%d] returned %d: %s", i, rec.Code, rec.Body.String())
		}
	}
}
func (f *fileSessionFixture) checkPublication(rec *httptest.ResponseRecorder) {
	f.t.Helper()
	if rec.Code != 201 {
		f.t.Fatalf("publish returned %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		f.t.Fatal(err)
	}
	if result["confirmation_receipt"] == "" || result["expires_at"] == "" {
		f.t.Fatal("incomplete result")
	}
	back := f.call("GET", sessionPath+"/"+f.id+"/result", "", nil)
	var replay map[string]string
	if back.Code != 200 || json.Unmarshal(back.Body.Bytes(), &replay) != nil || replay["link"] != result["link"] || replay["expires_at"] != result["expires_at"] {
		f.t.Fatal("unstable receipt")
	}
	view, err := url.Parse(result["link"])
	if err != nil || view.Host != "" || !strings.HasPrefix(view.Path, "/file/") {
		f.t.Fatal("untrusted link origin")
	}
	// Use the same-origin browser submission with Echo's Fetch Metadata check.
	r := httptest.NewRequest("POST", "https://example.test"+view.Path, strings.NewReader("password="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	download := followDownloadForm(f.t, f.e, r)
	if download.Code != 200 {
		f.t.Fatalf("download=%d", download.Code)
	}
	archive, err := zip.NewReader(bytes.NewReader(download.Body.Bytes()), int64(download.Body.Len()))
	if err != nil || len(archive.File) != 2 {
		f.t.Fatalf("invalid ZIP: %v", err)
	}
	for i, want := range []string{"abcdef", ""} {
		in, e := archive.File[i].Open()
		if e != nil {
			f.t.Fatal(e)
		}
		b, e := io.ReadAll(in)
		in.Close()
		if e != nil || string(b) != want {
			f.t.Fatal("incorrect extracted bytes")
		}
	}
}
func TestPreparedMultipartRoundTrip(t *testing.T) {
	f := newFileSessionFixture(t)
	f.prepare("multipart")
	send := func(second string) *httptest.ResponseRecorder {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		a, _ := w.CreateFormFile("files", "test.bin")
		_, _ = io.WriteString(a, "abcdef")
		z, _ := w.CreateFormFile("files", "empty")
		_, _ = io.WriteString(z, second)
		_ = w.Close()
		return f.call("POST", preparedFilePath, w.FormDataContentType(), &b)
	}
	if rec := send("x"); rec.Code != 400 {
		t.Fatalf("wrong file size returned %d", rec.Code)
	}
	f.checkPublication(send(""))
	if rec := send(""); rec.Code != 409 {
		t.Fatalf("duplicate upload returned %d", rec.Code)
	}
}
