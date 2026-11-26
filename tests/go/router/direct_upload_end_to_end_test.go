package router

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/utils"
)

type directE2EFile struct {
	name string
	data []byte
}

func directE2ERequest(t *testing.T, endpoint, token, password string, blob, mismatch bool, files []directE2EFile) *http.Request {
	t.Helper()
	manifest := make([]map[string]any, 0, len(files))
	for i, f := range files {
		size := len(f.data)
		if mismatch && i == len(files)-1 {
			size++
		}
		manifest = append(manifest, map[string]any{"name": f.name, "size": size})
	}
	metadata := map[string]any{"ttl_seconds": 3600, "views": 2, "deletable": true, "files": manifest}
	if password != "" {
		metadata["password"] = password
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	parameters := map[string]string{"name": "metadata"}
	if blob {
		parameters["filename"] = "blob"
	}
	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", mime.FormatMediaType("form-data", parameters))
	headers.Set("Content-Type", "application/json")
	part, err := mw.CreatePart(headers)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(part).Encode(metadata); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		part, err := mw.CreateFormFile("files", f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		req.Header.Set("X-CSRF-Token", token)
	}
	return req
}

func directE2EJSON(t *testing.T, client *http.Client, req *http.Request, status int, dst any) http.Header {
	t.Helper()
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if res.StatusCode != status || err != nil || mediaType != "application/json" ||
		!strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("expected HTTP %d JSON with no-store, got %d %q %q", status, res.StatusCode, mediaType, res.Header.Get("Cache-Control"))
	}
	if dst != nil {
		if err := json.NewDecoder(res.Body).Decode(dst); err != nil {
			t.Fatal(err)
		}
	}
	return res.Header
}

func directE2EDownload(t *testing.T, client *http.Client, rawURL, password string, files []directE2EFile) {
	t.Helper()
	preview, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	preview.Body.Close()
	if preview.StatusCode != http.StatusOK {
		t.Fatalf("file preview returned %d", preview.StatusCode)
	}
	var formToken string
	for _, cookie := range preview.Cookies() {
		if cookie.Name == "__Host-okuru-csrf" {
			formToken = cookie.Value
		}
	}
	if formToken == "" {
		t.Fatal("file preview did not supply the legacy form cookie")
	}
	res, err := client.PostForm(rawURL, url.Values{"_csrf": {formToken}, "password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Request.Method != http.MethodGet ||
		res.Request.Response == nil || res.Request.Response.StatusCode != http.StatusSeeOther ||
		res.Header.Get("Accept-Ranges") != "bytes" || res.Header.Get("ETag") == "" {
		t.Fatalf("expected a resumable GET after the form redirect, got %s %d", res.Request.Method, res.StatusCode)
	}
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil || len(zr.File) != len(files) {
		t.Fatalf("downloaded ZIP does not contain the expected files: %v", err)
	}
	for i, entry := range zr.File {
		want := files[i]
		if entry.Name != want.name || entry.UncompressedSize64 != uint64(len(want.data)) {
			t.Fatalf("entry %d has unexpected name or size", i)
		}
		rc, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(got, want.data) {
			t.Fatalf("entry %d payload mismatch: read=%v close=%v", i, readErr, closeErr)
		}
	}
}

func TestDirectUploadEndToEnd(t *testing.T) {
	prefix := configureLeaseTestRedis(t)
	conn := utils.NewPool().Get()
	t.Cleanup(func() { conn.Close() })
	folder, oldFolder, oldMax := t.TempDir(), utils.FILEFOLDER, utils.MaxFileSize
	utils.FILEFOLDER, utils.MaxFileSize = folder, 4<<20
	t.Cleanup(func() { utils.FILEFOLDER, utils.MaxFileSize = oldFolder, oldMax })
	t.Setenv("OKURU_SHORTLINK_PUBLIC_ORIGIN", "")
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "268435456")

	router := New()
	router.Renderer = securityTestRenderer{}
	ConfigureErrorHandler(router, t.TempDir())
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: server.Client().Transport, Jar: jar, Timeout: 30 * time.Second}
	noCookies := &http.Client{Transport: server.Client().Transport, Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v2/uploads/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	var limits struct {
		URL          string `json:"direct_url"`
		RequestBytes int64  `json:"max_request_bytes"`
		FileBytes    int64  `json:"max_file_bytes_total"`
	}
	header := directE2EJSON(t, client, req, http.StatusOK, &limits)
	token := header.Get("X-CSRF-Token")
	if token == "" || len(jar.Cookies(req.URL)) == 0 || limits.URL != "/api/v2/files/direct" ||
		limits.RequestBytes != 90_000_000 || limits.FileBytes != utils.MaxFileSize {
		t.Fatal("bootstrap did not provide credentials, endpoint and expected byte limits")
	}
	endpoint := server.URL + limits.URL
	files := []directE2EFile{{"first.bin", []byte{0xff, 0, 0x80, 13, 10}}, {"second.bin", bytes.Repeat([]byte{17, 0, 42}, 1024)}}

	for _, tc := range []struct {
		name     string
		client   *http.Client
		csrf     string
		mismatch bool
		status   int
	}{
		{"missing header", client, "", false, http.StatusForbidden},
		{"missing cookie", noCookies, token, false, http.StatusForbidden},
		{"wrong header", client, "different", false, http.StatusForbidden},
		{"wrong second file size", client, token, true, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := directE2ERequest(t, endpoint, tc.csrf, "", false, tc.mismatch, files)
			var failure struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			directE2EJSON(t, tc.client, req, tc.status, &failure)
			if strings.TrimSpace(failure.Code) == "" || strings.TrimSpace(failure.Message) == "" {
				t.Fatal("rejection must provide a nonempty JSON code and message")
			}
			keys, err := redis.Strings(conn.Do("KEYS", prefix+"file_*"))
			if err != nil || len(keys) != 0 {
				t.Fatalf("rejected upload left file metadata: count=%d err=%v", len(keys), err)
			}
			archives, err := filepath.Glob(filepath.Join(folder, "*.zip"))
			if err != nil || len(archives) != 0 {
				t.Fatalf("rejected upload published archives: count=%d err=%v", len(archives), err)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		blob     bool
		password string
	}{
		{"plain metadata", false, ""},
		{"browser Blob metadata", true, "a direct upload test password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var result struct {
				Link         string    `json:"link"`
				DeleteLink   string    `json:"delete_link"`
				PasswordLink *string   `json:"password_link"`
				ExpiresAt    time.Time `json:"expires_at"`
			}
			start := time.Now().Truncate(time.Second)
			req := directE2ERequest(t, endpoint, token, tc.password, tc.blob, false, files)
			directE2EJSON(t, client, req, http.StatusCreated, &result)
			if result.ExpiresAt.Before(start.Add(time.Hour)) || result.ExpiresAt.After(time.Now().Add(time.Hour+time.Second)) {
				t.Fatalf("unexpected expiration %v", result.ExpiresAt)
			}
			if result.Link == "" || result.DeleteLink == "" || (tc.password != "") != (result.PasswordLink != nil) ||
				(result.PasswordLink != nil && *result.PasswordLink == "") {
				t.Fatal("creation result does not provide the expected sharing links")
			}
			link, err := req.URL.Parse(result.Link)
			if err != nil || link.Host != req.URL.Host || link.Scheme != "https" || !strings.HasPrefix(link.Path, "/file/") {
				t.Fatal("creation result does not address the HTTPS file route")
			}
			id, _, err := utils.ParseToken(strings.TrimPrefix(link.Path, "/file/"))
			if err != nil {
				t.Fatal("unexpected file link")
			}
			key := prefix + "file_" + id
			ttl, err := redis.Int(conn.Do("TTL", key))
			if err != nil || ttl > 3600 || ttl < 3600-int(time.Since(start).Seconds())-1 {
				t.Fatalf("stored file TTL = %d: %v", ttl, err)
			}
			views, err := redis.Int(conn.Do("HGET", key, "views"))
			if err != nil || views != 2 {
				t.Fatalf("stored views = %d: %v", views, err)
			}
			deletion, err := req.URL.Parse(result.DeleteLink)
			if err != nil || deletion.Host != link.Host || deletion.Path != fmt.Sprintf("/file/remove/%s", strings.TrimPrefix(link.Path, "/file/")) {
				t.Fatal("deletion link does not refer to the created share")
			}
			directE2EDownload(t, client, link.String(), tc.password, files)
		})
	}
}
