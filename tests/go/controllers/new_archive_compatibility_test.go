package controllers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/flosch/pongo2"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

func TestBusyKDFDoesNotConsumeFileViewsOrBlockPasswordlessDownloads(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, expected := resumeFixture(t, conn, u.ArchiveFormatAge, true)
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	passwordlessEcho, passwordlessToken, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	_, release, err := u.ReserveArchiveKDF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)

	for i := 0; i < 64; i++ {
		rec, downloadErr := downloadCompatibilityFile(t, e, token, "wrong-password")
		var httpErr *echo.HTTPError
		if !errors.As(downloadErr, &httpErr) || httpErr.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: error = %v, want 503", i, downloadErr)
		}
		if rec.Header().Get("Retry-After") != "1" {
			t.Fatalf("attempt %d: missing retry hint", i)
		}
	}
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || count != 0 {
		t.Fatalf("overloaded attempts consumed views: count=%d err=%v", count, err)
	}
	rec, err := downloadCompatibilityFile(t, passwordlessEcho, passwordlessToken, "")
	if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), plain) {
		t.Fatalf("passwordless download blocked by KDF: status=%d err=%v", rec.Code, err)
	}
	release()
	rec, err = downloadCompatibilityFile(t, e, token, password)
	if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), expected) {
		t.Fatalf("legacy download failed after recovery: status=%d err=%v", rec.Code, err)
	}
}

func TestEmptyFilePasswordConsumesViewsWithoutKDFAdmission(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, expected := resumeFixture(t, conn, u.ArchiveFormatAge, true)
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 3); err != nil {
		t.Fatal(err)
	}
	_, release, err := u.ReserveArchiveKDF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	for i := 0; i < 2; i++ {
		rec, downloadErr := downloadCompatibilityFile(t, e, token, "")
		if downloadErr != nil || rec.Code != http.StatusUnauthorized {
			t.Fatalf("empty password %d: status=%d err=%v", i, rec.Code, downloadErr)
		}
	}
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || count != 2 {
		t.Fatalf("empty password did not consume the expected views: count=%d err=%v", count, err)
	}
	keys, err := redis.Strings(conn.Do("KEYS", u.REDIS_PREFIX+"admission_file_kdf_*"))
	if err != nil || len(keys) != 0 {
		t.Fatalf("empty password consumed KDF admission: keys=%d err=%v", len(keys), err)
	}
	release()
	rec, err := downloadCompatibilityFile(t, e, token, password)
	if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), expected) {
		t.Fatalf("correct password after failures: status=%d err=%v", rec.Code, err)
	}
}

func TestArchiveKDFShareRateLimitDoesNotConsumeLastView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, expected := resumeFixture(t, conn, u.ArchiveFormatAge, true)
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the budget independently of expensive scrypt so the regression is
	// deterministic and the unconsumed view can be checked without delays.
	for i := 0; i < 4; i++ {
		allowed, err := u.AllowIdentityAction(id, "file_kdf_share", 4, 24, time.Minute)
		if err != nil || !allowed {
			t.Fatalf("seed share budget %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	rec, downloadErr := downloadCompatibilityFile(t, e, token, password)
	var httpErr *echo.HTTPError
	if !errors.As(downloadErr, &httpErr) || httpErr.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("limited download: error=%v retry=%q", downloadErr, rec.Header().Get("Retry-After"))
	}
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || count != 0 {
		t.Fatalf("rate limit consumed a view: count=%d err=%v", count, err)
	}
	// Simulate expiration of this one test's identity counter. Global and
	// origin counters remain, so the recovery still passes through admission.
	digest := sha256.Sum256([]byte(id))
	if _, err := conn.Do("DEL", u.REDIS_PREFIX+"admission_file_kdf_share_"+hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	rec, err = downloadCompatibilityFile(t, e, token, password)
	if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), expected) {
		t.Fatalf("download after budget recovery: status=%d err=%v", rec.Code, err)
	}
}

func TestArchiveKDFUploadOriginLimit(t *testing.T) {
	_ = configureCompatibilityRedis(t)
	e := echo.New()
	for i := 0; i < 7; i++ {
		ctx := e.NewContext(httptest.NewRequest(http.MethodPost, "/file", nil), httptest.NewRecorder())
		err := admitArchiveKDF(ctx, "", false)
		if i < 6 && err != nil {
			t.Fatalf("admission %d was rejected: %v", i, err)
		}
		if i == 6 {
			var httpErr *echo.HTTPError
			if !errors.As(err, &httpErr) || httpErr.Code != http.StatusTooManyRequests {
				t.Fatalf("seventh admission error = %v", err)
			}
		}
	}
}

type compatibilityRenderer struct {
	name string
	data pongo2.Context
}

func (r *compatibilityRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	r.name = name
	r.data = data.(pongo2.Context)
	_, err := io.WriteString(w, name)
	return err
}

func configureCompatibilityRedis(t *testing.T) redis.Conn {
	t.Helper()
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix, oldFolder, oldSize := u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX, u.FILEFOLDER, u.MaxFileSize
	t.Cleanup(func() {
		u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX, u.FILEFOLDER, u.MaxFileSize = oldHost, oldPort, oldDB, oldPassword, oldPrefix, oldFolder, oldSize
	})
	u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD = host, port, "0", ""
	u.REDIS_PREFIX, u.FILEFOLDER, u.MaxFileSize = "integration_archive_compat_"+uuid.NewString()+"_", t.TempDir(), 1<<20
	conn := u.NewPool().Get()
	if err := conn.Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func tokenFromCompatibilityLink(t *testing.T, raw, prefix string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(parsed.Path, prefix) {
		t.Fatalf("invalid generated link: %v", err)
	}
	token := strings.TrimPrefix(parsed.Path, prefix)
	if _, _, err := u.ParseToken(token); err != nil {
		t.Fatal("generated link does not contain a valid token")
	}
	return token
}

func createCompatibilityUpload(t *testing.T, password string) (*echo.Echo, *compatibilityRenderer) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for key, value := range map[string]string{"ttl": "1", "ttlViews": "4", "password": password, "deletable": "on"} {
		if err := form.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := form.CreateFormFile("files", "example.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "synthetic integration content"); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	renderer := &compatibilityRenderer{}
	e.Renderer, e.Validator = renderer, uploadValidator{}
	req := httptest.NewRequest(http.MethodPost, "/file", &body)
	req.Header.Set(echo.HeaderContentType, form.FormDataContentType())
	rec := httptest.NewRecorder()
	if err := AddFile(e.NewContext(req, rec)); err != nil || rec.Code != http.StatusOK || renderer.name != "confirm_file.html" {
		t.Fatalf("upload: status=%d view=%q error=%v", rec.Code, renderer.name, err)
	}
	return e, renderer
}

func downloadCompatibilityFile(t *testing.T, e *echo.Echo, token, password string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	form := url.Values{"password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/file/"+token, strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("file_key")
	ctx.SetParamValues(token)
	return rec, DownloadFile(ctx)
}

func assertCompatibilityZIP(t *testing.T, body []byte) {
	t.Helper()
	if !bytes.HasPrefix(body, []byte("PK\x03\x04")) {
		t.Fatal("download is not a ZIP stream")
	}
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil || len(archive.File) != 1 || archive.File[0].Name != "example.txt" {
		t.Fatalf("invalid ZIP entries: %v", err)
	}
	reader, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != "synthetic integration content" {
		t.Fatalf("invalid ZIP content: %v", err)
	}
}

func compatibilityZIPFixture(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	part, err := writer.Create("example.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "synthetic integration content"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNewPasswordArchiveIntegration(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	const password = "long synthetic passphrase 4930"
	e, renderer := createCompatibilityUpload(t, password)
	file := renderer.data["f"].(*models.File)
	if file.Password != "" {
		t.Fatal("upload confirmation exposes the password")
	}
	token := tokenFromCompatibilityLink(t, file.Link, "/file/")
	fileID, key, _ := u.ParseToken(token)
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+"file_"+fileID) })
	passwordLink, ok := renderer.data["passwordLink"].(string)
	if !ok || passwordLink == "" {
		t.Fatal("separate password link missing")
	}
	passwordToken := tokenFromCompatibilityLink(t, passwordLink, "/")
	passwordID, _, _ := u.ParseToken(passwordToken)
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+passwordID) })
	if passwordID == fileID {
		t.Fatal("password and file links share a storage identifier")
	}

	record, err := redis.StringMap(conn.Do("HGETALL", u.REDIS_PREFIX+"file_"+fileID))
	if err != nil || record["archive_format"] != u.ArchiveFormatAgeUserPassword || record["provided_key"] != passwordID {
		t.Fatalf("incorrect file metadata: %v", err)
	}
	for _, value := range record {
		if strings.Contains(value, password) {
			t.Fatal("plaintext password stored in file record")
		}
	}
	fileSecret, err := u.Decrypt([]byte(record["token"]), key, 0)
	if err != nil || strings.Contains(fileSecret, password) {
		t.Fatal("file-link key reveals the supplied archive password")
	}
	pw := &models.Password{PasswordKey: passwordToken}
	if err := u.RetrievePassword(pw); err != nil || pw.Password != password {
		t.Fatal("separate password link failed")
	}
	name, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(u.FILEFOLDER, name))
	if err != nil || !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) || bytes.Contains(ciphertext, []byte("synthetic integration content")) || bytes.Contains(ciphertext, []byte("example.txt")) {
		t.Fatal("stored archive is missing or exposes its contents")
	}

	rec, err := downloadCompatibilityFile(t, e, token, "wrong password")
	if err != nil || rec.Code != http.StatusUnauthorized || renderer.name != "file.html" {
		t.Fatalf("wrong password: status=%d view=%q error=%v", rec.Code, renderer.name, err)
	}
	visibleFile, ok := renderer.data["f"].(*models.File)
	if !ok || visibleFile.Password != "" || visibleFile.FileKey != token || renderer.data["passwordNeeded"] != true || renderer.data["ttl"] == nil || renderer.data["dlViews"] == nil || renderer.data["errors"] == nil {
		t.Fatal("wrong-password form did not preserve required state safely")
	}
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+fileID, "views_count"))
	if err != nil || count != 1 {
		t.Fatalf("wrong password did not consume exactly one attempt: %d, %v", count, err)
	}
	rec, err = downloadCompatibilityFile(t, e, token, password)
	if err != nil || rec.Code != http.StatusOK {
		t.Fatalf("valid download: status=%d error=%v", rec.Code, err)
	}
	assertCompatibilityZIP(t, rec.Body.Bytes())
	count, err = redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+fileID, "views_count"))
	if err != nil || count != 2 {
		t.Fatalf("valid download did not consume one attempt: %d, %v", count, err)
	}
}

func TestNewPasswordlessArchiveIntegration(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, renderer := createCompatibilityUpload(t, "")
	file := renderer.data["f"].(*models.File)
	if file.Password != "" || renderer.data["passwordLink"] != "" {
		t.Fatal("passwordless upload exposed a secret or password link")
	}
	token := tokenFromCompatibilityLink(t, file.Link, "/file/")
	fileID, key, _ := u.ParseToken(token)
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+"file_"+fileID) })
	record, err := redis.StringMap(conn.Do("HGETALL", u.REDIS_PREFIX+"file_"+fileID))
	if err != nil || record["archive_format"] != u.ArchiveFormatAgeX25519 || record["provided_key"] != "" {
		t.Fatalf("incorrect passwordless metadata: %v", err)
	}
	identity, err := u.Decrypt([]byte(record["token"]), key, 0)
	if err != nil || !strings.HasPrefix(identity, "AGE-SECRET-KEY-") {
		t.Fatal("passwordless archive identity was not protected by the link key")
	}
	name, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(u.FILEFOLDER, name))
	if err != nil || bytes.Contains(ciphertext, []byte(identity)) || bytes.Contains(ciphertext, []byte("synthetic integration content")) || !bytes.Contains(ciphertext, []byte("\n-> X25519 ")) {
		t.Fatal("passwordless archive is missing or exposes its identity or content")
	}
	rec, err := downloadCompatibilityFile(t, e, token, "")
	if err != nil || rec.Code != http.StatusOK {
		t.Fatalf("passwordless download: status=%d error=%v", rec.Code, err)
	}
	assertCompatibilityZIP(t, rec.Body.Bytes())
}

func TestLegacyZipAndFactor18LinksIntegration(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	const password = "legacy synthetic password"
	for _, tc := range []struct {
		name, format string
		protected    bool
	}{
		{"plain ZIP without password", "", false},
		{"plain ZIP with password", "", true},
		{"age factor 18 without password", u.ArchiveFormatAge, false},
		{"age factor 18 with password", u.ArchiveFormatAge, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var token string
			var errHTTP *echo.HTTPError
			if tc.format == "" {
				token, errHTTP = u.SetFile(password, 60, 2, true, tc.protected, "")
			} else {
				token, errHTTP = u.SetFile(password, 60, 2, true, tc.protected, "", tc.format)
			}
			if errHTTP != nil {
				t.Fatal(errHTTP)
			}
			fileID, _, _ := u.ParseToken(token)
			t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+"file_"+fileID) })
			contents := compatibilityZIPFixture(t)
			if tc.format == u.ArchiveFormatAge {
				recipient, err := age.NewScryptRecipient(password)
				if err != nil {
					t.Fatal(err)
				}
				recipient.SetWorkFactor(18)
				var encrypted bytes.Buffer
				writer, err := age.Encrypt(&encrypted, recipient)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(contents); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				contents = encrypted.Bytes()
			}
			name, err := archiveNameFromToken(token)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(u.FILEFOLDER, name), contents, 0600); err != nil {
				t.Fatal(err)
			}
			e := echo.New()
			e.Renderer = &compatibilityRenderer{}
			given := ""
			if tc.protected {
				given = password
			}
			rec, err := downloadCompatibilityFile(t, e, token, given)
			if err != nil || rec.Code != http.StatusOK {
				t.Fatalf("legacy download: status=%d error=%v", rec.Code, err)
			}
			assertCompatibilityZIP(t, rec.Body.Bytes())
		})
	}
}
