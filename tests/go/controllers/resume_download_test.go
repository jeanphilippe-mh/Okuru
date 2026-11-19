package controllers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func TestBusyKDFDoesNotConsumeResumeAttempts(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, plain := resumeFixture(t, conn, u.ArchiveFormatAgeUserPassword, true)
	cookie, prefix, etag := interruptedSessionWithPassword(t, conn, e, token, 5, password)
	if !bytes.Equal(prefix, plain[:5]) {
		t.Fatal("initial prefix mismatch")
	}
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	_, release, err := u.ReserveArchiveKDF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	const attempts = 32
	results := make(chan int, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, _ := getResume(e, token, cookie, "bytes=5-5", etag)
			results <- rec.Code
		}()
	}
	wg.Wait()
	close(results)
	for status := range results {
		if status != http.StatusServiceUnavailable {
			t.Fatalf("busy resume status=%d, want 503", status)
		}
	}
	counts, err := redis.Ints(conn.Do("HMGET", sessionKey, "requests", "used"))
	if err != nil || len(counts) != 2 || counts[0] != 0 || counts[1] != 0 {
		t.Fatalf("busy resumes consumed session budget: %v err=%v", counts, err)
	}
	release()
	// The password-protected initial GET already used one KDF admission.
	for i := 1; i < 8; i++ {
		allowed, err := u.AllowIdentityAction(id, "file_kdf_resume_share", 8, 24, time.Minute)
		if err != nil || !allowed {
			t.Fatalf("seed resume budget %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	limited, _ := getResume(e, token, cookie, "bytes=5-5", etag)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "60" {
		t.Fatalf("limited resume: status=%d retry=%q", limited.Code, limited.Header().Get("Retry-After"))
	}
	counts, err = redis.Ints(conn.Do("HMGET", sessionKey, "requests", "used"))
	if err != nil || len(counts) != 2 || counts[0] != 0 || counts[1] != 0 {
		t.Fatalf("rate-limited resume consumed session budget: %v err=%v", counts, err)
	}
	digest := sha256.Sum256([]byte(id))
	if _, err := conn.Do("DEL", u.REDIS_PREFIX+"admission_file_kdf_resume_share_"+hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	rec, err := getResume(e, token, cookie, "bytes=5-5", etag)
	if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), plain[5:6]) {
		t.Fatalf("resume after capacity recovery: status=%d err=%v", rec.Code, err)
	}
}

func resumeFixture(t *testing.T, conn redis.Conn, format string, protected bool) (*echo.Echo, string, string, []byte) {
	t.Helper()
	return resumeFixtureForZIP(t, conn, format, protected, compatibilityZIPFixture(t), 300)
}

func resumeFixtureForZIP(t *testing.T, conn redis.Conn, format string, protected bool, plain []byte, ttl int) (*echo.Echo, string, string, []byte) {
	t.Helper()
	secret := "resume-synthetic-password"
	var stored []byte
	switch format {
	case u.ArchiveFormatAgeUserPassword:
		recipient, err := age.NewScryptRecipient(secret)
		if err != nil {
			t.Fatal(err)
		}
		recipient.SetWorkFactor(18)
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, recipient)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		stored = buf.Bytes()
	case u.ArchiveFormatAgeX25519:
		var err error
		secret, err = u.GenerateArchiveIdentity()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, err := u.EncryptArchiveWithIdentity(t.Context(), &buf, secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(plain); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		stored = buf.Bytes()
	default:
		t.Fatalf("unsupported fixture format %q", format)
	}
	var passwordID string
	if protected {
		link, err := u.SetPassword(secret, ttl, 1, false)
		if err != nil {
			t.Fatal(err)
		}
		passwordID, _, _ = u.ParseToken(link)
		t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+passwordID) })
	}
	token, httpErr := u.SetFile(secret, ttl, 1, true, protected, passwordID, format)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+"file_"+id) })
	name, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u.FILEFOLDER, name), stored, 0600); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Renderer = &compatibilityRenderer{}
	password := ""
	if protected {
		password = secret
	}
	return e, token, password, plain
}

func getResume(e *echo.Echo, token string, cookie *http.Cookie, rangeValue, validator string) (*httptest.ResponseRecorder, error) {
	// Keep the selected share independent of the cookie to exercise cross-file rejection.
	path := "/file/" + token + "/download/" + downloadSessionDigest(cookie.Value)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Range", rangeValue)
	req.Header.Set("If-Range", validator)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	return rec, downloadRequest(e, rec, req, token)
}

func TestDownloadRedirectRequiresCookieAndAllowsOneInitialGET(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, archivePath := finalizationArchive(t, token)
	fileKey := u.REDIS_PREFIX + "file_" + id
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	// Leave another view on the share so completion does not remove the session.
	if _, err := conn.Do("HSET", fileKey, "views", 2); err != nil {
		t.Fatal(err)
	}
	post, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, post)
	req := httptest.NewRequest(http.MethodGet, post.Header().Get("Location"), nil)
	rec := httptest.NewRecorder()
	if err := downloadRequest(e, rec, req, token); rec.Code != http.StatusNotFound {
		t.Fatalf("GET without cookie: status=%d err=%v", rec.Code, err)
	}
	if rec, _ := getResume(e, token, cookie, "bytes=0-1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("range before initial GET was served: status=%d", rec.Code)
	}
	req.AddCookie(cookie)
	first := httptest.NewRecorder()
	if err := downloadRequest(e, first, req, token); err != nil || first.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), plain) {
		t.Fatalf("authorized first GET: status=%d err=%v", first.Code, err)
	}
	if first.Header().Get("Content-Length") != strconv.Itoa(len(plain)) || first.Header().Get("ETag") == "" || first.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatal("initial GET did not advertise resumable ZIP metadata")
	}
	modified := info.ModTime().UTC().Format(http.TimeFormat)
	if got := first.Header().Get("Last-Modified"); got != modified {
		t.Fatalf("initial Last-Modified=%q, want %q", got, modified)
	}
	if got := first.Header().Get("Cache-Control"); got != "private, no-store, no-transform" {
		t.Fatalf("initial Cache-Control=%q", got)
	}
	rec = httptest.NewRecorder()
	if err := downloadRequest(e, rec, req, token); rec.Code != http.StatusNotFound {
		t.Fatalf("replayed first GET: status=%d err=%v", rec.Code, err)
	}
	views, err := redis.Int(conn.Do("HGET", fileKey, "views_count"))
	if err != nil || views != 1 {
		t.Fatalf("POST plus GET requests used %d views: %v", views, err)
	}
}

func TestInterruptedDownloadRestartsWithoutRangeOnSameView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, format := range []string{u.ArchiveFormatAgeX25519, u.ArchiveFormatAgeUserPassword} {
		t.Run(format, func(t *testing.T) {
			e, token, password, plain := resumeFixture(t, conn, format, format == u.ArchiveFormatAgeUserPassword)
			id, path := finalizationArchive(t, token)
			cookie, _, etag := interruptedSessionWithPassword(t, conn, e, token, 11, password)
			count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
			if err != nil || count != 1 {
				t.Fatalf("unexpected reserved view count %d: %v", count, err)
			}
			for _, badRange := range []string{"", "not-a-range"} {
				for _, wrong := range []bool{false, true} {
					req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
					req.Header.Set("Range", badRange)
					if wrong {
						req.AddCookie(&http.Cookie{Name: cookie.Name, Value: "wrong"})
					}
					rec := httptest.NewRecorder()
					if err := downloadRequest(e, rec, req, token); err != nil || rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
						t.Fatalf("unauthorized retry: status=%d error=%v", rec.Code, err)
					}
				}
			}
			if rec, err := getResume(e, token, cookie, "not-a-range", ""); err != nil || rec.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Fatalf("authorized malformed range: status=%d error=%v", rec.Code, err)
			}
			rec, err := getResume(e, token, cookie, "", "")
			if err != nil || rec.Code != http.StatusOK || rec.Header().Get("Content-Range") != "" ||
				rec.Header().Get("ETag") != etag || rec.Header().Get("Content-Length") != strconv.Itoa(len(plain)) ||
				!bytes.Equal(rec.Body.Bytes(), plain) {
				t.Fatalf("full restart: status=%d length=%d error=%v", rec.Code, rec.Body.Len(), err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("completed one-view archive still present: %v", err)
			}
			if rec, err := getResume(e, token, cookie, "", ""); err != nil || rec.Code != http.StatusNotFound {
				t.Fatalf("replayed completed restart: status=%d error=%v", rec.Code, err)
			}
		})
	}
}

func TestInterruptedFullRestartKeepsOnlyRemainingRangeBudget(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, _, etag := interruptedSession(t, conn, e, token, 5)
	prefix, _ := interruptAuthorizedGET(t, e, token, cookie, 11, 0)
	id, _, _ := u.ParseToken(token)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	state, err := redis.StringMap(conn.Do("HGETALL", key))
	if err != nil || state["requests"] != "1" || state["used"] != "11" {
		t.Fatalf("interrupted restart: requests=%s used=%s error=%v", state["requests"], state["used"], err)
	}
	if rec, err := getResume(e, token, cookie, "", ""); err != nil || rec.Code != http.StatusNotFound {
		t.Fatalf("plain GET allowed another restart: status=%d error=%v", rec.Code, err)
	}
	rec, err := getResume(e, token, cookie, "bytes=11-", etag)
	if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(append(prefix, rec.Body.Bytes()...), plain) {
		t.Fatalf("remaining partial request failed: status=%d error=%v", rec.Code, err)
	}
}

func TestDownloadIfRangeHTTPDate(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	modified := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second).Add(250 * time.Millisecond)
	date := modified.Format(http.TimeFormat)
	future := modified.Add(time.Hour)
	for _, tc := range []struct {
		name             string
		fileTime         time.Time
		validator        string
		wantLastModified string
		wantStatus       int
	}{
		{"exact HTTP second", modified, date, date, http.StatusPartialContent},
		{"older date", modified, modified.Add(-time.Second).Format(http.TimeFormat), date, http.StatusOK},
		{"newer date", modified, modified.Add(time.Second).Format(http.TimeFormat), date, http.StatusOK},
		{"invalid date", modified, "yesterday", date, http.StatusOK},
		{"future archive timestamp", future, future.Format(http.TimeFormat), "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			_, path := finalizationArchive(t, token)
			if err := os.Chtimes(path, tc.fileTime, tc.fileTime); err != nil {
				t.Fatal(err)
			}
			const offset = 11
			cookie, prefix, etag := interruptedSession(t, conn, e, token, offset)
			missingCookie := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
			missingCookie.Header.Set("Range", "bytes=11-")
			missingCookie.Header.Set("If-Range", tc.validator)
			denied := httptest.NewRecorder()
			if err := downloadRequest(e, denied, missingCookie, token); err != nil || denied.Code != http.StatusNotFound || denied.Body.Len() != 0 {
				t.Fatalf("validator without cookie: status=%d err=%v", denied.Code, err)
			}
			rec, err := getResume(e, token, cookie, "bytes=11-", tc.validator)
			if err != nil || rec.Code != tc.wantStatus {
				t.Fatalf("resume returned status=%d err=%v, want %d", rec.Code, err, tc.wantStatus)
			}
			wantRange := ""
			data := rec.Body.Bytes()
			if tc.wantStatus == http.StatusPartialContent {
				wantRange = "bytes 11-" + strconv.Itoa(len(plain)-1) + "/" + strconv.Itoa(len(plain))
				data = append(prefix, data...)
			}
			if !bytes.Equal(data, plain) || rec.Header().Get("Content-Range") != wantRange {
				t.Fatalf("ZIP data or Content-Range differs: %q", rec.Header().Get("Content-Range"))
			}
			if rec.Header().Get("Last-Modified") != tc.wantLastModified || rec.Header().Get("ETag") != etag ||
				rec.Header().Get("Cache-Control") != "private, no-store, no-transform" {
				t.Fatal("resumed response changed its validators or cache policy")
			}
		})
	}
}

func TestDownloadIfRangeRejectsWeakETag(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, _, etag := interruptedSession(t, conn, e, token, 11)
	rec, err := getResume(e, token, cookie, "bytes=11-", "W/"+etag)
	if err != nil || rec.Code != http.StatusOK || rec.Header().Get("Content-Range") != "" ||
		!bytes.Equal(rec.Body.Bytes(), plain) {
		t.Fatalf("weak If-Range must return the complete ZIP: status=%d err=%v", rec.Code, err)
	}
}

func TestLongRunningZIPResumesFromExactOffsetWithFreshIdleWindow(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "45")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "2")
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.CreateHeader(&zip.FileHeader{Name: "large.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(bytes.Repeat([]byte("0123456789abcdef"), 1<<18)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	e, token, _, plain := resumeFixtureForZIP(t, conn, u.ArchiveFormatAgeX25519, false, archive.Bytes(), 3600)
	const offset = (1 << 20) + 19
	handoff, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, handoff)
	if cookie.MaxAge < 44 || cookie.MaxAge > 45 {
		t.Fatalf("cookie must cover the 45-second session: got %ds", cookie.MaxAge)
	}
	// Hold the first socket write past the idle timeout, then disconnect after a known byte.
	// A live request retains its session even if no new bytes fit into the socket.
	prefix, etag := interruptAuthorizedGET(t, e, token, cookie, offset, 2500*time.Millisecond)
	id, _ := finalizationArchive(t, token)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	ttl, err := redis.Int64(conn.Do("PTTL", key))
	if err != nil || ttl < 1200 || ttl > 2000 {
		t.Fatalf("interrupted transfer should have a fresh two-second resume window: %dms, err=%v", ttl, err)
	}
	rest, err := getResume(e, token, cookie, "bytes="+strconv.Itoa(offset)+"-", etag)
	if err != nil || rest.Code != http.StatusPartialContent || !bytes.Equal(prefix, plain[:offset]) || !bytes.Equal(rest.Body.Bytes(), plain[offset:]) {
		t.Fatalf("large ZIP continuation: status=%d err=%v", rest.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestRetryInitialGETAfterArchiveBecomesAvailable(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, path := finalizationArchive(t, token)
	post, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, post)
	req := httptest.NewRequest(http.MethodGet, post.Header().Get("Location"), nil)
	req.AddCookie(cookie)
	if err := os.Rename(path, path+".unavailable"); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := downloadRequest(e, rec, req, token); err == nil || rec.Code != http.StatusInternalServerError {
		t.Fatalf("initial GET while archive was unavailable: status=%d err=%v", rec.Code, err)
	}
	views, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || views != 1 {
		t.Fatalf("claimed views after failed GET: %d err=%v", views, err)
	}
	if err := os.Rename(path+".unavailable", path); err != nil {
		t.Fatal(err)
	}
	retry := httptest.NewRecorder()
	if err := downloadRequest(e, retry, req, token); err != nil || retry.Code != http.StatusOK || !bytes.Equal(retry.Body.Bytes(), plain) {
		t.Fatalf("initial GET after archive recovery: status=%d err=%v", retry.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestRangeSessionsSurviveUpgradeOnTheirOriginalURL(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _ := finalizationArchive(t, token)
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 2); err != nil {
		t.Fatal(err)
	}
	first, prefix1, etag1 := interruptedSession(t, conn, e, token, 11)
	second, prefix2, etag2 := interruptedSession(t, conn, e, token, 17)
	original := func(offset int, validator string) (*httptest.ResponseRecorder, error) {
		req := httptest.NewRequest(http.MethodGet, "/file/"+token, nil)
		req.AddCookie(first)
		req.AddCookie(second)
		req.Header.Set("Range", "bytes="+strconv.Itoa(offset)+"-")
		req.Header.Set("If-Range", validator)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPathValues(echo.PathValues{{Name: "file_key", Value: token}})
		return rec, ReadFile(c)
	}
	// Even a client that manually includes new cookies must use the dedicated URL.
	if rec, err := original(11, etag1); rec.Code != http.StatusNotFound {
		t.Fatalf("new session at share URL: status=%d err=%v", rec.Code, err)
	}
	for _, cookie := range []*http.Cookie{first, second} {
		key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
		// Older POSTs had already streamed the prefix; their Redis records did
		// not need a separate initial GET reservation.
		if _, err := conn.Do("HSET", key, "session_version", "2"); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Do("HDEL", key, "initial_started"); err != nil {
			t.Fatal(err)
		}
	}
	if rec, _ := getResume(e, token, first, "bytes=11-", etag1); rec.Code != http.StatusNotFound {
		t.Fatalf("old session at new URL: status=%d", rec.Code)
	}
	if rec, _ := original(11, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("ambiguous old sessions without If-Range: status=%d", rec.Code)
	}
	for _, tc := range []struct {
		prefix    []byte
		validator string
	}{{prefix1, etag1}, {prefix2, etag2}} {
		rec, err := original(len(tc.prefix), tc.validator)
		if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(tc.prefix), rec.Body.Bytes()...), plain) {
			t.Fatalf("old session on original URL: status=%d err=%v", rec.Code, err)
		}
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestResumeOneViewForBothArchiveFormats(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, tc := range []struct {
		name, format string
		protected    bool
	}{
		{"password-protected age", u.ArchiveFormatAgeUserPassword, true},
		{"passwordless age", u.ArchiveFormatAgeX25519, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, token, password, expected := resumeFixture(t, conn, tc.format, tc.protected)
			cookie, initial, etag := interruptedSessionWithPassword(t, conn, e, token, 5, password)
			if !bytes.Equal(initial, expected[:5]) {
				t.Fatal("interrupted ZIP prefix changed")
			}
			second, _ := downloadCompatibilityFile(t, e, token, password)
			if second.Code != http.StatusNotFound {
				t.Fatalf("second view status %d", second.Code)
			}
			rec, err := getResume(e, token, cookie, "bytes=5-19", etag)
			if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected[5:20]) {
				t.Fatalf("resume status=%d error=%v", rec.Code, err)
			}
			wantRange := "bytes 5-19/" + strconv.Itoa(len(expected))
			if rec.Header().Get("Content-Range") != wantRange {
				t.Fatal("invalid Content-Range")
			}
		})
	}
}

type changingReaderAt struct {
	file *os.File
	once sync.Once
}

func (r *changingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.file.ReadAt(p, off)
	r.once.Do(func() {
		_, _ = r.file.WriteAt([]byte("X"), 2)
		changed := time.Now().Add(2 * time.Second)
		_ = os.Chtimes(r.file.Name(), changed, changed)
	})
	return n, err
}

func TestMutationDuringStreamAborts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(path, []byte("synthetic-content"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	a := &downloadArchive{file: file, info: info, reader: &changingReaderAt{file: file}, size: info.Size(), etag: `"test"`}
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/file/test/download/session", nil), httptest.NewRecorder())
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("mutation during streaming did not abort")
		}
	}()
	_ = writeDownloadArchive(c, a, "test.zip", nil, &downloadProgress{})
}

func TestEncryptedValidatorRejectsShortRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := encryptedArchiveETag(file, 100); err == nil {
		t.Fatal("short archive was accepted")
	}
}

type interruptedResponseWriter struct {
	*httptest.ResponseRecorder
	remaining       int
	firstWriteDelay time.Duration
}

func (w *interruptedResponseWriter) Write(p []byte) (int, error) {
	if w.firstWriteDelay > 0 {
		time.Sleep(w.firstWriteDelay)
		w.firstWriteDelay = 0
	}
	if w.remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	n := min(w.remaining, len(p))
	w.remaining -= n
	w.ResponseRecorder.Write(p[:n])
	if w.remaining == 0 {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func TestInterruptedInitialDownloadResumesOneView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, prefix, _ := interruptedSessionWithPassword(t, conn, e, token, 11, password)
	id, _, _ := u.ParseToken(token)
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || count != 1 {
		t.Fatalf("initial download did not consume exactly one view: %d %v", count, err)
	}
	rec, err := getResume(e, token, cookie, "bytes=11-", "")
	if err != nil || rec.Code != http.StatusPartialContent {
		t.Fatalf("continuation: %d %v", rec.Code, err)
	}
	joined := append(bytes.Clone(prefix), rec.Body.Bytes()...)
	if !bytes.Equal(joined, plain) {
		t.Fatal("resumed bytes do not reconstruct the original ZIP")
	}
	if exists, err := redis.Int(conn.Do("EXISTS", u.REDIS_PREFIX+"file_"+id)); err != nil || exists != 0 {
		t.Fatalf("completed final view retained file metadata: %d %v", exists, err)
	}
}

func interruptedSession(t *testing.T, conn redis.Conn, e *echo.Echo, token string, prefixLen int) (*http.Cookie, []byte, string) {
	return interruptedSessionWithPassword(t, conn, e, token, prefixLen, "")
}

func interruptedSessionWithPassword(t *testing.T, conn redis.Conn, e *echo.Echo, token string, prefixLen int, password string) (*http.Cookie, []byte, string) {
	t.Helper()
	handoff, err := postDownload(t, e, token, password)
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, handoff)
	prefix, etag := interruptAuthorizedGET(t, e, token, cookie, prefixLen, 0)
	id, _, _ := u.ParseToken(token)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	t.Cleanup(func() { _, _ = conn.Do("DEL", key) })
	return cookie, prefix, etag
}

func interruptAuthorizedGET(t *testing.T, e *echo.Echo, token string, cookie *http.Cookie, prefixLen int, delay time.Duration) ([]byte, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
	req.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: prefixLen, firstWriteDelay: delay}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("initial GET did not abort")
			}
		}()
		_ = downloadRequest(e, writer, req, token)
	}()
	if recorder.Code != http.StatusOK || recorder.Body.Len() != prefixLen ||
		recorder.Header().Get("ETag") == "" || recorder.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatal("interrupted initial GET missing validator or bytes")
	}
	return bytes.Clone(recorder.Body.Bytes()), recorder.Header().Get("ETag")
}

func TestTwoInterruptedSessionsForSameFileResumeIndependently(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _, _ := u.ParseToken(token)
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 2); err != nil {
		t.Fatal(err)
	}
	first, prefix1, etag1 := interruptedSession(t, conn, e, token, 11)
	second, prefix2, etag2 := interruptedSession(t, conn, e, token, 17)
	if first.Name == second.Name || etag1 == etag2 {
		t.Fatal("sessions for the same file collided")
	}
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || count != 2 {
		t.Fatalf("unexpected view count before resuming: %d %v", count, err)
	}
	if first.Path == second.Path {
		t.Fatal("distinct sessions received the same GET URL")
	}
	for _, tc := range []struct {
		offset    int
		cookie    *http.Cookie
		validator string
		prefix    []byte
	}{{11, first, etag1, prefix1}, {17, second, etag2, prefix2}} {
		// The requested URL selects the session even when two cookies are supplied.
		req := httptest.NewRequest(http.MethodGet, tc.cookie.Path, nil)
		req.Header.Set("Range", "bytes="+strconv.Itoa(tc.offset)+"-")
		req.Header.Set("If-Range", tc.validator)
		req.AddCookie(first)
		req.AddCookie(second)
		rec := httptest.NewRecorder()
		err := downloadRequest(e, rec, req, token)
		if err != nil || rec.Code != http.StatusPartialContent {
			t.Fatalf("continuation: %d %v", rec.Code, err)
		}
		if !bytes.Equal(append(bytes.Clone(tc.prefix), rec.Body.Bytes()...), plain) {
			t.Fatal("incorrect session continuation")
		}
	}
	if exists, err := redis.Int(conn.Do("EXISTS", u.REDIS_PREFIX+"file_"+id)); err != nil || exists != 0 {
		t.Fatalf("both completed views retained file metadata: %d %v", exists, err)
	}
}

func TestResumeRefundsUnwrittenBytes(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, prefix, _ := interruptedSession(t, conn, e, token, 5)
	recorder := httptest.NewRecorder()
	writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: 5}
	req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
	req.Header.Set("Range", "bytes=0-")
	req.AddCookie(cookie)
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("interrupted continuation did not abort")
			}
		}()
		_ = downloadRequest(e, writer, req, token)
	}()
	rec, err := getResume(e, token, cookie, "bytes=5-", "")
	if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(prefix), rec.Body.Bytes()...), plain) {
		t.Fatalf("unused range was not refunded: status=%d error=%v", rec.Code, err)
	}
}

func TestCorruptedEncryptedChunkAbortsDownload(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	secret, err := u.GenerateArchiveIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	w, err := u.EncryptArchiveWithIdentity(t.Context(), &encrypted, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("synthetic-integrity-check"), 10000)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := bytes.Clone(encrypted.Bytes())
	if len(data) < 140000 {
		t.Fatal("fixture is too short")
	}
	data[8192] ^= 1 // corrupt an early chunk, leaving the authenticated final chunk intact
	token, httpErr := u.SetFile(secret, 300, 1, true, false, "", u.ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	id, _, _ := u.ParseToken(token)
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+"file_"+id) })
	name, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u.FILEFOLDER, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Renderer = &compatibilityRenderer{}
	handoff, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, handoff)
	req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
	req.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("corrupted chunk did not abort the response")
		}
		if recorder.Body.Len() != 0 {
			t.Error("corrupted chunk emitted unauthenticated plaintext")
		}
	}()
	_ = downloadRequest(e, recorder, req, token)
}

func TestPasswordV2ArchiveResumesWithoutRetainingPasswordUnderLink(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	const password = "synthetic long secret 498263"
	e, renderer := createCompatibilityUpload(t, password)
	f := renderer.data["f"].(*models.File)
	token := tokenFromCompatibilityLink(t, f.Link, "/file/")
	id, _, _ := u.ParseToken(token)
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+"file_"+id) })
	passwordToken := tokenFromCompatibilityLink(t, renderer.data["passwordLink"].(string), "/")
	passwordID, _, _ := u.ParseToken(passwordToken)
	t.Cleanup(func() { _, _ = conn.Do("DEL", u.REDIS_PREFIX+passwordID) })
	cookie, prefix, etag := interruptedSessionWithPassword(t, conn, e, token, 3, password)
	rec, err := getResume(e, token, cookie, "bytes=3-", etag)
	if err != nil || rec.Code != http.StatusPartialContent {
		t.Fatalf("password-protected resume: %d %v", rec.Code, err)
	}
	assertCompatibilityZIP(t, append(bytes.Clone(prefix), rec.Body.Bytes()...))
}

func TestResumeSessionsAreDistinctBoundedAndRevocable(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token1, _, expected1 := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	_, token2, _, expected2 := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie1, _, etag1 := interruptedSession(t, conn, e, token1, 11)
	cookie2, _, etag2 := interruptedSession(t, conn, e, token2, 11)
	if cookie1.Name == cookie2.Name || cookie1.Path == cookie2.Path {
		t.Fatal("cookies collide")
	}
	if rec, _ := getResume(e, token2, cookie1, "bytes=0-1", ""); rec.Code != http.StatusNotFound {
		t.Fatal("session crossed files")
	}
	if rec, err := getResume(e, token1, cookie1, "bytes=0-0", etag1); err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected1[:1]) {
		t.Fatal("first session broken")
	}
	if rec, err := getResume(e, token2, cookie2, "bytes=0-0", etag2); err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected2[:1]) {
		t.Fatal("second session broken")
	}
	id, _, _ := u.ParseToken(token1)
	digest := sha256.Sum256([]byte(cookie1.Value))
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
	if err := u.RemoveFile(&models.File{FileKey: token1}); err != nil {
		t.Fatal("authenticated file deletion failed")
	}
	if exists, err := redis.Int(conn.Do("EXISTS", sessionKey)); err != nil || exists != 0 {
		t.Fatal("deleted file left its encrypted download session in Redis")
	}
	if rec, _ := getResume(e, token1, cookie1, "bytes=1-2", ""); rec.Code != http.StatusNotFound {
		t.Fatal("deleted file remained resumable")
	}
	if rec, err := getResume(e, token2, cookie2, "bytes=1-2", ""); err != nil || rec.Code != http.StatusPartialContent {
		t.Fatal("other session affected by deletion")
	}
}

func TestResumeByteBudgetIsAtomic(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _, _ := u.ParseToken(token)
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 2); err != nil {
		t.Fatal(err)
	}
	cookie, _, _ := interruptedSession(t, conn, e, token, 5)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rec, _ := getResume(e, token, cookie, "bytes=0-", ""); codes <- rec.Code }()
	}
	wg.Wait()
	close(codes)
	var succeeded, rejected int
	for code := range codes {
		if code == http.StatusPartialContent {
			succeeded++
		}
		if code == http.StatusTooManyRequests || code == http.StatusNotFound {
			rejected++
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("full range for %d bytes: success=%d rejection=%d", len(plain), succeeded, rejected)
	}
	name, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(u.FILEFOLDER, name)); err != nil {
		t.Fatal(err)
	}
	// If the exhausted session reached archive opening (and potentially a
	// password KDF), the missing file would yield an internal error instead.
	if rec, _ := getResume(e, token, cookie, "bytes=0-1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("exhausted session reached archive: %d", rec.Code)
	}
}

func TestUnusedDownloadAuthorizationExpiresBeforeFirstGET(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "1")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "60")
	e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	handoff, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, handoff)
	time.Sleep(1200 * time.Millisecond)
	if rec, err := getResume(e, token, cookie, "", ""); err != nil || rec.Code != http.StatusNotFound {
		t.Fatalf("first GET after start deadline: status=%d err=%v", rec.Code, err)
	}
}

func TestInvalidResumeTimeoutDoesNotConsumeView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "invalid")
	e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	_, err := postDownload(t, e, token, "")
	var httpErr *echo.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Code != http.StatusInternalServerError {
		t.Fatalf("invalid resume timeout: want 500, got %v", err)
	}
	id, _ := finalizationArchive(t, token)
	views, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || views != 0 {
		t.Fatalf("invalid configuration spent a view: count=%d err=%v", views, err)
	}
}

func TestRejectedRangeDoesNotExtendResumeDeadline(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "30")
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, _, etag := interruptedSession(t, conn, e, token, 11)
	id, _ := finalizationArchive(t, token)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	expires, err := redis.Int64(conn.Do("PEXPIRETIME", key))
	if err != nil || expires <= 0 {
		t.Fatalf("resume deadline unavailable: %d, err=%v", expires, err)
	}
	time.Sleep(75 * time.Millisecond)
	if rec, err := getResume(e, token, cookie, "bytes="+strconv.Itoa(len(plain))+"-", etag); err != nil || rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("range beyond the ZIP: status=%d err=%v", rec.Code, err)
	}
	after, err := redis.Int64(conn.Do("PEXPIRETIME", key))
	if err != nil || after != expires {
		t.Fatalf("rejected range changed idle deadline from %d to %d, err=%v", expires, after, err)
	}
}

func TestResumeSessionExpiry(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "1")
	e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, _, _ := interruptedSession(t, conn, e, token, 11)
	time.Sleep(1200 * time.Millisecond)
	if rec, _ := getResume(e, token, cookie, "bytes=0-1", ""); rec.Code != http.StatusNotFound {
		t.Fatal("expired session remained usable")
	}
}

func TestSingleByteRangeValidation(t *testing.T) {
	for _, v := range []string{"", "bytes=", "bytes=-", "bytes=1-2,4-5", "bytes=20-21", "bytes=-0", "bytes=+1-2", "items=0-1"} {
		if _, _, err := parseSingleByteRange(v, 10); err == nil {
			t.Fatalf("accepted %q", v)
		}
	}
	for _, tc := range []struct {
		v             string
		start, length int64
	}{{"bytes=1-3", 1, 3}, {"bytes=4-", 4, 6}, {"bytes=-3", 7, 3}, {"bytes=0-99", 0, 10}} {
		start, length, err := parseSingleByteRange(tc.v, 10)
		if err != nil || start != tc.start || length != tc.length {
			t.Fatalf("%s: %d %d %v", tc.v, start, length, err)
		}
	}
}
