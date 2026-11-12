package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

func resumeFixture(t *testing.T, conn redis.Conn, format string, protected bool) (*echo.Echo, string, string, []byte) {
	t.Helper()
	plain := compatibilityZIPFixture(t)
	secret := "resume-synthetic-password"
	var stored []byte
	switch format {
	case "":
		stored = plain
	case u.ArchiveFormatAge:
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
	var token string
	var httpErr *echo.HTTPError
	if format == "" {
		token, httpErr = u.SetFile(secret, 300, 1, true, protected, "")
	} else {
		token, httpErr = u.SetFile(secret, 300, 1, true, protected, "", format)
	}
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
	req := httptest.NewRequest(http.MethodGet, "/file/"+token, nil)
	req.Header.Set("Range", rangeValue)
	if validator != "" {
		req.Header.Set("If-Range", validator)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("file_key")
	c.SetParamValues(token)
	err := ReadFile(c)
	if err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec, err
}

func TestResumeOneViewAndHistoricalLinks(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, tc := range []struct {
		name, format string
		protected    bool
	}{
		{"legacy zip", "", true},
		{"legacy age factor 18", u.ArchiveFormatAge, true},
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

func TestHistoricalZipAllowsRangeOnInitialPost(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, plain := resumeFixture(t, conn, "", true)
	form := url.Values{"password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/file/"+token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", echo.MIMEApplicationForm)
	req.Header.Set("Range", "bytes=1-8")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("file_key")
	ctx.SetParamValues(token)
	if err := DownloadFile(ctx); err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), plain[1:9]) {
		t.Fatalf("legacy POST range: %d %v", rec.Code, err)
	}
}

func TestLegacyZipMiddleMutationChangesIfRangeValidator(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, original := resumeFixture(t, conn, "", false)
	cookie, _, etag := interruptedSession(t, conn, e, token, 5)
	changed := bytes.Clone(original)
	changed[len(changed)/2] ^= 1
	name, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u.FILEFOLDER, name), changed, 0600); err != nil {
		t.Fatal(err)
	}
	rec, err := getResume(e, token, cookie, "bytes=0-5", etag)
	if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), changed) || rec.Header().Get("ETag") == etag {
		t.Fatalf("changed archive was mixed with an older copy: status=%d error=%v", rec.Code, err)
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

func TestLegacyMutationDuringStreamAborts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.zip")
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
	c := e.NewContext(httptest.NewRequest(http.MethodPost, "/file/test", nil), httptest.NewRecorder())
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("mutation during streaming did not abort")
		}
	}()
	_ = writeDownloadArchive(c, a, "legacy.zip", nil)
}

func TestLegacyHashRejectsShortRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.zip")
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := legacyArchiveETag(file, 100); err == nil {
		t.Fatal("short archive was accepted")
	}
}

type interruptedResponseWriter struct {
	*httptest.ResponseRecorder
	remaining int
}

func (w *interruptedResponseWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	n := min(w.remaining, len(p))
	w.remaining -= n
	w.ResponseRecorder.Write(p[:n])
	return n, io.ErrClosedPipe
}

func TestInterruptedInitialDownloadResumesOneView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	form := url.Values{"password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/file/"+token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", echo.MIMEApplicationForm)
	recorder := httptest.NewRecorder()
	writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: 11}
	c := e.NewContext(req, writer)
	c.SetParamNames("file_key")
	c.SetParamValues(token)
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("interrupted download did not abort")
			}
		}()
		_ = DownloadFile(c)
	}()
	var cookie *http.Cookie
	for _, item := range recorder.Result().Cookies() {
		name, err := downloadSessionCookie(token, item.Value)
		if err == nil && item.Name == name {
			cookie = item
		}
	}
	if cookie == nil || recorder.Body.Len() != 11 {
		t.Fatal("interrupted response did not retain cookie and partial bytes")
	}
	id, _, _ := u.ParseToken(token)
	digest := sha256.Sum256([]byte(cookie.Value))
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
	t.Cleanup(func() { _, _ = conn.Do("DEL", sessionKey) })
	count, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count"))
	if err != nil || count != 1 {
		t.Fatalf("initial download did not consume exactly one view: %d %v", count, err)
	}
	rec, err := getResume(e, token, cookie, "bytes=11-", "")
	if err != nil || rec.Code != http.StatusPartialContent {
		t.Fatalf("continuation: %d %v", rec.Code, err)
	}
	joined := append(bytes.Clone(recorder.Body.Bytes()), rec.Body.Bytes()...)
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
	form := url.Values{"password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/file/"+token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", echo.MIMEApplicationForm)
	recorder := httptest.NewRecorder()
	writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: prefixLen}
	c := e.NewContext(req, writer)
	c.SetParamNames("file_key")
	c.SetParamValues(token)
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("initial response did not abort")
			}
		}()
		_ = DownloadFile(c)
	}()
	var cookie *http.Cookie
	for _, item := range recorder.Result().Cookies() {
		name, err := downloadSessionCookie(token, item.Value)
		if err == nil && name == item.Name {
			cookie = item
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode ||
		cookie.Path != "/file/"+token || recorder.Body.Len() != prefixLen ||
		recorder.Header().Get("ETag") == "" || recorder.Header().Get("Accept-Ranges") != "bytes" {
		t.Fatal("interrupted session missing cookie, validator or bytes")
	}
	id, _, _ := u.ParseToken(token)
	digest := sha256.Sum256([]byte(cookie.Value))
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
	t.Cleanup(func() { _, _ = conn.Do("DEL", key) })
	return cookie, bytes.Clone(recorder.Body.Bytes()), recorder.Header().Get("ETag")
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
	resume := func(offset int, validator string) (*httptest.ResponseRecorder, error) {
		req := httptest.NewRequest(http.MethodGet, "/file/"+token, nil)
		req.Header.Set("Range", "bytes="+strconv.Itoa(offset)+"-")
		if validator != "" {
			req.Header.Set("If-Range", validator)
		}
		req.AddCookie(first)
		req.AddCookie(second)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("file_key")
		ctx.SetParamValues(token)
		err := ReadFile(ctx)
		if err != nil {
			e.HTTPErrorHandler(err, ctx)
		}
		return rec, err
	}
	if rec, _ := resume(11, ""); rec.Code != http.StatusNotFound {
		t.Fatal("ambiguous session without If-Range was accepted")
	}
	for _, tc := range []struct {
		offset    int
		validator string
		prefix    []byte
	}{{11, etag1, prefix1}, {17, etag2, prefix2}} {
		rec, err := resume(tc.offset, tc.validator)
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
	f := &models.File{FileKey: token}
	_, session, httpErr := u.ResumeFileDownload(f, cookie.Value)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	if httpErr := u.ReserveDownloadBytes(session, int64(len(plain))); httpErr != nil {
		t.Fatal(httpErr)
	}
	recorder := httptest.NewRecorder()
	writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: 5}
	req := httptest.NewRequest(http.MethodGet, "/file/"+token, nil)
	req.Header.Set("Range", "bytes=0-")
	c := e.NewContext(req, writer)
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("interrupted continuation did not abort")
			}
		}()
		_ = writeDownloadArchive(c, &downloadArchive{reader: bytes.NewReader(plain), size: int64(len(plain)), etag: `"test"`}, "test.zip", &downloadBudget{session: session, reserved: int64(len(plain))})
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
	req := httptest.NewRequest(http.MethodPost, "/file/"+token, nil)
	recorder := httptest.NewRecorder()
	c := e.NewContext(req, recorder)
	c.SetParamNames("file_key")
	c.SetParamValues(token)
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("corrupted chunk did not abort the response")
		}
		if recorder.Body.Len() != 0 {
			t.Error("corrupted chunk emitted unauthenticated plaintext")
		}
	}()
	_ = DownloadFile(c)
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

func TestResumeSessionExpiry(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "1s")
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
