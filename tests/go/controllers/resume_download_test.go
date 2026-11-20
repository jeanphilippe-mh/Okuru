package controllers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	path := downloadSessionPath(token, downloadSessionDigest(cookie.Value))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Range", rangeValue)
	req.Header.Set("If-Range", validator)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	return rec, downloadRequest(e, rec, req)
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
	if err := downloadRequest(e, rec, req); rec.Code != http.StatusNotFound {
		t.Fatalf("GET without cookie: status=%d err=%v", rec.Code, err)
	}
	if rec, _ := getResume(e, token, cookie, "bytes=0-1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("range before initial GET was served: status=%d", rec.Code)
	}
	req.AddCookie(cookie)
	first := httptest.NewRecorder()
	if err := downloadRequest(e, first, req); err != nil || first.Code != http.StatusOK || !bytes.Equal(first.Body.Bytes(), plain) {
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
	if err := downloadRequest(e, rec, req); rec.Code != http.StatusNotFound {
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
					if err := downloadRequest(e, rec, req); err != nil || rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
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
	prefix, _ := interruptAuthorizedGET(t, e, cookie, 11, 0)
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

func interruptDownloadRange(t *testing.T, e *echo.Echo, cookie *http.Cookie, byteRange, validator string, prefixLen int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
	req.AddCookie(cookie)
	req.Header.Set("Range", byteRange)
	req.Header.Set("If-Range", validator)
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Fatal("transfer did not stop on the simulated write error")
			}
		}()
		_ = downloadRequest(e, &interruptedResponseWriter{ResponseRecorder: rec, remaining: prefixLen}, req)
	}()
	return rec
}

func TestDoubleInterruptedValidatedRangeGap(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, tc := range []struct {
		name, first, second                            string
		initialMarker, firstValidator, secondValidator bool
		want                                           int
	}{
		{"validated gap", "bytes=5-", "bytes=24-", true, true, true, 200},
		{"overlapping first range", "bytes=3-", "bytes=24-", true, true, true, 200},
		{"overlap starts at zero", "bytes=0-", "bytes=24-", true, true, true, 200},
		{"gap beyond EOF", "bytes=3-", "bytes=9999999999-", true, true, true, 200},
		{"unvalidated gap beyond EOF", "bytes=5-", "bytes=9999999999-", true, true, false, 416},
		{"ordinary unsatisfiable offset", "bytes=6-", "bytes=9999999999-", true, true, true, 416},
		{"contiguous offset", "bytes=5-", "bytes=12-", true, true, true, 206},
		{"ordinary random range", "bytes=6-", "bytes=24-", true, true, true, 206},
		{"bounded first range", "bytes=5-18", "bytes=24-", true, true, true, 206},
		{"bounded second range", "bytes=5-", "bytes=24-31", true, true, true, 206},
		{"unvalidated first range", "bytes=5-", "bytes=24-", true, false, true, 206},
		{"unvalidated second range", "bytes=5-", "bytes=24-", true, true, false, 206},
		{"pre-upgrade interruption", "bytes=5-", "bytes=24-", false, true, true, 206},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			id, path := finalizationArchive(t, token)
			cookie, _, etag := interruptedSession(t, conn, e, token, 5)
			key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
			if !tc.initialMarker {
				if _, err := conn.Do("HDEL", key, "initial_written"); err != nil {
					t.Fatal(err)
				}
			}
			validator := ""
			if tc.firstValidator {
				validator = etag
			}
			first := interruptDownloadRange(t, e, cookie, tc.first, validator, 7)
			if first.Code != http.StatusPartialContent || first.Body.Len() != 7 {
				t.Fatal("invalid first partial response")
			}
			validator = ""
			if tc.secondValidator {
				validator = first.Header().Get("Last-Modified")
				if validator == "" {
					t.Fatal("missing date validator")
				}
			}
			second, err := getResume(e, token, cookie, tc.second, validator)
			if err != nil || second.Code != tc.want {
				t.Fatalf("next GET: status=%d err=%v", second.Code, err)
			}
			if tc.want == http.StatusRequestedRangeNotSatisfiable {
				if second.Body.Len() != 0 || second.Header().Get("Content-Range") != "bytes */"+strconv.Itoa(len(plain)) {
					t.Fatal("invalid unsatisfiable-range response")
				}
				return
			}
			data := plain
			if tc.want == http.StatusPartialContent {
				start, count, err := parseSingleByteRange(tc.second, int64(len(plain)))
				if err != nil {
					t.Fatal(err)
				}
				data = plain[start : start+count]
			} else if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("completed replacement failed to finalize the original view")
			}
			if (second.Header().Get("Content-Range") == "") != (tc.want == http.StatusOK) || second.Header().Get("ETag") != etag ||
				second.Header().Get("Content-Length") != strconv.Itoa(len(data)) || !bytes.Equal(data, second.Body.Bytes()) {
				t.Fatal("response bytes, range, length or entity tag are incorrect")
			}
		})
	}
}

func TestPlainGETRestartsAfterFirstVerifiedRangeInterrupted(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, path := finalizationArchive(t, token)
	cookie, _, etag := interruptedSession(t, conn, e, token, 5)
	first := interruptDownloadRange(t, e, cookie, "bytes=3-", etag, 7)
	if first.Code != http.StatusPartialContent || !bytes.Equal(first.Body.Bytes(), plain[3:10]) {
		t.Fatal("first continuation did not deliver the expected partial bytes")
	}
	for _, value := range []string{"", "invalid"} {
		req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
		if value != "" {
			req.AddCookie(&http.Cookie{Name: cookie.Name, Value: value})
		}
		rec := httptest.NewRecorder()
		if err := downloadRequest(e, rec, req); err != nil || rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
			t.Fatalf("plain GET without valid cookie: status=%d err=%v", rec.Code, err)
		}
	}
	if views, err := redis.Int(conn.Do("HGET", u.REDIS_PREFIX+"file_"+id, "views_count")); err != nil || views != 1 {
		t.Fatalf("initial POST and partial transfers reserved %d views: %v", views, err)
	}
	rec, err := getResume(e, token, cookie, "", "")
	if err != nil || rec.Code != http.StatusOK || rec.Header().Get("Content-Range") != "" ||
		rec.Header().Get("Content-Length") != strconv.Itoa(len(plain)) ||
		rec.Header().Get("ETag") != etag || !bytes.Equal(rec.Body.Bytes(), plain) {
		t.Fatalf("plain restart did not return the full ZIP: status=%d bytes=%d err=%v", rec.Code, rec.Body.Len(), err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("completed one-view archive was not deleted: %v", err)
	}
	if rec, err := getResume(e, token, cookie, "", ""); err != nil || rec.Code != http.StatusNotFound {
		t.Fatalf("duplicate full restart: status=%d err=%v", rec.Code, err)
	}
}

type downloadHandoffTestConn struct {
	redis.ConnWithContext
	settlingArgs int
	sessionKey   string
	finishing    chan<- struct{}
	allowFinish  <-chan struct{}
	rechecking   chan<- struct{}
	finishPaused *atomic.Bool
	previewReads *atomic.Int32
}

func (c *downloadHandoffTestConn) Do(command string, args ...any) (any, error) {
	if (command == "EVALSHA" || command == "EVAL") && len(args) == c.settlingArgs && args[3] == c.sessionKey &&
		c.finishPaused.CompareAndSwap(false, true) {
		close(c.finishing)
		<-c.allowFinish
	}
	reply, err := c.ConnWithContext.Do(command, args...)
	c.observePreview(command, args, err)
	return reply, err
}

func (c *downloadHandoffTestConn) DoContext(ctx context.Context, command string, args ...any) (any, error) {
	reply, err := c.ConnWithContext.DoContext(ctx, command, args...)
	c.observePreview(command, args, err)
	return reply, err
}

func (c *downloadHandoffTestConn) observePreview(command string, args []any, err error) {
	if err == nil && (command == "EVALSHA" || command == "EVAL") &&
		(len(args) == 6 || len(args) == 7) && args[3] == c.sessionKey && args[5] == 32 && c.previewReads.Add(1) == 2 {
		c.rechecking <- struct{}{}
	}
}

func TestAuthenticatedPlainGETWaitsForInterruptedTransfer(t *testing.T) {
	t.Run("initial GET", func(t *testing.T) { testAuthenticatedPlainGETHandoff(t, false) })
	t.Run("first range GET", func(t *testing.T) { testAuthenticatedPlainGETHandoff(t, true) })
}

func testAuthenticatedPlainGETHandoff(t *testing.T, firstRange bool) {
	t.Helper()
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, path := finalizationArchive(t, token)
	var cookie *http.Cookie
	var validator string
	settlingArgs, expectedRequests, expectedUsed := 17, 0, 0 // RecordDownloadProgress
	if firstRange {
		cookie, _, validator = interruptedSession(t, conn, e, token, 5)
		settlingArgs, expectedRequests, expectedUsed = 8, 1, len(plain) // RefundDownloadBytes
	} else {
		handoff, err := postDownload(t, e, token, "")
		if err != nil {
			t.Fatal(err)
		}
		cookie = authorizedDownload(t, token, handoff)
	}
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	t.Cleanup(func() { _, _ = conn.Do("DEL", sessionKey) })

	if err := u.CloseRedisPool(); err != nil {
		t.Fatal(err)
	}
	finishing, allowFinish, rechecking := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	release := sync.OnceFunc(func() { close(allowFinish) })
	var finishPaused atomic.Bool
	var previewReads atomic.Int32
	pool := u.NewPool()
	dial := pool.DialContext
	pool.DialContext = func(ctx context.Context) (redis.Conn, error) {
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return &downloadHandoffTestConn{c.(redis.ConnWithContext), settlingArgs, sessionKey, finishing, allowFinish, rechecking, &finishPaused, &previewReads}, nil
	}
	t.Cleanup(func() { _ = u.CloseRedisPool() })

	initial := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
	initial.AddCookie(cookie)
	written, previousStatus := 5, http.StatusOK
	if firstRange {
		initial.Header.Set("Range", "bytes=0-")
		initial.Header.Set("If-Range", validator)
		written, previousStatus = 9, http.StatusPartialContent
	}
	initialResponse := &interruptedResponseWriter{ResponseRecorder: httptest.NewRecorder(), remaining: written}
	initialDone := make(chan any, 1)
	go func() {
		defer func() { initialDone <- recover() }()
		_ = downloadRequest(e, initialResponse, initial)
	}()
	defer func() {
		release()
		if result := <-initialDone; result != http.ErrAbortHandler {
			t.Errorf("original GET did not abort: %v", result)
		}
	}()
	select {
	case <-finishing:
	case <-time.After(time.Second):
		t.Fatal("original GET did not reach Redis finalization")
	}
	if initialResponse.Code != previousStatus || initialResponse.Body.Len() != written {
		t.Fatalf("original GET returned %d and %d bytes", initialResponse.Code, initialResponse.Body.Len())
	}
	state := func() string {
		t.Helper()
		fields, err := redis.Strings(conn.Do("HMGET", sessionKey, "active", "requests", "used", "idle_deadline", "absolute_deadline"))
		if err != nil || len(fields) != 5 || fields[0] != "1" ||
			fields[1] != strconv.Itoa(expectedRequests) || fields[2] != strconv.Itoa(expectedUsed) {
			t.Fatalf("waiting GET changed active transfers or budgets: %v err=%v", fields, err)
		}
		return strings.Join(fields, ",")
	}
	before := state()
	previewReads.Store(0)
	missing := httptest.NewRecorder()
	if err := downloadRequest(e, missing, httptest.NewRequest(http.MethodGet, cookie.Path, nil)); err != nil ||
		missing.Code != http.StatusNotFound || missing.Body.Len() != 0 || previewReads.Load() != 0 {
		t.Fatalf("GET without cookie reached the handoff: status=%d err=%v", missing.Code, err)
	}
	resumed := make(chan *httptest.ResponseRecorder, 2)
	resume := func(ctx context.Context) {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, cookie.Path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		_ = downloadRequest(e, rec, req)
		resumed <- rec
	}
	requireRecheck := func() {
		t.Helper()
		select {
		case <-rechecking:
		case rec := <-resumed:
			t.Fatalf("replacement GET returned %d before the original GET was finalized", rec.Code)
		case <-time.After(time.Second):
			t.Fatal("replacement GET did not recheck the active transfer")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go resume(ctx)
	requireRecheck()
	cancel()
	select {
	case rec := <-resumed:
		if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
			t.Fatalf("canceled handoff returned %d and %d bytes", rec.Code, rec.Body.Len())
		}
	case <-time.After(time.Second):
		t.Fatal("handoff did not stop after request cancellation")
	}
	if after := state(); after != before {
		t.Fatalf("canceled handoff changed session deadlines: before=%s after=%s", before, after)
	}
	previewReads.Store(0)
	go resume(t.Context())
	requireRecheck()
	go resume(t.Context())
	release()
	accepted := 0
	for range 2 {
		select {
		case rec := <-resumed:
			switch rec.Code {
			case http.StatusOK:
				accepted++
				if rec.Header().Get("Content-Range") != "" || !bytes.Equal(rec.Body.Bytes(), plain) {
					t.Fatal("replacement GET did not deliver the full original ZIP")
				}
			case http.StatusNotFound:
				if rec.Body.Len() != 0 {
					t.Fatal("concurrent replacement received bytes")
				}
			default:
				t.Fatalf("unexpected replacement status %d", rec.Code)
			}
		case <-time.After(time.Second):
			t.Fatal("replacement GET did not finish")
		}
	}
	if accepted != 1 {
		t.Fatalf("%d replacement GETs were admitted, want exactly one", accepted)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("completed one-view archive was not deleted: %v", err)
	}
}

func TestAuthenticatedPlainGETHandoffHonorsWaitLimit(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	handoff, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, handoff)
	_, initial, fault := u.StartTrackedFileDownload(&models.File{FileKey: token}, cookie.Value)
	if fault != nil {
		t.Fatal(fault)
	}
	defer func() { _ = u.AbandonDownloadPreparation(initial) }()
	if err := initial.MarkDownloadStreaming(); err != nil {
		t.Fatal(err)
	}
	id, _, _ := u.ParseToken(token)
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	t.Cleanup(func() { _, _ = conn.Do("DEL", sessionKey) })
	state := func() string {
		t.Helper()
		fields, err := redis.Strings(conn.Do("HMGET", sessionKey, "active", "requests", "used", "idle_deadline", "absolute_deadline"))
		if err != nil || len(fields) != 5 {
			t.Fatalf("could not read session state: %v err=%v", fields, err)
		}
		return strings.Join(fields, ",")
	}
	before := state()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, cookie.Path, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	started := time.Now()
	if err := downloadRequest(e, rec, req); err != nil || rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
		t.Fatalf("handoff returned status=%d err=%v while the first GET was active", rec.Code, err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second || elapsed < 100*time.Millisecond {
		t.Fatalf("handoff ignored its bounded wait: elapsed=%s", elapsed)
	}
	if after := state(); after != before {
		t.Fatalf("handoff changed deadlines or budget: before=%s after=%s", before, after)
	}
}

func TestPlainGETAfterRangeRequiresVerifiedPrefixAndByteBudget(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, scenario := range []string{"unvalidated", "prefix gap", "overlap exceeds first allowance", "later admitted range"} {
		t.Run(scenario, func(t *testing.T) {
			e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			initial := len(plain) / 2
			cookie, _, etag := interruptedSession(t, conn, e, token, initial)
			byteRange, validator, written := "bytes=1-", etag, initial
			switch scenario {
			case "unvalidated":
				validator = ""
			case "prefix gap":
				byteRange = fmt.Sprintf("bytes=%d-", initial+1)
				written = 7
			case "overlap exceeds first allowance":
				written = len(plain) - initial + 1
			}
			if first := interruptDownloadRange(t, e, cookie, byteRange, validator, written); first.Code != http.StatusPartialContent {
				t.Fatal("first range was refused")
			}
			if scenario == "later admitted range" {
				_, other, fault := u.ResumeStartedFileDownload(&models.File{FileKey: token}, cookie.Value)
				if fault != nil {
					t.Fatal(fault)
				}
				if err := u.AbandonDownloadPreparation(other); err != nil {
					t.Fatal(err)
				}
			}
			if rec, err := getResume(e, token, cookie, "", ""); err != nil || rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
				t.Fatalf("plain restart was accepted: status=%d bytes=%d err=%v", rec.Code, rec.Body.Len(), err)
			}
			offset := len(plain) - 1
			if rec, err := getResume(e, token, cookie, fmt.Sprintf("bytes=%d-", offset), etag); err != nil ||
				rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), plain[offset:]) {
				t.Fatalf("ordinary continuation failed: status=%d err=%v", rec.Code, err)
			}
		})
	}
}

func TestPlainGETAfterRangeKeepsItsReservationAndDeadlineAfterPreHeaderFailure(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, scenario := range []string{"retry", "attempt limit", "idle expired", "session expired", "intervening range"} {
		t.Run(scenario, func(t *testing.T) {
			e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			id, _, _ := u.ParseToken(token)
			cookie, _, etag := interruptedSession(t, conn, e, token, 5)
			_ = interruptDownloadRange(t, e, cookie, "bytes=3-", etag, 7)
			key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
			idle := time.Now().Add(25 * time.Second).UnixMilli()
			if _, err := conn.Do("HSET", key, "idle_deadline", idle); err != nil {
				t.Fatal(err)
			}
			absolute, err := redis.Int64(conn.Do("HGET", key, "absolute_deadline"))
			if err != nil {
				t.Fatal(err)
			}
			f := &models.File{FileKey: token}
			failures := 1
			if scenario == "attempt limit" {
				failures = 31
			}
			for i := 0; i < failures; i++ {
				_, session, fault := u.StartTrackedFileDownload(f, cookie.Value)
				if fault != nil || session.IsInitialGET() {
					t.Fatalf("plain replacement %d could not reserve one full response: %v", i, fault)
				}
				for _, byteRange := range []string{"", "bytes=4-5"} {
					if rec, err := getResume(e, token, cookie, byteRange, etag); err != nil || rec.Code != http.StatusNotFound {
						t.Fatal("competing request accepted during an exclusive restart")
					}
				}
				// The Redis streaming marker may have succeeded even though the
				// application has not sent the first response header.
				if err := session.MarkDownloadStreaming(); err != nil {
					t.Fatal(err)
				}
				if err := u.AbandonDownloadPreparation(session); err != nil {
					t.Fatal(err)
				}
				state, err := redis.Int64s(conn.Do("HMGET", key, "used", "requests", "active", "idle_deadline", "absolute_deadline"))
				if err != nil || len(state) != 5 || state[0] != 7 || state[1] != int64(2+i) ||
					state[2] != 0 || state[3] != idle || state[4] != absolute {
					t.Fatalf("abandonment changed the original charge or deadlines: %v %v", state, err)
				}
			}
			want := http.StatusNotFound
			switch scenario {
			case "retry":
				want = http.StatusOK
			case "idle expired", "session expired":
				deadline := "idle_deadline"
				if scenario == "session expired" {
					deadline = "absolute_deadline"
				}
				if _, err := conn.Do("HSET", key, deadline, time.Now().Add(-time.Second).UnixMilli()); err != nil {
					t.Fatal(err)
				}
			case "intervening range":
				if rec, err := getResume(e, token, cookie, "bytes=10-10", etag); err != nil || rec.Code != http.StatusPartialContent {
					t.Fatalf("ordinary intervening range: status=%d err=%v", rec.Code, err)
				}
			}
			rec, err := getResume(e, token, cookie, "", "")
			if err != nil || rec.Code != want || (want == http.StatusOK && !bytes.Equal(rec.Body.Bytes(), plain)) {
				t.Fatalf("plain replacement after abandonment: status=%d want=%d err=%v", rec.Code, want, err)
			}
		})
	}
}

func TestOverlappingRangesCannotExceedTwoZIPs(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, archive := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	initial := len(archive) / 2
	cookie, _, etag := interruptedSession(t, conn, e, token, initial)
	// The writer handed off more than one ZIP in the two overlapping transfers,
	// even though their union still has a hole near the end.
	first := interruptDownloadRange(t, e, cookie, "bytes=1-", etag, len(archive)-initial+1)
	if first.Code != http.StatusPartialContent {
		t.Fatal("first range failed")
	}
	from := len(archive) - 1
	next, err := getResume(e, token, cookie, "bytes="+strconv.Itoa(from)+"-", etag)
	if err != nil || next.Code != http.StatusPartialContent || !bytes.Equal(next.Body.Bytes(), archive[from:]) {
		t.Fatal("overspent initial allowance authorized a complete ZIP")
	}
}

func TestGapReplacementExclusivityAndPreHeaderRollback(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, concurrent := range []bool{false, true} {
		e, token, _, archive := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
		id, _, _ := u.ParseToken(token)
		cookie, _, etag := interruptedSession(t, conn, e, token, 5)
		_ = interruptDownloadRange(t, e, cookie, "bytes=3-", etag, 7)
		_, session, sessionErr := u.ResumeStartedFileRange(&models.File{FileKey: token}, cookie.Value, "bytes=24-", etag)
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		reserved := int64(len(archive) - 24)
		if err := u.ReserveDownloadBytes(session, reserved); err != nil {
			t.Fatal(err)
		}
		if concurrent {
			_, other, err := u.ResumeStartedFileDownload(&models.File{FileKey: token}, cookie.Value)
			if err != nil {
				t.Fatal(err)
			}
			if err := u.AbandonDownloadPreparation(other); err != nil {
				t.Fatal(err)
			}
		}
		promoted, err := session.ValidateOpenRange(24, reserved)
		if err != nil || promoted == concurrent {
			t.Fatalf("concurrent=%v promoted=%v err=%v", concurrent, promoted, err)
		}
		if promoted {
			if denied, err := getResume(e, token, cookie, "bytes=24-", etag); err != nil || denied.Code != http.StatusNotFound {
				t.Fatal("competing request admitted during exclusive replacement")
			}
		} else if err := u.RefundDownloadBytes(session, reserved); err != nil {
			t.Fatal(err)
		}
		if err := u.AbandonDownloadPreparation(session); err != nil {
			t.Fatal(err)
		}
		key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
		counts, err := redis.Ints(conn.Do("HMGET", key, "used", "active"))
		if err != nil || len(counts) != 2 || counts[0] != 7 || counts[1] != 0 {
			t.Fatalf("lost original range charges after pre-header failure: %v %v", counts, err)
		}
	}
}

func TestInterruptedReplacementRefundsOnlyUnwrittenBytes(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, scenario := range []string{"forward gap", "plain GET"} {
		t.Run(scenario, func(t *testing.T) {
			e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			id, _, _ := u.ParseToken(token)
			cookie, _, etag := interruptedSession(t, conn, e, token, 5)
			first := interruptDownloadRange(t, e, cookie, "bytes=5-", etag, 7)
			byteRange, validator := "bytes=24-", etag
			if scenario == "plain GET" {
				byteRange, validator = "", ""
			}
			replacement := interruptDownloadRange(t, e, cookie, byteRange, validator, 9)
			if first.Code != http.StatusPartialContent || replacement.Code != http.StatusOK || !bytes.Equal(replacement.Body.Bytes(), plain[:9]) {
				t.Fatal("replacement did not start at byte zero")
			}
			key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
			state, err := redis.StringMap(conn.Do("HGETALL", key))
			if err != nil || state["used"] != "9" || state["restart_available"] != "0" || state["active"] != "0" ||
				state["requests"] != "2" || state["initial_written"] != "5" || state["interrupted_prefix"] != "12" {
				t.Fatal("incorrect byte accounting after interrupted replacement")
			}
			if replay, err := getResume(e, token, cookie, "", ""); err != nil || replay.Code != http.StatusNotFound {
				t.Fatal("additional full replay admitted")
			}
			final, err := getResume(e, token, cookie, "bytes=9-", etag)
			if err != nil || final.Code != http.StatusPartialContent || !bytes.Equal(final.Body.Bytes(), plain[9:]) {
				t.Fatal("could not complete within the remaining byte allowance")
			}
		})
	}
}

func TestIdenticalGapRetryAfterPreHeaderFailure(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, scenario := range []string{"identical", "beyond EOF", "changed offset", "changed validator", "intervening range", "limit", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			e, token, _, archive := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			id, _, _ := u.ParseToken(token)
			cookie, _, etag := interruptedSession(t, conn, e, token, 5)
			first := interruptDownloadRange(t, e, cookie, "bytes=3-", etag, 7)
			key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
			holdUntil := time.Now().Add(25 * time.Second).UnixMilli()
			if _, err := conn.Do("HSET", key, "idle_deadline", holdUntil); err != nil {
				t.Fatal(err)
			}
			start := 24
			if scenario == "beyond EOF" {
				start = len(archive) + 1
			}
			byteRange := "bytes=" + strconv.Itoa(start) + "-"
			reserved := int64(max(0, len(archive)-start))
			// Simulate a successful Redis streaming mark whose reply was lost:
			// the server still knows it has emitted zero archive headers or bytes.
			failures := 1
			if scenario == "limit" {
				failures = 31
			}
			for i := 0; i < failures; i++ {
				_, session, fault := u.ResumeStartedFileRange(&models.File{FileKey: token}, cookie.Value, byteRange, etag)
				if fault != nil {
					t.Fatal(fault)
				}
				if i > 0 {
					if _, _, competing := u.ResumeStartedFileRange(&models.File{FileKey: token}, cookie.Value, byteRange, etag); competing == nil {
						t.Fatal("competing retry admitted before archive validation")
					}
				}
				if err := u.ReserveDownloadBytes(session, reserved); err != nil {
					t.Fatal(err)
				}
				if promoted, err := session.ValidateOpenRange(int64(start), reserved); err != nil || !promoted {
					t.Fatalf("attempt %d did not acquire the full response: %v", i, err)
				}
				if err := session.MarkDownloadStreaming(); err != nil {
					t.Fatal(err)
				}
				if err := u.AbandonDownloadPreparation(session); err != nil {
					t.Fatal(err)
				}
				state, err := redis.Int64s(conn.Do("HMGET", key, "used", "requests", "active", "idle_deadline"))
				if err != nil || len(state) != 4 || state[0] != 7 || state[1] != int64(2+i) || state[2] != 0 || state[3] != holdUntil {
					t.Fatalf("abandonment changed the budget, deadline or admission counter: %v %v", state, err)
				}
			}
			validator, want := etag, http.StatusOK
			switch scenario {
			case "changed offset":
				byteRange, want = "bytes=25-", http.StatusPartialContent
			case "changed validator":
				validator, want = first.Header().Get("Last-Modified"), http.StatusPartialContent
			case "intervening range":
				if other, err := getResume(e, token, cookie, "bytes=20-20", etag); err != nil || other.Code != http.StatusPartialContent {
					t.Fatal("unrelated range was refused")
				}
				want = http.StatusPartialContent
			case "limit":
				want = http.StatusNotFound
			case "expired":
				if _, err := conn.Do("HSET", key, "idle_deadline", time.Now().Add(-time.Second).UnixMilli()); err != nil {
					t.Fatal(err)
				}
				want = http.StatusNotFound
			}
			result, err := getResume(e, token, cookie, byteRange, validator)
			if err != nil || result.Code != want {
				t.Fatalf("after abandonment: status=%d want=%d err=%v", result.Code, want, err)
			}
			if want == http.StatusOK && (!bytes.Equal(result.Body.Bytes(), archive) || result.Header().Get("ETag") != etag || result.Header().Get("Content-Range") != "") {
				t.Fatal("identical retry did not return the full original representation")
			}
		})
	}
}

type lostPromotionReplyConn struct {
	redis.ConnWithContext
	reserved int64
	identity string
	dropped  *atomic.Bool
}

func (c *lostPromotionReplyConn) Do(command string, args ...any) (any, error) {
	reply, err := c.ConnWithContext.Do(command, args...)
	// Drop the acknowledgement after Redis executed the promotion. The
	// operation field, reservation and identity distinguish it from admission.
	if err == nil && (command == "EVALSHA" || command == "EVAL") && len(args) == 10 &&
		args[8] == c.reserved && args[9] == c.identity && c.dropped.CompareAndSwap(false, true) {
		_ = c.ConnWithContext.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return reply, err
}

func TestLostGapPromotionReplyPreservesReservationAndIdenticalRetry(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, archive := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _, _ := u.ParseToken(token)
	fileKey := u.REDIS_PREFIX + "file_" + id
	// Keep the completed session inspectable without authorizing another view.
	if _, err := conn.Do("HSET", fileKey, "views", 2); err != nil {
		t.Fatal(err)
	}
	cookie, _, etag := interruptedSession(t, conn, e, token, 5)
	_ = interruptDownloadRange(t, e, cookie, "bytes=3-", etag, 7)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	absolute, err := redis.Int64(conn.Do("HGET", key, "absolute_deadline"))
	if err != nil {
		t.Fatal(err)
	}
	idle := time.Now().Add(25 * time.Second).UnixMilli()
	if _, err := conn.Do("HSET", key, "idle_deadline", idle); err != nil {
		t.Fatal(err)
	}
	const gap = "bytes=24-"
	identity := downloadSessionDigest(gap + "\x00" + etag)
	var dropped atomic.Bool
	if err := u.CloseRedisPool(); err != nil {
		t.Fatal(err)
	}
	pool := u.NewPool()
	dial := pool.DialContext
	pool.DialContext = func(ctx context.Context) (redis.Conn, error) {
		c, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return &lostPromotionReplyConn{c.(redis.ConnWithContext), int64(len(archive) - 24), identity, &dropped}, nil
	}
	t.Cleanup(func() { _ = u.CloseRedisPool() })

	first, requestErr := getResume(e, token, cookie, gap, etag)
	if !dropped.Load() || requestErr == nil || first.Code != http.StatusServiceUnavailable ||
		first.Header().Get("Content-Type") == "application/zip" || bytes.HasPrefix(first.Body.Bytes(), []byte("PK\x03\x04")) {
		t.Fatal("lost promotion acknowledgement did not stop the response before archive headers")
	}
	state, err := redis.StringMap(conn.Do("HGETALL", key))
	if err != nil || state["used"] != "7" || state["active"] != "0" || state["requests"] != "2" ||
		state["gap_retry_request"] != identity || state["gap_retry_after"] != "2" || state["restart_available"] != "0" ||
		state["idle_deadline"] != strconv.FormatInt(idle, 10) || state["absolute_deadline"] != strconv.FormatInt(absolute, 10) {
		t.Fatal("lost acknowledgement left the prior charges, retry or deadlines inconsistent")
	}
	second, err := getResume(e, token, cookie, gap, etag)
	if err != nil || second.Code != http.StatusOK || second.Header().Get("Content-Range") != "" ||
		second.Header().Get("ETag") != etag || !bytes.Equal(second.Body.Bytes(), archive) {
		t.Fatal("identical retry did not deliver the complete original ZIP")
	}
	state, err = redis.StringMap(conn.Do("HGETALL", key))
	if err != nil || state["used"] != strconv.Itoa(len(archive)) || state["requests"] != "3" ||
		state["active"] != "0" || state["complete"] != "1" || state["absolute_deadline"] != strconv.FormatInt(absolute, 10) {
		t.Fatal("completed replacement did not exhaust exactly one replacement allowance")
	}
	if views, err := redis.Int(conn.Do("HGET", fileKey, "views_count")); err != nil || views != 1 {
		t.Fatal("retry consumed another view")
	}
	if replay, err := getResume(e, token, cookie, gap, etag); err != nil || replay.Code != http.StatusNotFound || replay.Body.Len() != 0 {
		t.Fatal("completed replacement was replayable")
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
			if err := downloadRequest(e, denied, missingCookie); err != nil || denied.Code != http.StatusNotFound || denied.Body.Len() != 0 {
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
	prefix, etag := interruptAuthorizedGET(t, e, cookie, offset, 2500*time.Millisecond)
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
	if err := downloadRequest(e, rec, req); err == nil || rec.Code != http.StatusInternalServerError {
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
	if err := downloadRequest(e, retry, req); err != nil || retry.Code != http.StatusOK || !bytes.Equal(retry.Body.Bytes(), plain) {
		t.Fatalf("initial GET after archive recovery: status=%d err=%v", retry.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestDownloadCookiePathNormalizesEquivalentFileKeys(t *testing.T) {
	const id = "b6dd32ee-f79c-48b1-a20a-2132a8a76e45"
	key := bytes.Repeat([]byte{0xfb, 0xff}, 16)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	segment := "dl-" + id + "-" + encoded
	for _, value := range []string{base64.URLEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key)} {
		if downloadSharePath(id+u.TOKEN_SEPARATOR+value) != "/file/"+segment {
			t.Fatal("equivalent file keys selected different cookie paths")
		}
	}
	if downloadShareToken(segment) != id+u.TOKEN_SEPARATOR+encoded+"=" {
		t.Fatal("canonical segment did not resolve to its share key")
	}
	for _, malformed := range []string{"dl-", segment + "=", "dl-" + strings.ToUpper(id) + "-" + encoded, segment[:len(segment)-1] + "+"} {
		if downloadShareToken(malformed) != "" {
			t.Error("malformed dedicated segment was accepted")
		}
	}
}

func TestDownloadPathWithCustomTokenSeparator(t *testing.T) {
	previous := u.TOKEN_SEPARATOR
	t.Cleanup(func() { u.TOKEN_SEPARATOR = previous })
	const id = "b6dd32ee-f79c-48b1-a20a-2132a8a76e45"
	key := bytes.Repeat([]byte{0xff}, 32)
	encoded := base64.URLEncoding.EncodeToString(key)
	segment := "dl-" + id + "-" + strings.TrimSuffix(encoded, "=")
	for _, separator := range []string{"_", "__", "="} {
		u.TOKEN_SEPARATOR = separator
		source := id + separator + hex.EncodeToString(key)
		if downloadSharePath(source) != "/file/"+segment || downloadShareToken(segment) != id+separator+encoded {
			t.Errorf("could not recover canonical ZIP path with separator %q", separator)
		}
		if _, _, err := u.ParseToken(id + separator + "key" + separator + "extra"); err == nil {
			t.Errorf("invalid repeated separator %q accepted", separator)
		}
	}
}

func TestDownloadHexShareWithSeparatorInBase64Padding(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, archive := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, key, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	previous := u.TOKEN_SEPARATOR
	u.TOKEN_SEPARATOR = "="
	t.Cleanup(func() { u.TOKEN_SEPARATOR = previous })
	// The hex source has one separator. Its canonical key ends with another.
	rec, err := downloadCompatibilityFile(t, e, id+"="+hex.EncodeToString(raw), "")
	if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), archive) {
		t.Fatalf("authorized ZIP with custom separator: status=%d err=%v", rec.Code, err)
	}
}

func TestDedicatedZIPIssuedBeforeCanonicalPathsStillResumes(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	post, err := postDownload(t, e, token, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := authorizedDownload(t, token, post)
	cookie.Path = "/file/" + token + "/download/" + downloadSessionDigest(cookie.Value)
	prefix, etag := interruptAuthorizedGET(t, e, cookie, 11, 0)
	req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
	req.AddCookie(cookie)
	req.Header.Set("Range", "bytes=11-")
	req.Header.Set("If-Range", etag)
	rec := httptest.NewRecorder()
	if err := downloadRequest(e, rec, req); err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(append(prefix, rec.Body.Bytes()...), plain) {
		t.Fatalf("pre-upgrade ZIP failed to resume: status=%d error=%v", rec.Code, err)
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
	prefix, etag := interruptAuthorizedGET(t, e, cookie, prefixLen, 0)
	id, _, _ := u.ParseToken(token)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	t.Cleanup(func() { _, _ = conn.Do("DEL", key) })
	return cookie, prefix, etag
}

func interruptAuthorizedGET(t *testing.T, e *echo.Echo, cookie *http.Cookie, prefixLen int, delay time.Duration) ([]byte, string) {
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
		_ = downloadRequest(e, writer, req)
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
		err := downloadRequest(e, rec, req)
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
		_ = downloadRequest(e, writer, req)
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
	_ = downloadRequest(e, recorder, req)
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

func TestRejectedByteRangeReportsSizeOnlyToAuthenticatedSession(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "30")
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, _, etag := interruptedSession(t, conn, e, token, 11)
	id, _ := finalizationArchive(t, token)
	selector := downloadSessionDigest(cookie.Value)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + selector
	before, err := redis.StringMap(conn.Do("HGETALL", key))
	if err != nil || len(before) == 0 {
		t.Fatalf("session fields unavailable: %v", err)
	}
	expires, err := redis.Int64(conn.Do("PEXPIRETIME", key))
	if err != nil || expires <= 0 {
		t.Fatalf("resume deadline unavailable: %d, err=%v", expires, err)
	}
	invalidCookie := *cookie
	invalidCookie.Value = "invalid"
	archiveRange := "bytes */" + strconv.Itoa(len(plain))
	for _, tc := range []struct {
		name, rangeValue string
		cookie           *http.Cookie
		status           int
		contentRange     string
	}{
		{"malformed bytes", "Bytes=1-a", cookie, http.StatusRequestedRangeNotSatisfiable, archiveRange},
		{"multiple byte ranges", "bytes=1-2,4-5", cookie, http.StatusRequestedRangeNotSatisfiable, archiveRange},
		{"missing cookie", "bytes=1-2,4-5", nil, http.StatusNotFound, ""},
		{"invalid cookie", "bytes=1-2,4-5", &invalidCookie, http.StatusNotFound, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, downloadSessionPath(token, selector), nil)
			req.Header.Set("Range", tc.rangeValue)
			req.Header.Set("If-Range", etag)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			rec := httptest.NewRecorder()
			if err := downloadRequest(e, rec, req); err != nil || rec.Code != tc.status ||
				rec.Header().Get("Content-Range") != tc.contentRange || rec.Body.Len() != 0 {
				t.Fatalf("rejected range: status=%d range=%q bytes=%d err=%v", rec.Code, rec.Header().Get("Content-Range"), rec.Body.Len(), err)
			}
		})
	}
	after, err := redis.StringMap(conn.Do("HGETALL", key))
	if err != nil || !maps.Equal(before, after) {
		t.Fatalf("rejected range changed session fields: %v", err)
	}
	deadline, err := redis.Int64(conn.Do("PEXPIRETIME", key))
	if err != nil || deadline != expires {
		t.Fatalf("rejected range changed idle deadline from %d to %d, err=%v", expires, deadline, err)
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
