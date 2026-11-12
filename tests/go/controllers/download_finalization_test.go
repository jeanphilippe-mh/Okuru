package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

func finalizationArchive(t *testing.T, token string) (string, string) {
	t.Helper()
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	return id, filepath.Join(u.FILEFOLDER, id+".zip")
}

func requireFinalizationRetained(t *testing.T, conn redis.Conn, token string) {
	t.Helper()
	id, path := finalizationArchive(t, token)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Archive was not retained: %v", err)
	}
	if exists, err := redis.Bool(conn.Do("EXISTS", u.REDIS_PREFIX+"file_"+id)); err != nil || !exists {
		t.Fatalf("File metadata was not retained: exists=%v error=%v", exists, err)
	}
}

func requireFinalizationRemoved(t *testing.T, conn redis.Conn, token string) {
	t.Helper()
	id, path := finalizationArchive(t, token)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, fileErr := os.Lstat(path)
		exists, redisErr := redis.Bool(conn.Do("EXISTS", u.REDIS_PREFIX+"file_"+id))
		sessions, sessionsErr := redis.Strings(conn.Do("KEYS", u.REDIS_PREFIX+"download_session_"+id+"_*"))
		if os.IsNotExist(fileErr) && redisErr == nil && !exists && sessionsErr == nil && len(sessions) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Final download retained archive or metadata: file=%v exists=%v redis=%v sessions=%d sessionError=%v", fileErr, exists, redisErr, len(sessions), sessionsErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFinalDownloadDeletesExhaustedArchive(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, tc := range []struct {
		name, format string
		protected    bool
	}{
		{"Historical ZIP", "", false},
		{"Historical password-protected age", u.ArchiveFormatAge, true},
		{"Current age", u.ArchiveFormatAgeX25519, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, token, password, expected := resumeFixture(t, conn, tc.format, tc.protected)
			rec, err := downloadCompatibilityFile(t, e, token, password)
			if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), expected) {
				t.Fatalf("Initial download: status=%d error=%v", rec.Code, err)
			}
			requireFinalizationRemoved(t, conn, token)
			if rec, _ := downloadCompatibilityFile(t, e, token, password); rec.Code != http.StatusNotFound {
				t.Fatalf("Consumed link remained accessible: %d", rec.Code)
			}
		})
	}
}

func TestSuccessfulDownloadPreservesRemainingView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _ := finalizationArchive(t, token)
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 2); err != nil {
		t.Fatal(err)
	}
	for view := 1; view <= 2; view++ {
		rec, err := downloadCompatibilityFile(t, e, token, password)
		if err != nil || rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), expected) {
			t.Fatalf("View %d: status=%d error=%v", view, rec.Code, err)
		}
		if view == 1 {
			requireFinalizationRetained(t, conn, token)
		} else {
			requireFinalizationRemoved(t, conn, token)
		}
	}
}

func TestInterruptedDownloadIsDeletedOnlyAfterCompleteResume(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, prefix, etag := interruptedSession(t, conn, e, token, 11)
	requireFinalizationRetained(t, conn, token)

	// A valid but incomplete Range cannot be considered a complete download.
	partial, err := getResume(e, token, cookie, "bytes=11-13", etag)
	if err != nil || partial.Code != http.StatusPartialContent || !bytes.Equal(partial.Body.Bytes(), expected[11:14]) {
		t.Fatalf("Partial resume: status=%d error=%v", partial.Code, err)
	}
	requireFinalizationRetained(t, conn, token)

	remaining, err := getResume(e, token, cookie, "bytes=14-", etag)
	if err != nil || remaining.Code != http.StatusPartialContent {
		t.Fatalf("Final resume: status=%d error=%v", remaining.Code, err)
	}
	joined := append(bytes.Clone(prefix), partial.Body.Bytes()...)
	joined = append(joined, remaining.Body.Bytes()...)
	if !bytes.Equal(joined, expected) {
		t.Fatal("Interrupted download and resumed ranges did not reconstruct the ZIP")
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestOutOfOrderRangesDoNotFinalizeUntilGapIsFilled(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, prefix, etag := interruptedSession(t, conn, e, token, 11)
	tail, err := getResume(e, token, cookie, "bytes=14-", etag)
	if err != nil || tail.Code != http.StatusPartialContent || !bytes.Equal(tail.Body.Bytes(), expected[14:]) {
		t.Fatalf("Out-of-order tail: status=%d error=%v", tail.Code, err)
	}
	requireFinalizationRetained(t, conn, token)
	gap, err := getResume(e, token, cookie, "bytes=11-13", etag)
	if err != nil || gap.Code != http.StatusPartialContent || !bytes.Equal(gap.Body.Bytes(), expected[11:14]) {
		t.Fatalf("Missing range: status=%d error=%v", gap.Code, err)
	}
	joined := append(bytes.Clone(prefix), gap.Body.Bytes()...)
	joined = append(joined, tail.Body.Bytes()...)
	if !bytes.Equal(joined, expected) {
		t.Fatal("Out-of-order resumed ranges did not reconstruct the ZIP")
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestOverlappingRangesDoNotCountDuplicateBytesAsCompletion(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, _, etag := interruptedSession(t, conn, e, token, 11)
	if len(expected) < 23 {
		t.Fatal("Fixture is too small for overlap coverage")
	}
	for i := 0; i < 2; i++ {
		rec, err := getResume(e, token, cookie, "bytes=11-20", etag)
		if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected[11:21]) {
			t.Fatalf("Overlapping range %d: status=%d error=%v", i, rec.Code, err)
		}
	}
	tail := "bytes=21-" + strconv.Itoa(len(expected)-2)
	rec, err := getResume(e, token, cookie, tail, etag)
	if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected[21:len(expected)-1]) {
		t.Fatalf("Incomplete tail: status=%d error=%v", rec.Code, err)
	}
	// The transmitted byte count exceeds the ZIP size, but its last byte has
	// never been sent: summing byte counts would delete the file too early.
	requireFinalizationRetained(t, conn, token)
	last := "bytes=" + strconv.Itoa(len(expected)-1) + "-"
	rec, err = getResume(e, token, cookie, last, etag)
	if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected[len(expected)-1:]) {
		t.Fatalf("Final byte: status=%d error=%v", rec.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestInvalidRangeDoesNotPreventLaterCompleteResume(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	cookie, prefix, etag := interruptedSession(t, conn, e, token, 11)
	invalid := "bytes=" + strconv.Itoa(len(expected)) + "-"
	rec, _ := getResume(e, token, cookie, invalid, etag)
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("Invalid range status: %d", rec.Code)
	}
	requireFinalizationRetained(t, conn, token)
	rec, err := getResume(e, token, cookie, "bytes=11-", etag)
	if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(prefix), rec.Body.Bytes()...), expected) {
		t.Fatalf("Valid retry after invalid range: status=%d error=%v", rec.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestFailedWriteDoesNotFinalizeEvenIfAllBytesWereAccepted(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, tc := range []struct{ name, format string }{
		{"Current age", u.ArchiveFormatAgeX25519},
		{"Historical ZIP", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, token, _, expected := resumeFixture(t, conn, tc.format, false)
			recorder := httptest.NewRecorder()
			writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: len(expected)}
			ctx := e.NewContext(httptest.NewRequest(http.MethodPost, "/file/"+token, nil), writer)
			ctx.SetParamNames("file_key")
			ctx.SetParamValues(token)
			func() {
				defer func() {
					if value := recover(); value != nil && value != http.ErrAbortHandler {
						t.Errorf("Unexpected panic after response write error: %v", value)
					}
				}()
				_ = DownloadFile(ctx)
			}()
			if !bytes.Equal(recorder.Body.Bytes(), expected) {
				t.Fatal("Expected the writer to accept all bytes before returning an error")
			}
			var cookie *http.Cookie
			for _, item := range recorder.Result().Cookies() {
				name, err := downloadSessionCookie(token, item.Value)
				if err == nil && name == item.Name {
					cookie = item
				}
			}
			if cookie == nil {
				t.Fatal("Failed response did not retain a continuation cookie")
			}
			id, _ := finalizationArchive(t, token)
			digest := sha256.Sum256([]byte(cookie.Value))
			sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
			t.Cleanup(func() { _, _ = conn.Do("DEL", sessionKey) })
			requireFinalizationRetained(t, conn, token)
			rec, err := getResume(e, token, cookie, "bytes=0-0", recorder.Header().Get("ETag"))
			if err != nil || rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), expected[:1]) {
				t.Fatalf("One-byte retry: status=%d error=%v", rec.Code, err)
			}
			// A failed response cannot establish complete coverage, even if the
			// writer reported n == len(p); retrying one byte is insufficient.
			requireFinalizationRetained(t, conn, token)
		})
	}
}

func interruptedHistoricalSession(t *testing.T, conn redis.Conn, e *echo.Echo, token string) (*http.Cookie, []byte, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	writer := &interruptedResponseWriter{ResponseRecorder: recorder, remaining: 11}
	ctx := e.NewContext(httptest.NewRequest(http.MethodPost, "/file/"+token, nil), writer)
	ctx.SetParamNames("file_key")
	ctx.SetParamValues(token)
	func() {
		defer func() {
			if value := recover(); value != nil && value != http.ErrAbortHandler {
				t.Errorf("Unexpected panic after interrupted response: %v", value)
			}
		}()
		_ = DownloadFile(ctx)
	}()
	if recorder.Body.Len() != 11 {
		t.Fatalf("Expected an interrupted initial response, got %d bytes", recorder.Body.Len())
	}
	var cookie *http.Cookie
	for _, item := range recorder.Result().Cookies() {
		name, err := downloadSessionCookie(token, item.Value)
		if err == nil && name == item.Name {
			cookie = item
		}
	}
	if cookie == nil {
		t.Fatal("Interrupted legacy response did not retain a continuation cookie")
	}
	id, _ := finalizationArchive(t, token)
	digest := sha256.Sum256([]byte(cookie.Value))
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
	t.Cleanup(func() { _, _ = conn.Do("DEL", sessionKey) })
	return cookie, bytes.Clone(recorder.Body.Bytes()), recorder.Header().Get("ETag")
}

func TestInterruptedHistoricalZIPRemainsResumable(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, "", false)
	cookie, prefix, etag := interruptedHistoricalSession(t, conn, e, token)
	requireFinalizationRetained(t, conn, token)
	tail, err := getResume(e, token, cookie, "bytes=11-", etag)
	if err != nil || tail.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(prefix), tail.Body.Bytes()...), expected) {
		t.Fatalf("Historical ZIP resume: status=%d error=%v", tail.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

func TestChangedHistoricalArchiveDoesNotCombineResumeCoverage(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, withValidator := range []bool{false, true} {
		name := "Without If-Range"
		if withValidator {
			name = "With stale If-Range"
		}
		t.Run(name, func(t *testing.T) {
			e, token, _, original := resumeFixture(t, conn, "", false)
			cookie, prefix, etag := interruptedHistoricalSession(t, conn, e, token)
			if !bytes.Equal(prefix, original[:11]) {
				t.Fatal("Initial partial response differs from the original archive")
			}
			_, path := finalizationArchive(t, token)
			changed := bytes.Clone(original)
			changed[len(changed)/2] ^= 1
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			validator := ""
			if withValidator {
				validator = etag
			}
			rec, _ := getResume(e, token, cookie, "bytes=11-", validator)
			switch rec.Code {
			case http.StatusPartialContent:
				if withValidator || !bytes.Equal(rec.Body.Bytes(), changed[11:]) {
					t.Fatalf("Unexpected partial response for changed archive: status=%d", rec.Code)
				}
				// Old prefix plus new tail must not count as one complete copy.
				requireFinalizationRetained(t, conn, token)
			case http.StatusOK:
				if !bytes.Equal(rec.Body.Bytes(), changed) {
					t.Fatal("Full replacement response did not contain the new archive")
				}
			case http.StatusNotFound, http.StatusPreconditionFailed:
				requireFinalizationRetained(t, conn, token)
			default:
				t.Fatalf("Unexpected changed-archive response: %d", rec.Code)
			}
		})
	}
}

func TestRejectedPasswordDoesNotFinalizeArchive(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAge, true)
	rec, _ := downloadCompatibilityFile(t, e, token, "incorrect password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Wrong password: status=%d", rec.Code)
	}
	requireFinalizationRetained(t, conn, token)
}

func TestProtectedArchiveCompletionHandlesAssociatedPasswordRecord(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	for _, mode := range []string{"present", "already expired", "invalid association"} {
		t.Run(mode, func(t *testing.T) {
			const password = "synthetic archive password 723680"
			e, renderer := createCompatibilityUpload(t, password)
			file := renderer.data["f"].(*models.File)
			token := tokenFromCompatibilityLink(t, file.Link, "/file/")
			id, _ := finalizationArchive(t, token)
			passwordLink, ok := renderer.data["passwordLink"].(string)
			if !ok || passwordLink == "" {
				t.Fatal("Separate password link missing")
			}
			passwordToken := tokenFromCompatibilityLink(t, passwordLink, "/")
			passwordID, _, err := u.ParseToken(passwordToken)
			if err != nil {
				t.Fatal(err)
			}
			fileKey, passwordKey := u.REDIS_PREFIX+"file_"+id, u.REDIS_PREFIX+passwordID
			t.Cleanup(func() { _, _ = conn.Do("DEL", fileKey, passwordKey) })
			if _, err := conn.Do("HSET", fileKey, "views", 1); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "already expired":
				if _, err := conn.Do("DEL", passwordKey); err != nil {
					t.Fatal(err)
				}
			case "invalid association":
				if _, err := conn.Do("HSET", fileKey, "provided_key", "not-a-canonical-uuid"); err != nil {
					t.Fatal(err)
				}
			}
			rec, err := downloadCompatibilityFile(t, e, token, password)
			if err != nil || rec.Code != http.StatusOK {
				t.Fatalf("Protected download: status=%d error=%v", rec.Code, err)
			}
			assertCompatibilityZIP(t, rec.Body.Bytes())
			if mode == "invalid association" {
				requireFinalizationRetained(t, conn, token)
				if exists, err := redis.Bool(conn.Do("EXISTS", passwordKey)); err != nil || !exists {
					t.Fatalf("Unrelated password record was lost: exists=%v error=%v", exists, err)
				}
				return
			}
			requireFinalizationRemoved(t, conn, token)
			if exists, err := redis.Bool(conn.Do("EXISTS", passwordKey)); err != nil || exists {
				t.Fatalf("Associated password record retained: exists=%v error=%v", exists, err)
			}
		})
	}
}

func TestLegacyResumeSessionIsRejectedWithoutDeletingArchive(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, password, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _ := finalizationArchive(t, token)
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 2); err != nil {
		t.Fatal(err)
	}
	cookie, _, etag := interruptedSession(t, conn, e, token, 11)
	digest := sha256.Sum256([]byte(cookie.Value))
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
	version, err := redis.String(conn.Do("HGET", sessionKey, "session_version"))
	if err != nil || version != "2" {
		t.Fatalf("New session version: value=%q error=%v", version, err)
	}
	// Historical sessions and parents predate both the session marker and
	// tracked-view counter. Their prior delivery progress is unknowable.
	if _, err := conn.Do("HDEL", sessionKey, "session_version", "tracking", "active", "intervals", "complete"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Do("HDEL", u.REDIS_PREFIX+"file_"+id, "tracked_views"); err != nil {
		t.Fatal(err)
	}
	if rec, _ := getResume(e, token, cookie, "bytes=11-", etag); rec.Code != http.StatusNotFound {
		t.Fatalf("Legacy session remained resumable: status=%d", rec.Code)
	}
	requireFinalizationRetained(t, conn, token)
	second, err := downloadCompatibilityFile(t, e, token, password)
	if err != nil || second.Code != http.StatusOK || !bytes.Equal(second.Body.Bytes(), expected) {
		t.Fatalf("Remaining view with existing link: status=%d error=%v", second.Code, err)
	}
	// A pre-upgrade reservation cannot be proven complete. The remaining
	// view works, but early deletion must fail closed until the parent TTL.
	requireFinalizationRetained(t, conn, token)
}

func TestCompletingOneSessionDoesNotBreakAnotherAuthorizedResume(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _ := finalizationArchive(t, token)
	if _, err := conn.Do("HSET", u.REDIS_PREFIX+"file_"+id, "views", 2); err != nil {
		t.Fatal(err)
	}
	first, prefix1, etag1 := interruptedSession(t, conn, e, token, 11)
	second, prefix2, etag2 := interruptedSession(t, conn, e, token, 17)
	firstTail, err := getResume(e, token, first, "bytes=11-", etag1)
	if err != nil || firstTail.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(prefix1), firstTail.Body.Bytes()...), expected) {
		t.Fatalf("First resume: status=%d error=%v", firstTail.Code, err)
	}
	requireFinalizationRetained(t, conn, token)
	secondTail, err := getResume(e, token, second, "bytes=17-", etag2)
	if err != nil || secondTail.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(prefix2), secondTail.Body.Bytes()...), expected) {
		t.Fatalf("Second resume: status=%d error=%v", secondTail.Code, err)
	}
	requireFinalizationRemoved(t, conn, token)
}

type gatedFinalizationWriter struct {
	*httptest.ResponseRecorder
	waiting chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedFinalizationWriter) Write(data []byte) (int, error) {
	w.once.Do(func() {
		close(w.waiting)
		<-w.release
	})
	return w.ResponseRecorder.Write(data)
}

func TestExpiredSessionKeyDoesNotDeleteArchiveWhileAnotherResponseIsActive(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, expected := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _ := finalizationArchive(t, token)
	fileKey := u.REDIS_PREFIX + "file_" + id
	if _, err := conn.Do("HSET", fileKey, "views", 2); err != nil {
		t.Fatal(err)
	}
	first, prefix, etag := interruptedSession(t, conn, e, token, 11)
	recorder := httptest.NewRecorder()
	writer := &gatedFinalizationWriter{ResponseRecorder: recorder, waiting: make(chan struct{}), release: make(chan struct{})}
	ctx := e.NewContext(httptest.NewRequest(http.MethodPost, "/file/"+token, nil), writer)
	ctx.SetParamNames("file_key")
	ctx.SetParamValues(token)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer func() {
			if value := recover(); value != nil {
				done <- errors.New("Active response panicked")
			}
		}()
		done <- DownloadFile(ctx)
	}()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.release) }) }
	t.Cleanup(func() {
		release()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("Active response did not stop")
		}
	})
	select {
	case <-writer.waiting:
	case err := <-done:
		t.Fatalf("Second download ended before streaming: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Second download did not begin streaming")
	}
	var second *http.Cookie
	for _, item := range recorder.Result().Cookies() {
		name, err := downloadSessionCookie(token, item.Value)
		if err == nil && name == item.Name {
			second = item
		}
	}
	if second == nil {
		t.Fatal("Active second response did not create a continuation session")
	}
	digest := sha256.Sum256([]byte(second.Value))
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
	if _, err := conn.Do("PEXPIRE", sessionKey, 20); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		exists, err := redis.Bool(conn.Do("EXISTS", sessionKey))
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Second session did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	firstTail, err := getResume(e, token, first, "bytes=11-", etag)
	if err != nil || firstTail.Code != http.StatusPartialContent || !bytes.Equal(append(bytes.Clone(prefix), firstTail.Body.Bytes()...), expected) {
		t.Fatalf("First session completion: status=%d error=%v", firstTail.Code, err)
	}
	requireFinalizationRetained(t, conn, token)
	release()
	select {
	case err := <-done:
		if err != nil || recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), expected) {
			t.Fatalf("Active response did not finish: status=%d error=%v", recorder.Code, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Active response did not finish after release")
	}
	// The parent remains valid and records the in-flight operation, so the
	// successful full second response can establish completion even after
	// its continuation-session key expired.
	requireFinalizationRemoved(t, conn, token)
}

func TestClaimedDownloadSessionRespectsFiveMinutesAndParentTTL(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "12h")
	for _, tc := range []struct {
		name        string
		parentTTLms int64
	}{
		{"Long parent TTL", 30 * 60 * 1000},
		{"Short parent TTL", 20 * 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
			id, _ := finalizationArchive(t, token)
			fileKey := u.REDIS_PREFIX + "file_" + id
			if changed, err := redis.Int(conn.Do("PEXPIRE", fileKey, tc.parentTTLms)); err != nil || changed != 1 {
				t.Fatalf("Set parent TTL: changed=%d error=%v", changed, err)
			}
			// The HTTP download path creates a claimed session and aborts after
			// the first 11 bytes, leaving the session available for inspection.
			cookie, _, _ := interruptedSession(t, conn, e, token, 11)
			digest := sha256.Sum256([]byte(cookie.Value))
			sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + hex.EncodeToString(digest[:])
			parentTTL, err := redis.Int64(conn.Do("PTTL", fileKey))
			if err != nil || parentTTL <= 0 {
				t.Fatalf("Parent TTL: %d ms, error=%v", parentTTL, err)
			}
			sessionTTL, err := redis.Int64(conn.Do("PTTL", sessionKey))
			if err != nil || sessionTTL <= 0 {
				t.Fatalf("Session TTL: %d ms, error=%v", sessionTTL, err)
			}
			if sessionTTL > 5*60*1000 || sessionTTL > parentTTL {
				t.Fatalf("Session TTL %d ms exceeds five minutes or parent TTL %d ms", sessionTTL, parentTTL)
			}
		})
	}
}
