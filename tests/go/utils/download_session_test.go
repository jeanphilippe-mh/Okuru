package utils

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
)

func downloadSessionFixture(t *testing.T) (redis.Conn, string, *models.File, string) {
	t.Helper()
	admin := cleanupTest(t)
	link, httpErr := SetFile(archiveTestIdentity(t), 60, 1, true, false, "", ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	id, _, err := ParseToken(link)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Do("DEL", REDIS_PREFIX+"file_"+id) })
	file := &models.File{FileKey: link}
	if err := GetFile(file); err != nil {
		t.Fatal(err)
	}
	cookie, _, err := CreateDownloadSession(file, "session fixture secret", 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Do("DEL", downloadSessionKey(id, cookie)) })
	return admin, id, file, cookie
}

func TestDownloadSessionIsEncryptedAndRateBounded(t *testing.T) {
	admin, id, file, cookie := downloadSessionFixture(t)
	key := downloadSessionKey(id, cookie)
	ciphertext, err := redis.Bytes(admin.Do("HGET", key, "secret"))
	if err != nil || bytes.Contains(ciphertext, []byte("session fixture secret")) || bytes.Contains(ciphertext, []byte(cookie)) {
		t.Fatal("download session exposes secret or cookie")
	}
	for i := 0; i < maxDownloadSessionRequests; i++ {
		if _, _, err := ResumeFileDownload(&models.File{FileKey: file.FileKey}, cookie); err != nil {
			t.Fatalf("request %d refused", i)
		}
	}
	if _, _, err := ResumeFileDownload(&models.File{FileKey: file.FileKey}, cookie); err == nil {
		t.Fatal("session accepted more than the bounded number of attempts")
	}
}

func TestDownloadSessionDeletedAtomicallyWithFileAndACLFailure(t *testing.T) {
	admin, id, file, cookie := downloadSessionFixture(t)
	fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
	path := cleanupArchive(t, id)
	username := "okuru_session_acl_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Do("ACL", "SETUSER", username, "on", ">temporary-test-password", "~"+fileKey, "+@all"); err != nil {
		t.Fatal(err)
	}
	defer admin.Do("ACL", "DELUSER", username)
	originalDial := redisDialContext
	defer func() { CloseRedisPool(); redisDialContext = originalDial }()
	CloseRedisPool()
	redisDialContext = func(ctx context.Context, network, address string, options ...redis.DialOption) (redis.Conn, error) {
		options = append(options, redis.DialUsername(username), redis.DialPassword("temporary-test-password"))
		return redis.DialContext(ctx, network, address, options...)
	}
	if err := RemoveFile(&models.File{FileKey: file.FileKey}); err == nil {
		t.Fatal("ACL denial accepted")
	}
	for _, key := range []string{fileKey, sessionKey} {
		if n, err := redis.Int(admin.Do("EXISTS", key)); err != nil || n != 1 {
			t.Fatalf("record lost on ACL failure: %d %v", n, err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("archive lost on ACL failure")
	}
	CloseRedisPool()
	redisDialContext = originalDial
	if err := RemoveFile(&models.File{FileKey: file.FileKey}); err != nil {
		t.Fatal("authorized removal failed")
	}
	for _, key := range []string{fileKey, sessionKey} {
		if n, err := redis.Int(admin.Do("EXISTS", key)); err != nil || n != 0 {
			t.Fatalf("record remained after deletion: %d %v", n, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("archive remained after deletion")
	}
}

func TestDownloadSessionTimeoutValidation(t *testing.T) {
	for _, tc := range []struct {
		name, session, resume   string
		wantSession, wantResume int
	}{
		{"defaults", "", "", 900, 300},
		{"only session configured", "17", "", 17, 300},
		{"only resume configured", "", "23", 900, 23},
		{"existing operator duration", "2h", "23", 7200, 23},
		{"separate windows", "2", "29", 2, 29},
		{"operational bounds", "1", "86401", 1, 86400},
		{"maximum unsigned integer", "18446744073709551615", "18446744073709551615", 86400, 86400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", tc.session)
			t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", tc.resume)
			session, resume, err := downloadTimeouts()
			if err != nil || session != tc.wantSession || resume != tc.wantResume {
				t.Fatalf("windows = (%d, %d, %v), want (%d, %d)", session, resume, err, tc.wantSession, tc.wantResume)
			}
		})
	}
	for _, key := range []string{"OKURU_DOWNLOAD_SESSION_TIMEOUT", "OKURU_DOWNLOAD_RESUME_TIMEOUT"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "300")
			t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "300")
			invalid := []string{"0", "-1", "1.25", "abc", "99999999999999999999999"}
			if key == "OKURU_DOWNLOAD_RESUME_TIMEOUT" {
				invalid = append(invalid, "5m")
			}
			for _, value := range invalid {
				t.Setenv(key, value)
				if err := ValidateDownloadTimeouts(); err == nil {
					t.Errorf("%s accepted invalid seconds %q", key, value)
				}
			}
		})
	}
}

func TestLegacyRangeSessionLifetimeRespectsResumeWindowAndParent(t *testing.T) {
	admin := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "86400")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "10800")
	for _, ttl := range []int{4 * 60 * 60, 2 * 60} {
		link, httpErr := SetFile(archiveTestIdentity(t), ttl, 1, true, false, "", ArchiveFormatAgeX25519)
		if httpErr != nil {
			t.Fatal(httpErr)
		}
		id, _, err := ParseToken(link)
		if err != nil {
			t.Fatal(err)
		}
		file := &models.File{FileKey: link}
		if err := GetFile(file); err != nil {
			t.Fatal(err)
		}
		cookie, lifetime, err := CreateDownloadSession(file, "fixture-secret", 100)
		if err != nil {
			t.Fatal(err)
		}
		fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
		t.Cleanup(func() { _, _ = admin.Do("DEL", fileKey, sessionKey) })
		parentTTL, err := redis.Int64(admin.Do("PTTL", fileKey))
		if err != nil {
			t.Fatal(err)
		}
		sessionTTL, err := redis.Int64(admin.Do("PTTL", sessionKey))
		wantSeconds := min(ttl, 3*60*60)
		if err != nil || sessionTTL > int64(wantSeconds)*1000 || sessionTTL > parentTTL || lifetime < wantSeconds-2 || lifetime > wantSeconds {
			t.Fatalf("parent TTL=%dms, session TTL=%dms, lifetime=%ds, error=%v", parentTTL, sessionTTL, lifetime, err)
		}
	}
}

func TestLegacyDownloadSessionIsRevokedWithoutDeletingShare(t *testing.T) {
	admin, id, file, cookie := downloadSessionFixture(t)
	fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
	archive := cleanupArchive(t, id)
	// Legacy records have neither a version nor a trustworthy creation time.
	if _, err := admin.Do("HDEL", sessionKey, "session_version"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Do("EXPIRE", fileKey, 3*60*60); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Do("EXPIRE", sessionKey, 2*60*60); err != nil {
		t.Fatal(err)
	}
	if _, _, httpErr := ResumeFileDownload(&models.File{FileKey: file.FileKey}, cookie); httpErr == nil {
		t.Fatal("A legacy download session was unexpectedly accepted")
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("The legacy session check removed the archive: %v", err)
	}
	if httpErr := GetFile(&models.File{FileKey: file.FileKey}); httpErr != nil {
		t.Fatalf("The legacy session check invalidated the still-usable share: %v", httpErr)
	}
}

// A 1 GiB ZIP exercises timing for a long transfer without allocating the payload.
func claimLargeDownload(t *testing.T, parentSeconds int) (*models.File, string, string, int) {
	t.Helper()
	link, httpErr := SetFile(archiveTestIdentity(t), parentSeconds, 1, false, false, "", ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	f := &models.File{FileKey: link}
	claim, httpErr := ClaimFileDownload(f)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	cookie, cookieLifetime, err := CreateClaimedDownloadSession(f, "test-secret", 1<<30, claim, `"`+strings.Repeat("1", 64)+`"`)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := ParseToken(link)
	if err != nil {
		t.Fatal(err)
	}
	return f, cookie, downloadSessionKey(id, cookie), cookieLifetime
}

func TestInitialGETIsAtomicAndLeavesRangeBudgetUntouched(t *testing.T) {
	c := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "300")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "300")
	f, cookie, sessionKey, _ := claimLargeDownload(t, 4*60*60)
	link := f.FileKey
	id, _, _ := ParseToken(link)
	fileKey := REDIS_PREFIX + "file_" + id
	if _, _, fault := ResumeStartedFileDownload(f, cookie); fault == nil {
		t.Fatal("Accepted Range before the initial GET")
	}
	if _, _, fault := ResumeTrackedFileDownload(f, cookie); fault == nil {
		t.Fatal("Accepted a new session on the legacy continuation endpoint")
	}
	fields, err := redis.StringMap(c.Do("HGETALL", fileKey))
	if err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		if strings.HasPrefix(name, "pending_") || strings.HasPrefix(name, "operation_") {
			t.Fatal("Idle session marked as an in-flight response")
		}
	}

	const contenders = 8
	results := make(chan *DownloadSession, contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			_, session, _ := StartTrackedFileDownload(&models.File{FileKey: link}, cookie)
			results <- session
		}()
	}
	var winner *DownloadSession
	for i := 0; i < contenders; i++ {
		if s := <-results; s != nil {
			if winner != nil {
				t.Fatal("Two concurrent initial GETs admitted")
			}
			winner = s
		}
	}
	if winner == nil {
		t.Fatal("Initial GET was not admitted")
	}
	state, err := redis.StringMap(c.Do("HGETALL", sessionKey))
	if err != nil || state["requests"] != "0" || state["used"] != "0" || state["active"] != "1" {
		t.Fatalf("initial GET: requests=%s used=%s active=%s err=%v", state["requests"], state["used"], state["active"], err)
	}
	if err := AbandonDownloadPreparation(winner); err != nil {
		t.Fatal(err)
	}
	_, retry, fault := StartTrackedFileDownload(f, cookie)
	if fault != nil {
		t.Fatal("Could not retry a GET rejected before response headers", fault)
	}
	if err := AbandonDownloadPreparation(winner); err != nil {
		t.Fatal(err)
	}
	if _, _, fault := StartTrackedFileDownload(f, cookie); fault == nil {
		t.Fatal("Stale rollback released the current initial GET")
	}
	if err := RecordDownloadProgress(retry, 0, 64, true, false); err != nil {
		t.Fatal(err)
	}
	_, resumed, httpErr := ResumeStartedFileDownload(f, cookie)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	if err := RecordDownloadProgress(resumed, 64, 1, true, true); err != nil {
		t.Fatal(err)
	}
	if count, err := redis.Int(c.Do("HGET", fileKey, "views_count")); count != 1 || err != nil {
		t.Fatalf("After initial GET and Range: views=%d error=%v", count, err)
	}
}

func sessionExpiryMillis(t *testing.T, c redis.Conn, key string) int64 {
	t.Helper()
	expiry, err := redis.Int64(c.Do("PEXPIRETIME", key))
	if err != nil || expiry <= 0 {
		t.Fatalf("expected an expiring download record, got %d: %v", expiry, err)
	}
	return expiry
}

func TestDownloadSessionHasAbsoluteAndIdleDeadlines(t *testing.T) {
	c := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "64")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "37")
	f, cookie, key, cookieLifetime := claimLargeDownload(t, 90)

	startTTL, err := redis.Int64(c.Do("PTTL", key))
	if err != nil || startTTL < 63000 || startTTL > 64000 || cookieLifetime < 63 || cookieLifetime > 64 {
		t.Fatalf("pending 1 GiB download: Redis %dms, cookie %ds, error %v", startTTL, cookieLifetime, err)
	}
	startExpiry := sessionExpiryMillis(t, c, key)
	_, initial, failure := StartTrackedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if err := AbandonDownloadPreparation(initial); err != nil {
		t.Fatal(err)
	}
	if retryExpiry := sessionExpiryMillis(t, c, key); retryExpiry > startExpiry+2 || retryExpiry < startExpiry-2 {
		t.Fatalf("rejected preparation moved initial deadline by %dms", retryExpiry-startExpiry)
	}
	_, initial, failure = StartTrackedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if expiry := sessionExpiryMillis(t, c, key); expiry > startExpiry+2 {
		t.Fatal("starting the ZIP extended the absolute session deadline")
	}
	if err := RecordDownloadProgress(initial, 0, 1024, true, false); err != nil {
		t.Fatal(err)
	}
	resumeTTL, err := redis.Int64(c.Do("PTTL", key))
	if err != nil || resumeTTL < 36000 || resumeTTL > 37000 {
		t.Fatalf("after interruption: Redis TTL %dms, error %v", resumeTTL, err)
	}
	// A new process reads the same Redis state. It must honor the window
	// captured at POST even if the operator has changed the environment.
	CloseRedisPool()
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "1")
	_, resumed, failure := ResumeStartedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if err := RecordDownloadProgress(resumed, 1024, 512, true, false); err != nil {
		t.Fatal(err)
	}
	resumeTTL, err = redis.Int64(c.Do("PTTL", key))
	if err != nil || resumeTTL < 36000 || resumeTTL > 37000 {
		t.Fatalf("existing session lost its resume policy: TTL %dms, error %v", resumeTTL, err)
	}

}

func TestRunningDownloadRenewsItsLeaseAndStopsAfterInterruption(t *testing.T) {
	c := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "30")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "1")
	f, cookie, key, _ := claimLargeDownload(t, 60)
	_, initial, failure := StartTrackedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if err := initial.MarkDownloadStreaming(); err != nil {
		t.Fatal(err)
	}
	firstExpiry := sessionExpiryMillis(t, c, key)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := KeepDownloadSessionAlive(ctx, initial)
	// At least one renewal must have occurred beyond the originally allotted
	// second. A one-shot extension at GET is insufficient for a long transfer.
	cleanupEventually(t, func() bool {
		expiry, err := redis.Int64(c.Do("PEXPIRETIME", key))
		return err == nil && expiry > firstExpiry+1000
	})
	stop()
	if err := RecordDownloadProgress(initial, 0, 1024, true, false); err != nil {
		t.Fatal(err)
	}
	// With no writer left this session now expires by itself, although its
	// parent share has nearly a minute left.
	cleanupEventually(t, func() bool {
		exists, err := redis.Int(c.Do("EXISTS", key))
		return err == nil && exists == 0
	})
	if _, _, failure := ResumeStartedFileDownload(f, cookie); failure == nil {
		t.Fatal("accepted a resume after the inactivity window")
	}
	if exists, err := redis.Int(c.Do("EXISTS", initial.fileKey)); exists != 1 || err != nil {
		t.Fatalf("session expiry removed its share: %d %v", exists, err)
	}
}

func TestAbsoluteSessionExpiryPreventsResumingALongRunningZIP(t *testing.T) {
	c := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "2")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "9")
	f, cookie, key, lifetime := claimLargeDownload(t, 60)
	if lifetime != 2 {
		t.Fatalf("cookie lifetime %ds exceeds the two-second session or expires too early", lifetime)
	}
	deadline := sessionExpiryMillis(t, c, key)
	_, initial, failure := StartTrackedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if err := initial.MarkDownloadStreaming(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := KeepDownloadSessionAlive(ctx, initial)
	defer stop()
	if current := sessionExpiryMillis(t, c, key); current > deadline+2 {
		t.Fatal("streaming extended the absolute session deadline")
	}
	cleanupEventually(t, func() bool {
		exists, err := redis.Int(c.Do("EXISTS", key))
		return err == nil && exists == 0
	})
	if _, _, failure := ResumeStartedFileDownload(f, cookie); failure == nil {
		t.Fatal("the running ZIP accepted another request beyond its absolute deadline")
	}
	if err := RecordDownloadProgress(initial, 0, 1024, true, false); err != nil {
		t.Fatal(err)
	}
	if exists, err := redis.Int(c.Do("EXISTS", key)); exists != 0 || err != nil {
		t.Fatalf("finishing a response resurrected its expired session: %d, %v", exists, err)
	}
}

func TestAlreadyIssuedDedicatedDownloadKeepsItsOriginalDeadline(t *testing.T) {
	c := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "60")
	t.Setenv("OKURU_DOWNLOAD_RESUME_TIMEOUT", "300")
	f, cookie, key, _ := claimLargeDownload(t, 600)
	// A dedicated session issued before separate timers had no resume_seconds
	// field, and the browser already has its original fixed-lifetime cookie.
	if _, err := c.Do("HDEL", key, "resume_seconds"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("HSET", key, "session_version", "3"); err != nil {
		t.Fatal(err)
	}
	deadline := sessionExpiryMillis(t, c, key)
	_, initial, failure := StartTrackedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if err := RecordDownloadProgress(initial, 0, 1024, true, false); err != nil {
		t.Fatal(err)
	}
	_, resumed, failure := ResumeStartedFileDownload(f, cookie)
	if failure != nil {
		t.Fatal(failure)
	}
	if err := RecordDownloadProgress(resumed, 1024, 512, true, false); err != nil {
		t.Fatal(err)
	}
	if got := sessionExpiryMillis(t, c, key); got != deadline {
		t.Fatalf("existing session deadline changed by %dms", got-deadline)
	}
}
