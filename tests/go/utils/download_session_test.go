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
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "")
	if got, err := downloadSessionSeconds(0); err != nil || got != 5*60 {
		t.Fatalf("default timeout: %d %v", got, err)
	}
	for _, tc := range []struct {
		size int64
		want int
	}{
		{1 << 30, 300 + 8192},
		{maxExactSessionBytes, 24 * 60 * 60},
	} {
		if got, err := downloadSessionSeconds(tc.size); err != nil || got != tc.want {
			t.Fatalf("size %d: got %d, error %v; want %d", tc.size, got, err, tc.want)
		}
	}
	for _, value := range []string{"garbage", "0", "-1s", "1ms"} {
		t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", value)
		if _, err := downloadSessionSeconds(0); err == nil {
			t.Fatalf("accepted invalid timeout %q", value)
		}
	}
	for _, tc := range []struct {
		value string
		want  int
	}{
		{"1s", 1},
		{"2m", 2 * 60},
		{"5m", 5 * 60},
		{"15m", 15 * 60},
		{"1h", 60 * 60},
		{"3h", 3 * 60 * 60},
		{"1000h", 24 * 60 * 60},
	} {
		t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", tc.value)
		if got, err := downloadSessionSeconds(0); err != nil || got != tc.want {
			t.Errorf("timeout %q: got %d, error %v; want %d", tc.value, got, err, tc.want)
		}
	}
}

func TestDownloadSessionLifetimeRespectsConfiguredDurationAndParent(t *testing.T) {
	admin := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "3h")
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

func TestInitialGETIsAtomicAndLeavesRangeBudgetUntouched(t *testing.T) {
	c := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "")
	link, httpErr := SetFile(archiveTestIdentity(t), 4*60*60, 1, false, false, "", ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	f := &models.File{FileKey: link}
	claim, httpErr := ClaimFileDownload(f)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	cookie, life, err := CreateClaimedDownloadSession(f, "test-secret", 1<<30, claim, `"`+strings.Repeat("1", 64)+`"`)
	if err != nil || life != 300+8192 {
		t.Fatalf("session creation: lifetime=%d error=%v", life, err)
	}
	id, _, _ := ParseToken(link)
	fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
	t.Cleanup(func() { _, _ = c.Do("DEL", fileKey, sessionKey) })
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
	if err := AbandonInitialDownload(winner); err != nil {
		t.Fatal(err)
	}
	_, retry, fault := StartTrackedFileDownload(f, cookie)
	if fault != nil {
		t.Fatal("Could not retry a GET rejected before response headers", fault)
	}
	if err := AbandonInitialDownload(winner); err != nil {
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
