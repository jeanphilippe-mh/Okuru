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
	link, httpErr := SetFile("fixture-password", 60, 1, true, false, "")
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
	if got, err := downloadSessionSeconds(); err != nil || got != 5*60 {
		t.Fatalf("default timeout: %d %v", got, err)
	}
	for _, value := range []string{"garbage", "0", "-1s", "1ms"} {
		t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", value)
		if _, err := downloadSessionSeconds(); err == nil {
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
		{"15m", 5 * 60},
		{"1h", 5 * 60},
		{"3h", 5 * 60},
		{"1000h", 5 * 60},
	} {
		t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", tc.value)
		if got, err := downloadSessionSeconds(); err != nil || got != tc.want {
			t.Errorf("timeout %q: got %d, error %v; want %d", tc.value, got, err, tc.want)
		}
	}
}

func TestNewDownloadSessionLifetimeRespectsFiveMinutesAndParent(t *testing.T) {
	admin := cleanupTest(t)
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "3h")
	for _, ttl := range []int{2 * 60 * 60, 2 * 60} {
		link, httpErr := SetFile("fixture-password", ttl, 1, true, false, "")
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
		if err != nil || sessionTTL <= 0 || sessionTTL > 5*60*1000 || sessionTTL > parentTTL || lifetime > min(ttl, 5*60) {
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
