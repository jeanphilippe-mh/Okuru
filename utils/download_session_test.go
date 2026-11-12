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
	if got, err := downloadSessionSeconds(); err != nil || got != 4*60*60 {
		t.Fatalf("default timeout: %d %v", got, err)
	}
	for _, value := range []string{"garbage", "0", "-1s", "1ms", "1000h"} {
		t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", value)
		if _, err := downloadSessionSeconds(); err == nil {
			t.Fatalf("accepted invalid timeout %q", value)
		}
	}
	t.Setenv("OKURU_DOWNLOAD_SESSION_TIMEOUT", "3h")
	if got, err := downloadSessionSeconds(); err != nil || got != 10800 {
		t.Fatalf("valid timeout: %d %v", got, err)
	}
}
