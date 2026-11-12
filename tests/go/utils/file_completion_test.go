package utils

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
)

// An ACL denial for the linked password must not partially delete the file
// record or its encrypted archive. Normal reconciliation retries after access
// is restored, without weakening the production Redis user's privileges.
func TestCompletedCleanupACLFailurePreservesRelatedRecordsAndRetries(t *testing.T) {
	admin := cleanupTest(t)
	secretLink, httpErr := SetPassword("test-password", 60, 1, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	secretID := strings.Split(secretLink, TOKEN_SEPARATOR)[0]
	fileLink, httpErr := SetFile("test-password", 60, 1, false, true, secretID)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	fileID := strings.Split(fileLink, TOKEN_SEPARATOR)[0]
	path := cleanupArchive(t, fileID)
	f := &models.File{FileKey: fileLink}
	claim, httpErr := ClaimFileDownload(f)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	defer ReleaseFileDownloadClaim(claim)
	etag := `"` + strings.Repeat("a", 64) + `"`
	cookie, _, tracker, err := CreateClaimedDownloadSession(f, "test-password", 10, claim, etag)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := REDIS_PREFIX + "file_" + fileID
	secretKey := REDIS_PREFIX + secretID
	sessionKey := downloadSessionKey(fileID, cookie)
	username := "okuru_finish_acl_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Do("ACL", "SETUSER", username, "on", ">temporary-test-password", "~"+fileKey, "~"+sessionKey, "+@all"); err != nil {
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
	if err := RecordDownloadProgress(tracker, 0, 10, true, true); err == nil {
		t.Fatal("restricted finalization succeeded")
	}
	for _, key := range []string{fileKey, secretKey, sessionKey} {
		if n, err := redis.Int(admin.Do("EXISTS", key)); err != nil || n != 1 {
			t.Fatalf("metadata lost after denied finalization: %d %v", n, err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive lost after denied finalization: %v", err)
	}
	CloseRedisPool()
	redisDialContext = originalDial
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatalf("reconciliation failed after ACL repair: %v", err)
	}
	for _, key := range []string{fileKey, secretKey, sessionKey} {
		if n, err := redis.Int(admin.Do("EXISTS", key)); err != nil || n != 0 {
			t.Fatalf("metadata retained after retry: %d %v", n, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("archive retained after authorized retry")
	}
}

// Dry-run suppresses reconciliation but does not alter the explicit
// finalization performed in response to a successfully completed download.
func TestCompletedCleanupDryRunDoesNotMutateDuringReconciliation(t *testing.T) {
	c := cleanupTest(t)
	fileLink, httpErr := SetFile("test-password", 60, 1, false, false, "")
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	fileID := strings.Split(fileLink, TOKEN_SEPARATOR)[0]
	path := cleanupArchive(t, fileID)
	f := &models.File{FileKey: fileLink}
	claim, httpErr := ClaimFileDownload(f)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	defer ReleaseFileDownloadClaim(claim)
	etag := `"` + strings.Repeat("a", 64) + `"`
	_, _, tracker, err := CreateClaimedDownloadSession(f, "test-password", 10, claim, etag)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a completed response awaiting a previous interrupted session.
	other := "pending_" + strings.Repeat("b", 32)
	if _, err := c.Do("HSET", tracker.fileKey, other, "1"); err != nil {
		t.Fatal(err)
	}
	if err := RecordDownloadProgress(tracker, 0, 10, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("HDEL", tracker.fileKey, other); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "true")
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("dry-run removed archive: %v", err)
	}
	if n, err := redis.Int(c.Do("EXISTS", tracker.fileKey)); err != nil || n != 1 {
		t.Fatalf("dry-run removed metadata: %d %v", n, err)
	}
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("archive retained after dry-run disabled")
	}
}

func TestSuccessfulDownloadFinalizationRemainsActiveDuringDryRun(t *testing.T) {
	cleanupTest(t)
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "true")
	fileLink, httpErr := SetFile("test-password", 60, 1, false, false, "")
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	fileID := strings.Split(fileLink, TOKEN_SEPARATOR)[0]
	path := cleanupArchive(t, fileID)
	f := &models.File{FileKey: fileLink}
	claim, httpErr := ClaimFileDownload(f)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	defer ReleaseFileDownloadClaim(claim)
	etag := `"` + strings.Repeat("a", 64) + `"`
	_, _, tracker, err := CreateClaimedDownloadSession(f, "test-password", 10, claim, etag)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordDownloadProgress(tracker, 0, 10, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("completed download was not finalized")
	}
}
