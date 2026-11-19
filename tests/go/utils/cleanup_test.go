package utils

import (
	"context"
	"errors"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cleanupTest(t *testing.T) redis.Conn {
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
	t.Helper()
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oh, op, odb, opass, opre, of := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER
	REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER = h, p, "0", "", "cleanup_security_", t.TempDir()
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		keys, _ := redis.Strings(c.Do("KEYS", "cleanup_security_*"))
		for _, k := range keys {
			c.Do("DEL", k)
		}
		c.Close()
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER = oh, op, odb, opass, opre, of
	})
	return c
}
func cleanupArchive(t *testing.T, id string) string {
	t.Helper()
	p := filepath.Join(FILEFOLDER, id+".zip")
	if err := os.WriteFile(p, []byte("owned-test"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func cleanupEventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("cleanup condition not reached")
		case <-ticker.C:
		}
	}
}

func TestCleanFileReturnsRemovalErrors(t *testing.T) {
	oldFolder := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = oldFolder })
	id := uuid.NewString()
	path := filepath.Join(FILEFOLDER, id+".zip")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := CleanFile(id); err == nil {
		t.Fatal("non-regular archive was treated as successfully removed")
	}
	if err := CleanFile("../outside"); err == nil {
		t.Fatal("non-canonical archive identifier was accepted")
	}
	if err := CleanFile(uuid.NewString()); err != nil {
		t.Fatalf("already absent archive should count as removed: %v", err)
	}
}

func TestRemoveFileReportsArchiveRemovalFailure(t *testing.T) {
	c := cleanupTest(t)
	link, httpErr := SetFile(archiveTestIdentity(t), 60, 1, true, false, "", ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	id := strings.Split(link, TOKEN_SEPARATOR)[0]
	path := filepath.Join(FILEFOLDER, id+".zip")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveFile(&models.File{FileKey: link}); err == nil {
		t.Fatal("removal failure was reported as success")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("test archive directory unexpectedly removed: %v", err)
	}
	if n, err := redis.Int(c.Do("EXISTS", REDIS_PREFIX+"file_"+id)); err != nil || n != 0 {
		t.Fatalf("file metadata should be removed before reconciliation: %d, %v", n, err)
	}
}
func TestCleanupReconcilesOnlyExpiredManagedArchives(t *testing.T) {
	c := cleanupTest(t)
	active, expired := uuid.NewString(), uuid.NewString()
	activePath := cleanupArchive(t, active)
	expiredPath := cleanupArchive(t, expired)
	c.Do("SET", REDIS_PREFIX+"file_"+active, "active", "EX", 300)
	unknown := cleanupArchive(t, "unmanaged")
	dir := filepath.Join(FILEFOLDER, uuid.NewString()+".zip")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("preserve"), 0600)
	symlink := filepath.Join(FILEFOLDER, uuid.NewString()+".zip")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatal("expired ZIP retained")
	}
	for _, p := range []string{activePath, unknown, dir, outside, symlink} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("unrelated or live file removed: %s", p)
		}
	}
}

func TestCleanupReconcilesAfterRealRedisExpiry(t *testing.T) {
	c := cleanupTest(t)
	id := uuid.NewString()
	path := cleanupArchive(t, id)
	key := REDIS_PREFIX + "file_" + id
	if _, err := c.Do("HSET", key, "token", "synthetic", "views", 1, "views_count", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("EXPIRE", key, 30); err != nil {
		t.Fatal(err)
	}
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Unexpired archive was removed: %v", err)
	}
	if _, err := c.Do("PEXPIRE", key, 200); err != nil {
		t.Fatal(err)
	}
	cleanupEventually(t, func() bool {
		exists, err := redis.Bool(c.Do("EXISTS", key))
		if err != nil {
			t.Fatal(err)
		}
		return !exists
	})
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Archive remained after its Redis record expired: %v", err)
	}
}

func TestCleanupRetainsFilesWhenRedisFails(t *testing.T) {
	cleanupTest(t)
	path := cleanupArchive(t, uuid.NewString())
	entries, err := os.ReadDir(FILEFOLDER)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cleanupConnection(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := reconcileArchives(context.Background(), c, entries); err == nil {
		t.Fatal("Redis failure not reported")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("file removed despite Redis failure")
	}
}
func TestSecretExpiryDoesNotStopFileCleanupAndWorkerCancels(t *testing.T) {
	c := cleanupTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runFileCleanup(ctx, time.Hour); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("cleanup worker leaked")
		}
	}()
	channel := "__keyevent@0__:expired"
	subscribed := func() bool {
		v, err := redis.Values(c.Do("PUBSUB", "NUMSUB", channel))
		if err != nil || len(v) != 2 {
			return false
		}
		n, _ := redis.Int(v[1], nil)
		return n > 0
	}
	cleanupEventually(t, subscribed)
	// The same payload the worker receives when an ordinary secret expires.
	c.Do("PUBLISH", channel, REDIS_PREFIX+uuid.NewString())
	id := uuid.NewString()
	path := cleanupArchive(t, id)
	c.Do("PUBLISH", channel, REDIS_PREFIX+"file_"+id)
	cleanupEventually(t, func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
	// Disconnect only Pub/Sub clients in this isolated test Redis.
	if _, err := c.Do("CLIENT", "KILL", "TYPE", "pubsub"); err != nil {
		t.Fatal(err)
	}
	cleanupEventually(t, subscribed)
	id = uuid.NewString()
	path = cleanupArchive(t, id)
	c.Do("PUBLISH", channel, REDIS_PREFIX+"file_"+id)
	cleanupEventually(t, func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
}

func TestCleanupDryRunPreservesExpiredArchives(t *testing.T) {
	cleanupTest(t)
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "true")
	path := cleanupArchive(t, uuid.NewString())
	if err := CleanupExpiredArchives(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("dry-run removed archive")
	}
}

// A local failure must not prevent later expired archives from being handled.
func TestReconcileContinuesAfterLocalFailure(t *testing.T) {
	old := FILEFOLDER
	FILEFOLDER = t.TempDir()
	defer func() { FILEFOLDER = old }()
	first, second := uuid.NewString(), uuid.NewString()
	if first > second {
		first, second = second, first
	}
	firstPath, secondPath := cleanupArchive(t, first), cleanupArchive(t, second)
	entries, err := os.ReadDir(FILEFOLDER)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("local removal failure")
	err = reconcileArchivesWith(context.Background(), nil, entries, func(_ redis.Conn, id string) error {
		if id == first {
			return sentinel
		}
		return os.Remove(filepath.Join(FILEFOLDER, id+".zip"))
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("failure was not reported: %v", err)
	}
	if _, err := os.Stat(firstPath); err != nil {
		t.Fatal("failed archive was removed")
	}
	if _, err := os.Stat(secondPath); !os.IsNotExist(err) {
		t.Fatal("later archive was not removed")
	}
}

func TestRemoveFileACLFailurePreservesBothRecordsAndArchive(t *testing.T) {
	admin := cleanupTest(t)
	secretLink, httpErr := SetPassword("test-password", 60, 1, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	secretID := strings.Split(secretLink, TOKEN_SEPARATOR)[0]
	fileLink, httpErr := SetFile("test-password", 60, 1, true, true, secretID, ArchiveFormatAgeUserPassword)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	fileID := strings.Split(fileLink, TOKEN_SEPARATOR)[0]
	path := cleanupArchive(t, fileID)
	fileKey, secretKey := REDIS_PREFIX+"file_"+fileID, REDIS_PREFIX+secretID
	username := "okuru_delete_acl_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if err := RemoveFile(&models.File{FileKey: fileLink}); err == nil {
		t.Fatal("restricted delete succeeded")
	}
	for _, key := range []string{fileKey, secretKey} {
		n, err := redis.Int(admin.Do("EXISTS", key))
		if err != nil || n != 1 {
			t.Fatalf("metadata lost after denied delete: %d %v", n, err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive lost after denied delete: %v", err)
	}
	CloseRedisPool()
	redisDialContext = originalDial
	if err := RemoveFile(&models.File{FileKey: fileLink}); err != nil {
		t.Fatalf("authorized retry failed: %v", err)
	}
	for _, key := range []string{fileKey, secretKey} {
		n, err := redis.Int(admin.Do("EXISTS", key))
		if err != nil || n != 0 {
			t.Fatalf("metadata retained after retry: %d %v", n, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("archive retained after retry")
	}
}

func retentionTestFolder(t *testing.T) {
	t.Helper()
	previous := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = previous })
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
}

func stampRetentionTestFile(t *testing.T, path string, stamp time.Time) {
	t.Helper()
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveRetentionSevenDayBoundaryAndGuards(t *testing.T) {
	retentionTestFolder(t)
	now := time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)
	cutoff := now.Add(-7 * 24 * time.Hour)
	boundary, older := cleanupArchive(t, uuid.NewString()), cleanupArchive(t, uuid.NewString())
	younger, future := cleanupArchive(t, uuid.NewString()), cleanupArchive(t, uuid.NewString())
	stampRetentionTestFile(t, boundary, cutoff)
	stampRetentionTestFile(t, older, cutoff.Add(-time.Hour))
	stampRetentionTestFile(t, younger, cutoff.Add(time.Second))
	stampRetentionTestFile(t, future, now.Add(time.Minute))

	unmanaged := cleanupArchive(t, "example")
	stampRetentionTestFile(t, unmanaged, cutoff)
	outside := filepath.Join(t.TempDir(), "unrelated.zip")
	if err := os.WriteFile(outside, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	stampRetentionTestFile(t, outside, cutoff)
	symlink := filepath.Join(FILEFOLDER, uuid.NewString()+".zip")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(FILEFOLDER, uuid.NewString()+".zip")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	stampRetentionTestFile(t, nested, cutoff)
	journal, err := publicationRoot()
	if err != nil {
		t.Fatal(err)
	}
	protected := []string{younger, future, unmanaged, symlink, outside, nested}
	for _, marker := range []string{"", "collision-"} {
		id := uuid.NewString()
		path := cleanupArchive(t, id)
		stampRetentionTestFile(t, path, cutoff)
		if err := os.Mkdir(filepath.Join(journal, marker+id), 0700); err != nil {
			t.Fatal(err)
		}
		protected = append(protected, path)
	}
	// Include enough non-candidates to span several bounded batches.
	for i := range 257 {
		if err := os.WriteFile(filepath.Join(FILEFOLDER, strconv.Itoa(i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "true")
	if err := enforceArchiveRetention(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{boundary, older} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("dry-run removed an archive", err)
		}
	}
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
	if err := enforceArchiveRetention(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{boundary, older} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("deadline did not unlink archive", err)
		}
	}
	for _, path := range protected {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("protected or ineligible entry was removed", err)
		}
	}
}

func TestArchiveRetentionIgnoresStuckRedisMetadata(t *testing.T) {
	c := cleanupTest(t)
	id := uuid.NewString()
	path := cleanupArchive(t, id)
	key := REDIS_PREFIX + "file_" + id
	if _, err := c.Do("HSET", key, "token", "synthetic", "views", 2); err != nil {
		t.Fatal(err)
	}
	stampRetentionTestFile(t, path, time.Now().Add(-8*24*time.Hour))
	if err := enforceArchiveRetention(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("stuck key retained archive", err)
	}
	if ttl, err := redis.Int(c.Do("TTL", key)); err != nil || ttl != -1 {
		t.Fatal("unexpected Redis mutation", ttl, err)
	}
}

func TestArchiveRetentionStartsAndRepeatsWithoutRedis(t *testing.T) {
	retentionTestFolder(t)
	db := REDIS_DB
	REDIS_DB = "unavailable"
	t.Cleanup(func() { REDIS_DB = db })
	if c, err := cleanupConnection(t.Context(), time.Second); err == nil {
		c.Close()
		t.Fatal("fixture must reject every Redis connection")
	}
	path := cleanupArchive(t, uuid.NewString())
	stale := time.Now().Add(-8 * 24 * time.Hour)
	stampRetentionTestFile(t, path, stale)
	absent := func(path string) bool { _, err := os.Lstat(path); return os.IsNotExist(err) }
	stop := startArchiveRetention(time.Hour)
	stop() // Simulates immediate startup failure; first scan still completes.
	if !absent(path) {
		t.Fatal("startup missed an overdue archive without Redis")
	}
	stop = startArchiveRetention(15 * time.Millisecond)
	defer stop()
	newPath := cleanupArchive(t, uuid.NewString())
	stampRetentionTestFile(t, newPath, stale)
	cleanupEventually(t, func() bool { return absent(newPath) })
}

func TestPublicationStartsArchiveRetentionClock(t *testing.T) {
	retentionTestFolder(t)
	source := filepath.Join(t.TempDir(), "sealed")
	if err := os.WriteFile(source, []byte("sealed"), 0600); err != nil {
		t.Fatal(err)
	}
	stampRetentionTestFile(t, source, time.Now().Add(-10*24*time.Hour))
	path := filepath.Join(FILEFOLDER, uuid.NewString()+".zip")
	if err := LinkPublishedArchive(source, path); err != nil {
		t.Fatal(err)
	}
	if err := enforceArchiveRetention(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("new publication inherited old staging time", err)
	}
}
