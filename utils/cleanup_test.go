package utils

import (
	"context"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"net"
	"os"
	"path/filepath"
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
