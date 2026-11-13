package router

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/utils"
)

func configureLeaseTestRedis(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("OKURU_TEST_REDIS_ADDR is required for isolated Redis lease tests")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("lease tests require an isolated loopback Redis address")
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix := utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD, utils.REDIS_PREFIX
	oldPool := uploadLeasePool
	_ = utils.CloseRedisPool()
	utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD = host, port, "0", ""
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	utils.REDIS_PREFIX = "test_upload_lease_" + hex.EncodeToString(random[:]) + "_"
	uploadLeasePool = utils.NewPool
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	t.Cleanup(func() {
		// Only remove this test's random prefix; never FLUSHDB.
		c := utils.NewPool().Get()
		if keys, err := redis.Strings(c.Do("KEYS", utils.REDIS_PREFIX+"*")); err == nil {
			for _, key := range keys {
				_, _ = c.Do("DEL", key)
			}
		}
		_ = c.Close()
		_ = utils.CloseRedisPool()
		utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD, utils.REDIS_PREFIX = oldHost, oldPort, oldDB, oldPassword, oldPrefix
		uploadLeasePool = oldPool
	})
	return utils.REDIS_PREFIX
}

func leaseRequest(addr string) *http.Request {
	r := httptest.NewRequest("POST", "/file", nil)
	r.RemoteAddr = addr
	return r
}

func TestUploadLeaseSingleIdentityAcrossConnections(t *testing.T) {
	configureLeaseTestRedis(t)
	first, err := acquireUploadLease(leaseRequest("192.0.2.1:1200"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	if release, err := acquireUploadLease(leaseRequest("192.0.2.1:1300"), 5*time.Second); !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		t.Fatalf("same client was not denied: release=%v error=%v", release != nil, err)
	}
	other, err := acquireUploadLease(leaseRequest("192.0.2.2:1300"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other()
	first()
	first() // release is idempotent
	again, err := acquireUploadLease(leaseRequest("192.0.2.1:1400"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func TestUploadLeaseExpiredOwnerCannotReleaseSuccessor(t *testing.T) {
	configureLeaseTestRedis(t)
	r := leaseRequest("192.0.2.3:1200")
	old, err := acquireUploadLease(r, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	current, err := acquireUploadLease(r, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer current()
	old()
	if release, err := acquireUploadLease(r, time.Second); !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		t.Fatalf("old owner released successor: release=%v error=%v", release != nil, err)
	}
}

func TestUploadLeaseConcurrentAdmission(t *testing.T) {
	configureLeaseTestRedis(t)
	const attempts = 16
	var successes atomic.Int32
	var wg sync.WaitGroup
	releases := make(chan func(), attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			release, err := acquireUploadLease(leaseRequest("192.0.2.4:9000"), 5*time.Second)
			if err == nil {
				successes.Add(1)
				releases <- release
			} else if !errors.Is(err, ErrUploadLeaseBusy) {
				t.Errorf("unexpected lease error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(releases)
	for release := range releases {
		release()
	}
	if successes.Load() != 1 {
		t.Fatalf("got %d concurrent reservations, want 1", successes.Load())
	}
}

func TestUploadLeaseFailClosed(t *testing.T) {
	if release, err := acquireUploadLease(nil, time.Second); err == nil || release != nil {
		t.Fatal("nil request was accepted")
	}
	if release, err := acquireUploadLease(leaseRequest("192.0.2.1:42"), 0); err == nil || release != nil {
		t.Fatal("zero TTL was accepted")
	}
	if release, err := acquireUploadLease(leaseRequest("not-an-address"), time.Second); err == nil || release != nil {
		t.Fatal("invalid identity was accepted")
	}
	old := uploadLeasePool
	uploadLeasePool = func() *redis.Pool { return nil }
	t.Cleanup(func() { uploadLeasePool = old })
	if release, err := acquireUploadLease(leaseRequest("192.0.2.1:42"), time.Second); err == nil || release != nil {
		t.Fatal("unavailable Redis was accepted")
	}
	uploadLeasePool = func() *redis.Pool {
		return &redis.Pool{Dial: func() (redis.Conn, error) { return nil, errors.New("simulated Redis outage") }}
	}
	if release, err := acquireUploadLease(leaseRequest("192.0.2.1:42"), time.Second); err == nil || errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		t.Fatal("Redis connection failure was not refused as an availability error")
	}
}

func TestUploadLeaseIPv6PrefixSharing(t *testing.T) {
	configureLeaseTestRedis(t)
	first, err := acquireUploadLease(leaseRequest("[2001:db8:1234:5678::1]:1200"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	if release, err := acquireUploadLease(leaseRequest("[2001:db8:1234:5678::2]:1300"), time.Second); !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		t.Fatalf("IPv6 addresses in the same /64 were not grouped: %v", err)
	}
	other, err := acquireUploadLease(leaseRequest("[2001:db8:1234:5679::1]:1300"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other()
}

func TestUploadLeaseSharedProxyFourSlotsAndIndependentExpiry(t *testing.T) {
	prefix := configureLeaseTestRedis(t)
	r := leaseRequest("127.0.0.1:1200")
	first, err := acquireUploadLease(r, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var active []func()
	for i := 0; i < 3; i++ {
		release, err := acquireUploadLease(r, 5*time.Second)
		if err != nil {
			t.Fatalf("shared slot %d rejected: %v", i+2, err)
		}
		active = append(active, release)
	}
	t.Cleanup(func() {
		for _, release := range active {
			release()
		}
	})
	if release, err := acquireUploadLease(r, time.Second); !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		t.Fatalf("fifth shared upload was not denied: %v", err)
	}
	// Expire just slot 1 without shortening the three longer slot TTLs.
	c := utils.NewPool().Get()
	defer c.Close()
	keys, err := redis.Strings(c.Do("KEYS", prefix+"upload_lease_*"))
	if err != nil || len(keys) != 8 {
		t.Fatalf("expected eight slot keys: %v", err)
	}
	token, err := redis.String(c.Do("GET", prefix+"upload_lease_{okuru-upload-lease}_global_1"))
	if err != nil {
		t.Fatal(err)
	}
	expired := 0
	for _, key := range keys {
		value, e := redis.String(c.Do("GET", key))
		if e != nil {
			t.Fatal(e)
		}
		if value == token {
			if _, e = c.Do("PEXPIRE", key, 100); e != nil {
				t.Fatal(e)
			}
			expired++
		}
	}
	if expired != 2 {
		t.Fatalf("expected paired lease keys, got %d", expired)
	}
	time.Sleep(300 * time.Millisecond)
	successor, err := acquireUploadLease(r, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	active = append(active, successor)
	first() // compare-and-delete must not release the successor of slot 1.
	if release, err := acquireUploadLease(r, time.Second); !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		t.Fatalf("old shared slot owner released its successor: %v", err)
	}
	keys, err = redis.Strings(c.Do("KEYS", prefix+"upload_lease_*"))
	if err != nil || len(keys) != 8 {
		t.Fatalf("expected eight independent slot keys, got %d: %v", len(keys), err)
	}
	for _, key := range keys {
		if strings.Contains(key, "127.0.0.1") {
			t.Fatal("raw client address appeared in a lease key")
		}
		ttl, err := redis.Int64(c.Do("PTTL", key))
		if err != nil || ttl <= 0 {
			t.Fatalf("slot key lacks an expiry: %d %v", ttl, err)
		}
	}
}

func TestUploadLeaseSharedProxyConcurrentSlots(t *testing.T) {
	configureLeaseTestRedis(t)
	const attempts = 16
	var successes atomic.Int32
	var wg sync.WaitGroup
	releases := make(chan func(), attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			release, err := acquireUploadLease(leaseRequest("127.0.0.1:9000"), 5*time.Second)
			if err == nil {
				successes.Add(1)
				releases <- release
			} else if !errors.Is(err, ErrUploadLeaseBusy) {
				t.Errorf("unexpected shared lease error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(releases)
	for release := range releases {
		release()
	}
	if successes.Load() != 4 {
		t.Fatalf("got %d concurrent shared reservations, want 4", successes.Load())
	}
}

func TestUploadLeaseSubprocessHelper(t *testing.T) {
	mode := os.Getenv("OKURU_TEST_LEASE_CHILD")
	if mode == "" {
		return
	}
	host, port, err := net.SplitHostPort(os.Getenv("OKURU_TEST_REDIS_ADDR"))
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("child requires isolated loopback Redis")
	}
	utils.REDIS_HOST, utils.REDIS_PORT, utils.REDIS_DB, utils.REDIS_PASSWORD = host, port, "0", ""
	utils.REDIS_PREFIX = os.Getenv("OKURU_TEST_LEASE_PREFIX")
	addr := "192.0.2.8:8001"
	if custom := os.Getenv("OKURU_TEST_LEASE_CHILD_ADDR"); custom != "" {
		addr = custom
	}
	if strings.HasPrefix(mode, "shared-") {
		addr = "127.0.0.1:8001"
		mode = strings.TrimPrefix(mode, "shared-")
	}
	release, err := acquireUploadLease(leaseRequest(addr), 30*time.Second)
	if mode == "busy" {
		if !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
			t.Fatalf("child did not observe the existing lease: %v", err)
		}
		return
	}
	if mode != "available" || err != nil {
		t.Fatalf("child could not reserve identity: %v", err)
	}
	release()
}

func TestUploadLeaseSharedProxyAcrossProcesses(t *testing.T) {
	prefix := configureLeaseTestRedis(t)
	var held []func()
	for i := 0; i < 4; i++ {
		release, err := acquireUploadLease(leaseRequest("127.0.0.1:8000"), 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
		t.Cleanup(release)
	}
	run := func(mode string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestUploadLeaseSubprocessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), "OKURU_TEST_LEASE_CHILD=shared-"+mode, "OKURU_TEST_LEASE_PREFIX="+prefix)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child %s: %v: %s", mode, err, output)
		}
	}
	run("busy")
	held[0]()
	run("available")
}

func TestUploadLeaseAcrossProcesses(t *testing.T) {
	prefix := configureLeaseTestRedis(t)
	first, err := acquireUploadLease(leaseRequest("192.0.2.8:8000"), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first)
	run := func(mode string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestUploadLeaseSubprocessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), "OKURU_TEST_LEASE_CHILD="+mode, "OKURU_TEST_LEASE_PREFIX="+prefix)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child %s: %v: %s", mode, err, output)
		}
	}
	run("busy")
	first()
	run("available")
}

// Separate identities still share the global admission budget, even across
// Redis connections and concurrent processes.
func TestUploadLeaseGlobalAcrossIdentitiesAndProcesses(t *testing.T) {
	prefix := configureLeaseTestRedis(t)
	const attempts = 20
	var successes atomic.Int32
	var wg sync.WaitGroup
	releases := make(chan func(), attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			release, err := acquireUploadLease(leaseRequest(fmt.Sprintf("192.0.2.%d:9000", i+1)), 30*time.Second)
			if err == nil {
				successes.Add(1)
				releases <- release
			} else if !errors.Is(err, ErrUploadLeaseBusy) {
				t.Errorf("unexpected lease error: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(releases)
	var held []func()
	for release := range releases {
		held = append(held, release)
		t.Cleanup(release)
	}
	if successes.Load() != 4 {
		t.Fatalf("got %d reservations across identities, want 4", successes.Load())
	}
	run := func(mode string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestUploadLeaseSubprocessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), "OKURU_TEST_LEASE_CHILD="+mode, "OKURU_TEST_LEASE_PREFIX="+prefix, "OKURU_TEST_LEASE_CHILD_ADDR=198.51.100.200:9000")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child %s: %v: %s", mode, err, output)
		}
	}
	run("busy")
	held[0]()
	run("available")
}

func TestUploadLeaseExpiredOwnerCannotReleaseAnotherIdentityGlobalSlot(t *testing.T) {
	configureLeaseTestRedis(t)
	old, err := acquireUploadLease(leaseRequest("192.0.2.1:9000"), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	for i := 2; i <= 5; i++ {
		release, err := acquireUploadLease(leaseRequest(fmt.Sprintf("192.0.2.%d:9000", i)), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	old()
	if release, err := acquireUploadLease(leaseRequest("192.0.2.6:9000"), time.Second); !errors.Is(err, ErrUploadLeaseBusy) || release != nil {
		if release != nil {
			release()
		}
		t.Fatalf("expired owner freed another identity's global slot: %v", err)
	}
}
