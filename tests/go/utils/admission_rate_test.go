package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
)

func admissionTestRedis(t *testing.T) redis.Conn {
	t.Helper()
	address := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("admission tests require an isolated loopback Redis address")
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX
	REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD = host, port, "0", ""
	REDIS_PREFIX = "admission_test_" + time.Now().Format("150405.000000000") + "_"
	t.Cleanup(func() {
		_ = CloseRedisPool()
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX = oldHost, oldPort, oldDB, oldPassword, oldPrefix
	})
	conn, err := redis.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestAdmissionLimitsRemainAtomicAcrossConcurrentClients(t *testing.T) {
	conn := admissionTestRedis(t)
	var accepted, failed atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			ok, err := AllowIdentityAction("192.0.2.5", "test_atomic", 3, 20, time.Minute)
			if err != nil {
				failed.Add(1)
			} else if ok {
				accepted.Add(1)
			}
		}()
	}
	group.Wait()
	if failed.Load() != 0 || accepted.Load() != 3 {
		t.Fatalf("accepted=%d failed=%d, want 3 and 0", accepted.Load(), failed.Load())
	}
	keys, err := redis.Strings(conn.Do("KEYS", REDIS_PREFIX+"admission_test_atomic_*"))
	if err != nil || len(keys) != 2 {
		t.Fatalf("counter keys=%v err=%v", keys, err)
	}
	for _, key := range keys {
		if strings.Contains(key, "192.0.2.5") {
			t.Fatal("counter key contains a raw address")
		}
		ttl, err := redis.Int64(conn.Do("PTTL", key))
		if err != nil || ttl <= 0 || ttl > time.Minute.Milliseconds() {
			t.Fatalf("counter TTL=%d err=%v", ttl, err)
		}
	}
}

func TestAdmissionGlobalBudgetAndExpiry(t *testing.T) {
	admissionTestRedis(t)
	for _, identity := range []string{"192.0.2.1", "192.0.2.2"} {
		ok, err := AllowIdentityAction(identity, "test_global", 3, 2, time.Second)
		if err != nil || !ok {
			t.Fatalf("admission denied prematurely: %v %v", ok, err)
		}
	}
	if ok, err := AllowIdentityAction("192.0.2.3", "test_global", 3, 2, time.Second); err != nil || ok {
		t.Fatalf("global budget ignored: %v %v", ok, err)
	}
	time.Sleep(1100 * time.Millisecond)
	if ok, err := AllowIdentityAction("192.0.2.3", "test_global", 3, 2, time.Second); err != nil || !ok {
		t.Fatalf("budget did not expire: %v %v", ok, err)
	}
}

func TestAdmissionRejectsUnboundedOrInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		identity, action string
		per, global      int
		window           time.Duration
	}{
		{"", "test", 1, 1, time.Minute},
		{"client", "test:*", 1, 1, time.Minute},
		{"client", "test", 0, 1, time.Minute},
		{"client", "test", 1, 1, 0},
		{"client", "test", 1, 1, 25 * time.Hour},
	} {
		if ok, err := AllowIdentityAction(tc.identity, tc.action, tc.per, tc.global, tc.window); err == nil || ok {
			t.Fatalf("invalid admission accepted: %+v", tc)
		}
	}
}

func TestAdmissionRejectsCorruptOrPersistentCounters(t *testing.T) {
	conn := admissionTestRedis(t)
	identity := "192.0.2.70"
	digest := sha256.Sum256([]byte(identity))
	key := REDIS_PREFIX + "admission_test_corrupt_" + hex.EncodeToString(digest[:])
	for _, raw := range []string{"not-a-number", "1"} {
		// Both malformed values and numeric keys lacking an expiry must fail
		// closed, without allocating the global counter.
		if _, err := conn.Do("SET", key, raw); err != nil {
			t.Fatal(err)
		}
		if ok, err := AllowIdentityAction(identity, "test_corrupt", 3, 5, time.Minute); err == nil || ok {
			t.Fatalf("invalid counter %q was accepted", raw)
		}
		exists, err := redis.Int(conn.Do("EXISTS", REDIS_PREFIX+"admission_test_corrupt_global"))
		if err != nil || exists != 0 {
			t.Fatalf("global counter modified on error: %d, %v", exists, err)
		}
	}
}

func TestAdmissionSharedProxyUsesGlobalBudgetAndIgnoresSpoofedHeaders(t *testing.T) {
	admissionTestRedis(t)
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	for i := 0; i < 4; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "127.0.0.1:8000"
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		ok, err := AllowClientAction(r, "test_shared", 1, 3, time.Minute)
		if err != nil || ok != (i < 3) {
			t.Fatalf("attempt %d: allowed=%v err=%v", i, ok, err)
		}
	}
}
