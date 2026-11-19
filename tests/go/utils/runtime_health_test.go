package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

func TestRuntimeHealthReadinessAndFreshness(t *testing.T) {
	h := NewRuntimeHealth()
	if h.Ready() || h.RedisReady() {
		t.Fatal("ready before the first sample")
	}
	now := time.Now()
	h.recordRedis(now)
	if !h.RedisReady() || h.Ready() {
		t.Fatal("storage recovery must finish first")
	}
	h.SetStorageReady(true)
	h.recordStorage(archiveWritable, time.Now(), nil)
	if !h.Ready() {
		t.Fatal("healthy after recovery")
	}
	if !h.redisReadyAt(now.Add(healthFreshness-time.Nanosecond)) || h.redisReadyAt(now.Add(healthFreshness)) {
		t.Fatal("incorrect Redis freshness boundary")
	}
	h.recordRedis(now.Add(-healthFreshness))
	if h.Ready() || h.RedisReady() {
		t.Fatal("stale success still served")
	}
	h.recordRedis(now)
	h.SetStorageReady(false)
	if h.Ready() || !h.RedisReady() {
		t.Fatal("storage failure changed the Redis sample")
	}
}

func TestRuntimeHealthProbeTransitionsAndCancellation(t *testing.T) {
	var logs bytes.Buffer
	logger := log.StandardLogger()
	out := logger.Out
	logger.SetOutput(&logs)
	defer logger.SetOutput(out)
	h := NewRuntimeHealth()
	h.SetStorageReady(true)
	h.recordStorage(archiveWritable, time.Now(), nil)
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	attempts := make(chan context.Context)
	outcomes := make(chan bool)
	finished := make(chan struct{})
	probe := func(ctx context.Context) bool {
		select {
		case attempts <- ctx:
		case <-ctx.Done():
			return false
		}
		select {
		case ok := <-outcomes:
			return ok
		case <-ctx.Done():
			return false
		}
	}
	go func() { defer close(finished); h.run(ctx, time.Millisecond, 150*time.Millisecond, probe) }()
	next := func() context.Context {
		t.Helper()
		select {
		case c := <-attempts:
			return c
		case <-time.After(2 * time.Second):
			t.Fatal("probe did not run")
			return nil
		}
	}
	first := next()
	if _, ok := first.Deadline(); !ok {
		t.Fatal("probe lacks deadline")
	}
	outcomes <- true
	_ = next()
	if !h.Ready() {
		t.Fatal("first successful probe did not open readiness")
	}
	outcomes <- true // unchanged observations produce no additional event
	_ = next()
	outcomes <- false
	_ = next()
	if h.Ready() {
		t.Fatal("observed Redis failure did not close readiness")
	}
	outcomes <- true
	timed := next()
	if !h.Ready() {
		t.Fatal("Redis recovery did not restore readiness")
	}
	<-timed.Done()
	_ = next()
	if h.Ready() {
		t.Fatal("timeout left readiness open")
	}
	stop()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("shutdown left a probe running")
	}
	if h.Ready() {
		t.Fatal("stopped monitor reported ready")
	}
	if n := strings.Count(logs.String(), "Redis is "); n != 4 {
		t.Fatalf("expected four transition events, got %d", n)
	}
}

// Use real Redigo connections over in-memory streams so a disconnect and
// subsequent reconnect exercise the same pool and RESP PING as production.
func TestRuntimeHealthReconnectsUsingApplicationPool(t *testing.T) {
	poolTestConfig(t)
	type reply struct{ cmd, resp string }
	replies := make(chan reply, 7)
	for _, op := range []reply{
		{"PING", "+PONG\r\n"}, {"EVAL", ":1\r\n"},
		{"PING", ""},
		{"PING", "+PONG\r\n"}, {"EVAL", "-READONLY Redis is read-only\r\n"},
		{"PING", "+PONG\r\n"}, {"EVAL", ":1\r\n"},
	} {
		replies <- op
	}
	close(replies)
	dials := 0
	redisDialContext = func(_ context.Context, _, _ string, _ ...redis.DialOption) (redis.Conn, error) {
		dials++
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			decoder := redis.NewConn(server, time.Second, time.Second)
			for op := range replies {
				args, err := redis.Strings(decoder.Receive())
				if err != nil || len(args) == 0 || args[0] != op.cmd || op.resp == "" {
					return
				}
				if op.cmd == "EVAL" && (len(args) != 4 || args[1] != redisHealthScript || args[2] != "1" || !strings.HasPrefix(args[3], REDIS_PREFIX+"runtime_health_")) {
					return
				}
				if _, err := io.WriteString(server, op.resp); err != nil {
					return
				}
			}
		}()
		return redis.NewConn(client, time.Second, time.Second), nil
	}
	for i, want := range []bool{true, false, false, true} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		actual := probeApplicationRedis(ctx)
		cancel()
		if actual != want {
			t.Fatalf("probe %d: got %t, want %t", i, actual, want)
		}
	}
	if dials != 2 {
		t.Fatalf("expected a single reconnect, dialed %d times", dials)
	}
}

func TestRuntimeHealthRedisVerificationAndExpiry(t *testing.T) {
	admin := admissionTestRedis(t)
	ctx := t.Context()
	key := REDIS_PREFIX + "runtime_health_" + rand.Text()
	user := "health-test-" + rand.Text()
	password := rand.Text()
	t.Cleanup(func() { _, _ = admin.Do("DEL", key); _, _ = admin.Do("ACL", "DELUSER", user) })
	// Exercise exactly the permissions documented for the service's health keys.
	if _, err := admin.Do("ACL", "SETUSER", user, "on", ">"+password, "~"+REDIS_PREFIX+"runtime_health_*", "+ping", "+eval", "+set", "+get", "+del"); err != nil {
		t.Fatal(err)
	}
	c, err := redis.Dial("tcp", os.Getenv("OKURU_TEST_REDIS_ADDR"), redis.DialUsername(user), redis.DialPassword(password))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !probeRedisConnection(ctx, c, key) {
		t.Fatal("writable Redis rejected")
	}
	if found, err := redis.Bool(admin.Do("EXISTS", key)); err != nil || found {
		t.Fatal("successful probe retained a key", err)
	}
	if _, err := admin.Do("SET", key, "existing"); err != nil {
		t.Fatal(err)
	}
	if probeRedisConnection(ctx, c, key) {
		t.Fatal("probe accepted a key collision")
	}
	if value, err := redis.String(admin.Do("GET", key)); err != nil || value != "existing" {
		t.Fatal("collision changed a pre-existing key", err)
	}
	if _, err := admin.Do("DEL", key); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Do("ACL", "SETUSER", user, "-set"); err != nil {
		t.Fatal(err)
	}
	if !Ping(c) || probeRedisConnection(ctx, c, key) {
		t.Fatal("read-only permissions failed to close readiness")
	}
	if _, err := admin.Do("ACL", "SETUSER", user, "+set", "-del"); err != nil {
		t.Fatal(err)
	}
	if probeRedisConnection(ctx, c, key) {
		t.Fatal("missing delete permission did not close readiness")
	}
	if ttl, err := redis.Int64(admin.Do("PTTL", key)); err != nil || ttl <= 0 || ttl > 10000 {
		t.Fatalf("failed cleanup has no bounded expiry: %d, %v", ttl, err)
	}
}
