package utils

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
)

type fakePoolConn struct{ closed bool }

func (c *fakePoolConn) Close() error                                   { c.closed = true; return nil }
func (c *fakePoolConn) Err() error                                     { return nil }
func (c *fakePoolConn) Do(string, ...interface{}) (interface{}, error) { return "PONG", nil }
func (c *fakePoolConn) Send(string, ...interface{}) error              { return nil }
func (c *fakePoolConn) Flush() error                                   { return nil }
func (c *fakePoolConn) Receive() (interface{}, error)                  { return nil, nil }

func poolTestConfig(t *testing.T) {
	t.Helper()
	oldHost, oldPort, oldPassword, oldDB := REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB
	oldDial := redisDialContext
	_ = CloseRedisPool()
	REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB = "redis-test", "6379", "", "0"
	t.Cleanup(func() {
		_ = CloseRedisPool()
		REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB = oldHost, oldPort, oldPassword, oldDB
		redisDialContext = oldDial
	})
}

func TestRedisPoolReusesAndClosesConnections(t *testing.T) {
	poolTestConfig(t)
	created := 0
	var connection *fakePoolConn
	redisDialContext = func(_ context.Context, _, _ string, _ ...redis.DialOption) (redis.Conn, error) {
		created++
		connection = &fakePoolConn{}
		return connection, nil
	}
	pool := NewPool()
	if pool != NewPool() {
		t.Fatal("the same configuration must share a pool")
	}
	for i := 0; i < 2; i++ {
		c := NewPool().Get()
		if err := c.Err(); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if created != 1 || connection.closed {
		t.Fatalf("connection was not reused: dials=%d closed=%v", created, connection.closed)
	}
	if err := CloseRedisPool(); err != nil || !connection.closed {
		t.Fatalf("pool shutdown did not close idle connection: %v", err)
	}
}

func TestRedisPoolExhaustionFailsWithoutWaiting(t *testing.T) {
	poolTestConfig(t)
	redisDialContext = func(_ context.Context, _, _ string, _ ...redis.DialOption) (redis.Conn, error) {
		return &fakePoolConn{}, nil
	}
	pool := NewPool()
	connections := make([]redis.Conn, 0, redisMaxActive)
	for i := 0; i < redisMaxActive; i++ {
		c := pool.Get()
		if err := c.Err(); err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c)
	}
	defer func() {
		for _, c := range connections {
			_ = c.Close()
		}
	}()
	done := make(chan error, 1)
	go func() { c := pool.Get(); defer c.Close(); done <- c.Err() }()
	select {
	case err := <-done:
		if !errors.Is(err, redis.ErrPoolExhausted) {
			t.Fatalf("unexpected exhaustion error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pool acquisition blocked at capacity")
	}
}

func TestRedisPoolConfigurationChangeClosesPreviousPool(t *testing.T) {
	poolTestConfig(t)
	var first *fakePoolConn
	redisDialContext = func(_ context.Context, _, _ string, _ ...redis.DialOption) (redis.Conn, error) {
		first = &fakePoolConn{}
		return first, nil
	}
	old := NewPool()
	c := old.Get()
	if err := c.Err(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	REDIS_DB = "1"
	if NewPool() == old || !first.closed {
		t.Fatal("configuration change did not replace and close the previous pool")
	}
}

func TestRedisPoolDialFailureDoesNotPanic(t *testing.T) {
	poolTestConfig(t)
	redisDialContext = func(_ context.Context, _, _ string, _ ...redis.DialOption) (redis.Conn, error) {
		return nil, errors.New("connection unavailable")
	}
	c := NewPool().Get()
	defer c.Close()
	if c.Err() == nil || Ping(c) {
		t.Fatal("dial failure must be returned to the caller")
	}
}

func TestRedisPoolRejectsInvalidDatabaseBeforeDial(t *testing.T) {
	poolTestConfig(t)
	REDIS_DB = "invalid"
	called := false
	redisDialContext = func(_ context.Context, _, _ string, _ ...redis.DialOption) (redis.Conn, error) {
		called = true
		return &fakePoolConn{}, nil
	}
	c := NewPool().Get()
	defer c.Close()
	if c.Err() == nil || called {
		t.Fatal("invalid database must fail before dialing")
	}
}
