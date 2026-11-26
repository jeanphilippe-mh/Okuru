package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
)

// Each process shares a bounded pool. Pool.Get fails immediately at capacity:
// callers using Get rather than GetContext must never wait without a deadline.
const redisMaxActive = 64

type redisPoolConfig struct {
	host, port, password, database string
}

var redisPoolState struct {
	sync.Mutex
	config redisPoolConfig
	pool   *redis.Pool
}

// redisDialContext is a seam for deterministic tests; production uses Redigo.
var redisDialContext = redis.DialContext

func NewPool() *redis.Pool {
	config := redisPoolConfig{REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB}
	redisPoolState.Lock()
	defer redisPoolState.Unlock()
	if redisPoolState.pool != nil && redisPoolState.config == config {
		return redisPoolState.pool
	}
	// Tests and embedders may switch the configuration between uses. Closing
	// the prior pool also ensures an idle connection cannot cross databases.
	if redisPoolState.pool != nil {
		_ = redisPoolState.pool.Close()
	}
	pool := &redis.Pool{
		MaxIdle:         8,
		MaxActive:       redisMaxActive,
		Wait:            false,
		IdleTimeout:     time.Minute,
		MaxConnLifetime: time.Hour,
		DialContext: func(ctx context.Context) (redis.Conn, error) {
			db, err := strconv.Atoi(config.database)
			if err != nil || db < 0 {
				return nil, fmt.Errorf("Invalid Redis database")
			}
			opts := []redis.DialOption{
				redis.DialConnectTimeout(3 * time.Second),
				redis.DialReadTimeout(5 * time.Second),
				redis.DialWriteTimeout(5 * time.Second),
				redis.DialDatabase(db),
			}
			if config.password != "" {
				opts = append(opts, redis.DialPassword(config.password))
			}
			// Redigo closes the underlying connection on AUTH or SELECT failure.
			return redisDialContext(ctx, "tcp", net.JoinHostPort(config.host, config.port), opts...)
		},
	}
	redisPoolState.config = config
	redisPoolState.pool = pool
	return pool
}

// CloseRedisPool closes idle connections and marks borrowed ones for closing
// when returned. It is safe to call even when no pool has been initialized.
func CloseRedisPool() error {
	redisPoolState.Lock()
	defer redisPoolState.Unlock()
	if redisPoolState.pool == nil {
		return nil
	}
	err := redisPoolState.pool.Close()
	redisPoolState.pool = nil
	redisPoolState.config = redisPoolConfig{}
	return err
}

// Ping tests connectivity for redis (PONG should be returned).
func Ping(c redis.Conn) bool {
	// Send PING command to Redis.
	pong, err := redis.String(c.Do("PING"))
	if err != nil {
		return false
	}

	if pong == "PONG" {
		return true
	} else {
		return false
	}
}
