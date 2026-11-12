package utils

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
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
				return nil, fmt.Errorf("invalid Redis database")
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

	log.Infof("PING Response = %s\n", pong)
	// Output: PONG

	if pong == "PONG" {
		return true
	} else {
		return false
	}
}

/** listenPubSubChannels listens for messages on Redis pubsub channels.
* onStart function is called after the channels are subscribed.
* onMessage function is called for each message.
**/
func listenPubSubChannels(ctx context.Context, redisServerAddr string,
	onStart func() error,
	onMessage func(channel string, data []byte) error,
	channels ...string) error {

	// A ping is set to the server with this period to test for the health of
	// the connection and server.
	const healthCheckPeriod = time.Minute
	c, err := redis.Dial("tcp", redisServerAddr,
		// Read timeout on server should be greater than ping period.
		redis.DialReadTimeout(healthCheckPeriod+10*time.Second),
		redis.DialWriteTimeout(10*time.Second))

	if err != nil {
		return err
	}
	defer c.Close()

	psc := redis.PubSubConn{Conn: c}

	if err := psc.Subscribe(redis.Args{}.AddFlat(channels)...); err != nil {
		log.Printf("Error from subscribe redis channels : %s", err)
		return err
	}

	done := make(chan error, 1)
	/**
	 * Start a goroutine : to receive notifications from the server.
	**/
	go func() {
		for {
			switch v := psc.Receive().(type) {

			case error:
				done <- v
				return

			case redis.Message:
				log.Debugf("Message from redis %s %s \n", string(v.Data), v.Channel)
				if err := onMessage(v.Channel, v.Data); err != nil {
					done <- err
					return
				}

			case redis.Subscription:
				log.Debugf("Redis subscription: channel=%s kind=%s count=%d\n", v.Channel, v.Kind, v.Count)
				switch v.Count {
				case len(channels):
					// Notify application when all channels are subscribed.
					if err := onStart(); err != nil {
						done <- err
						return
					}
				case 0:
					// Return from the goroutine when all channels are unsubscribed.
					done <- nil
					return
				}
			}
		}
	}()

	ticker := time.NewTicker(healthCheckPeriod)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-ticker.C:
			// Send ping to test health of connection and server. If
			// corresponding pong is not received, then receive on the
			// connection will timeout and the receive goroutine will exit.
			if err = psc.Ping(""); err != nil {
				break loop
			}
		case <-ctx.Done():
			break loop
		case err := <-done:
			// Return error from the receive goroutine.
			return err
		}
	}

	// Signal the receiving goroutine to exit by unsubscribing from all channels.
	if err := psc.Unsubscribe(); err != nil {
		return err
	}

	// Wait for goroutine to complete.
	return <-done
}
