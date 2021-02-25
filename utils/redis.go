package utils

import (
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

//https://medium.com/@gilcrest_65433/basic-redis-examples-with-go-a3348a12878e
func NewPool() *redis.Pool {
	return &redis.Pool{
		// Maximum number of idle connections in the pool.
		MaxIdle: 80,
		// max number of connections
		MaxActive: 12000,
		// Dial is an application supplied function for creating and
		// configuring a connection.
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", REDIS_HOST + ":" + REDIS_PORT)
			if err != nil {
				println("Error Redis Dial")
				panic(err.Error())
			}
			if REDIS_PASSWORD != "" {
				_, err2 := c.Do("AUTH", REDIS_PASSWORD)
				if err2 != nil {
					println("Error Redis AUTH")
					panic(err2)
				}
			}
			_, err3 := c.Do("SELECT", REDIS_DB)
			if err3 != nil {
				println("Error Redis DO SELECT")
				panic(err3)
			}

			_, err4 := c.Do("CONFIG", "SET", "notify-keyspace-events", "KEA")
			if err4 != nil {
				println("Error Redis CONFIG")
				panic(err4)
			}
			return c, err
		},
	}
}

// Ping tests connectivity for redis (PONG should be returned)
func Ping(c redis.Conn) bool {
	// Send PING command to Redis
	pong, err := redis.String(c.Do("PING"))
	if err != nil {
		return false
	}

	log.Info("PING Response = %s\n", pong)
	// Output: PONG

	if pong == "PONG" {
		return true
	} else {
		return false
	}
}

// listenPubSubChannels listens for messages on Redis pubsub channels. The
// onStart function is called after the channels are subscribed.
// onMessage function is called for each message.
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
