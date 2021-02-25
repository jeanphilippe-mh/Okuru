package utils

import (
	"context"
	"time"
	
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
		return err
	}

	done := make(chan error, 1)

	// Start a goroutine to receive notifications from Redis.	
	for {
		switch v := psc.Receive().(type) {
			
		case error:
			done <- v
			return
		
		case redis.Message:
			log.Debug("Message from redis %s %s \n", string(v.Data), v.Channel)
			if err := onMessage(v.Channel, v.Data); err != nil {
				done <- err
				return
			}
		case redis.Subscription:
			log.Debug("Message from redis subscription ok : %s %s\n", v.Channel, v.Kind, v.Count)
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
	// Start a goroutine for CleanFileWatch.
	go func CleanFileWatch()
	
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

/**
 * Subscribe to redis and check when a key expire then clean the associated file
**/
func CleanFileWatch() {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Subscribe to Redis has been started. A periodic check will clean associated file when a File key expire /\n")
	if !Ping(c) {
		log.Printf("Can't open redis pool")
		return
	}

	psc := redis.PubSubConn{Conn: c}
	if err := psc.PSubscribe("__keyevent@*__:expired"); err != nil {
		log.Printf("Error from sub redis : %s", err)
		return
	}
	
	for {
		switch v := psc.Receive().(type) {
			
		case redis.Message:
			log.Debug("Message from redis %s %s \n", string(v.Data), v.Channel)
			keyName := string(v.Data)
			keyName = strings.ReplaceAll(keyName, REDIS_PREFIX+"file_", "")
			if strings.Contains(keyName, "_") {
				return
			}
			
			CleanFile(keyName)
			println("\n/ File key expired from Redis and associated file has been deleted from data folder /\n")

		case redis.Subscription:
			log.Debug("Message from redis subscription ok : %s %s\n", v.Channel, v.Kind)
		}
	}
}
