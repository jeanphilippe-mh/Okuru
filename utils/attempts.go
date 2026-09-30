package utils

import "github.com/gomodule/redigo/redis"

// Capture the record, validate expiry and reserve one attempt in a single Redis
// operation. Reservation happens before decryption: invalid keys count too.
var attemptScript = redis.NewScript(1, `
local key = KEYS[1]
local ttl = redis.call('TTL', key)
if ttl < 0 then return nil end
local views = tonumber(redis.call('HGET', key, 'views'))
local count = tonumber(redis.call('HGET', key, 'views_count') or '0')
if not views or count >= views then return nil end
local record = redis.call('HGETALL', key)
local next = count + 1
if next >= views and ARGV[1] == '1' then
    redis.call('DEL', key)
else
    redis.call('HSET', key, 'views_count', next)
end
return {record, views - next, ttl}
`)

func consumeAttempt(c redis.Conn, key string, deleteOnLast bool) ([]interface{}, int, int, error) {
	remove := "0"
	if deleteOnLast {
		remove = "1"
	}
	reply, err := redis.Values(attemptScript.Do(c, key, remove))
	if err != nil {
		return nil, 0, 0, err
	}
	var record []interface{}
	var remaining, ttl int
	if _, err = redis.Scan(reply, &record, &remaining, &ttl); err != nil {
		return nil, 0, 0, err
	}
	return record, remaining, ttl, nil
}
