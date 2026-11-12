package utils

import (
	"errors"

	"github.com/gomodule/redigo/redis"
)

// Redis does not roll a script back when a command fails. If EXPIRE fails,
// explicitly delete the newly created record before returning an error.
var createExpiringHashScript = redis.NewScript(1, `
local ttl = tonumber(ARGV[1])
if not ttl or ttl <= 0 or ttl ~= math.floor(ttl) then
    return redis.error_reply('invalid record expiry')
end
if redis.call('EXISTS', KEYS[1]) ~= 0 then
    return redis.error_reply('record already exists')
end
-- Probe expiry against the absent key before creating any record. Besides
-- validating the TTL, this fails closed if the Redis ACL forbids EXPIRE.
local probe = redis.pcall('EXPIRE', KEYS[1], ttl)
if type(probe) == 'table' and probe.err then return probe end
if probe ~= 0 then return redis.error_reply('unexpected existing record') end
-- Deletion must also be allowed in case a later command needs rollback.
local cleanupProbe = redis.pcall('DEL', KEYS[1])
if type(cleanupProbe) == 'table' and cleanupProbe.err then return cleanupProbe end
if cleanupProbe ~= 0 then return redis.error_reply('unexpected existing record') end
local created = redis.pcall('HMSET', KEYS[1], unpack(ARGV, 2))
if type(created) == 'table' and created.err then return created end
local expired = redis.pcall('EXPIRE', KEYS[1], ttl)
if expired ~= 1 then
    local rollback = redis.pcall('DEL', KEYS[1])
    if type(rollback) == 'table' and rollback.err then
        return redis.error_reply('record expiry and cleanup failed')
    end
    return redis.error_reply('record expiry failed')
end
return 1
`)

func createExpiringHash(c redis.Conn, key string, ttl int, fields ...interface{}) error {
	if ttl <= 0 {
		return errors.New("invalid record expiry")
	}
	args := append(redis.Args{}.Add(key, ttl), fields...)
	_, err := createExpiringHashScript.Do(c, args...)
	return err
}

// Reserve an attempt only when the encrypted token is still the exact value
// authenticated by the caller. The comparison and reservation are atomic.
var attemptScript = redis.NewScript(1, `
local key = KEYS[1]
local ttl = redis.call('TTL', key)
if ttl < 0 then return nil end
if redis.call('HGET', key, 'token') ~= ARGV[2] then return nil end
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

func consumeAttempt(c redis.Conn, key string, deleteOnLast bool, authenticatedToken []byte) ([]interface{}, int, int, error) {
	remove := "0"
	if deleteOnLast {
		remove = "1"
	}
	reply, err := redis.Values(attemptScript.Do(c, key, remove, authenticatedToken))
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

// authenticateAndConsumeAttempt verifies possession of the bearer key before
// consuming a view. A wrong file password is checked separately by the caller
// after this reservation and therefore continues to count as an attempt.
func authenticateAndConsumeAttempt(c redis.Conn, key, decryptionKey string, deleteOnLast bool) ([]interface{}, int, int, string, error) {
	token, err := redis.Bytes(c.Do("HGET", key, "token"))
	if err != nil {
		return nil, 0, 0, "", err
	}
	password, err := Decrypt(token, decryptionKey, 0)
	if err != nil {
		return nil, 0, 0, "", redis.ErrNil
	}
	record, remaining, ttl, err := consumeAttempt(c, key, deleteOnLast, token)
	if err != nil {
		return nil, 0, 0, "", err
	}
	return record, remaining, ttl, password, nil
}
