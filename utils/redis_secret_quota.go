package utils

import (
	"errors"
	"os"
	"strconv"
)

// ErrRedisSecretCapacity means secret creation was refused before a new key
// was written. The budget includes every key in the selected Redis database.
var ErrRedisSecretCapacity = errors.New("Redis secret creation capacity exhausted")

const (
	defaultRedisSecretMaxKeys int64 = 2048
	maxRedisLuaExactInteger   int64 = 1<<53 - 1
	maxSecretTTLSeconds             = 7 * 24 * 60 * 60
)

// redisSecretMaxKeys fails closed on malformed configuration. Redis Lua uses
// floating-point numbers, so values above its exact integer range are unsafe.
func redisSecretMaxKeys() (int64, error) {
	raw := os.Getenv("OKURU_REDIS_SECRET_MAX_KEYS")
	if raw == "" {
		return defaultRedisSecretMaxKeys, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || value > maxRedisLuaExactInteger {
		return 0, errors.New("Invalid Redis secret creation key limit")
	}
	return value, nil
}
