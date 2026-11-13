package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gomodule/redigo/redis"
)

var ErrAdmissionUnavailable = errors.New("Admission service unavailable")

// The fixed-window counters are shared by processes using the same Redis
// database and prefix. The global budget bounds the number of fresh identity
// keys that can be allocated in a window. Hashing the identity avoids writing
// a raw address to Redis; an IPv4 hash is still pseudonymous, not anonymous.
var admissionRateScript = redis.NewScript(2, `
local perLimit = tonumber(ARGV[1])
local globalLimit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
if not perLimit or not globalLimit or not window or perLimit < 1 or globalLimit < 1 or window < 1 then
    return redis.error_reply('invalid admission limits')
end
local function readCounter(key)
    local raw = redis.call('GET', key)
    if not raw then return 0, window end
    local count = tonumber(raw)
    local ttl = redis.call('PTTL', key)
    if not count or count < 0 or count ~= math.floor(count) or ttl < 0 then
        return nil, nil
    end
    if ttl < 1 then ttl = 1 end
    return count, ttl
end
local per, perTTL = readCounter(KEYS[1])
local total, totalTTL = readCounter(KEYS[2])
if not per or not total then return redis.error_reply('invalid admission counter') end
if per >= perLimit or total >= globalLimit then return 0 end
-- Redis scripts do not roll back commands after an error. Update the global
-- budget first: if the per-client write fails, only capacity is conservatively
-- consumed until its bounded TTL. Each write sets its expiry atomically.
local globalWrite = redis.pcall('SET', KEYS[2], total + 1, 'PX', totalTTL)
if type(globalWrite) == 'table' and globalWrite.err then return globalWrite end
local perWrite = redis.pcall('SET', KEYS[1], per + 1, 'PX', perTTL)
if type(perWrite) == 'table' and perWrite.err then return perWrite end
return 1
`)

// AllowClientAction applies per-origin and global admission budgets. The
// identity is derived only from the connection and explicitly trusted proxies.
func AllowClientAction(r *http.Request, action string, perClient, global int, window time.Duration) (bool, error) {
	identity, err := ClientIdentity(r)
	if err != nil {
		return false, err
	}
	if SharedClientIdentity(identity) {
		// A proxy without independently trusted client forwarding represents all
		// visitors. Do not let one visitor exhaust a smaller per-client bucket
		// shared by everyone. The global capacity budget still applies.
		perClient = global
	}
	return AllowIdentityAction(identity, action, perClient, global, window)
}

// AllowIdentityAction is also suitable for limiting a share by its canonical
// public identifier. Callers must never pass a bearer key or secret.
func AllowIdentityAction(identity, action string, perIdentity, global int, window time.Duration) (bool, error) {
	if identity == "" || len(identity) > 128 || action == "" || len(action) > 32 || perIdentity < 1 || perIdentity > 1_000_000 || global < 1 || global > 1_000_000 || window < time.Second || window > 24*time.Hour {
		return false, ErrAdmissionUnavailable
	}
	for _, char := range action {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_') {
			return false, ErrAdmissionUnavailable
		}
	}
	digest := sha256.Sum256([]byte(identity))
	prefix := REDIS_PREFIX + "admission_" + action + "_"
	identityKey := prefix + hex.EncodeToString(digest[:])
	globalKey := prefix + "global"
	conn := NewPool().Get()
	defer conn.Close()
	if conn.Err() != nil {
		return false, ErrAdmissionUnavailable
	}
	allowed, err := redis.Int(admissionRateScript.Do(conn, identityKey, globalKey, perIdentity, global, window.Milliseconds()))
	if err != nil {
		return false, ErrAdmissionUnavailable
	}
	return allowed == 1, nil
}
