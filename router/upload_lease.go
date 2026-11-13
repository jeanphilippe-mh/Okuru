package router

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/utils"
	log "github.com/sirupsen/logrus"
)

// ErrUploadLeaseBusy signals that all upload slots for this client identity
// are occupied. Other failures must not be treated as successful reservations.
var ErrUploadLeaseBusy = errors.New("Upload already in progress")

var errUploadLeaseUnavailable = errors.New("Upload admission unavailable")

var uploadLeasePool = utils.NewPool

// The global and identity slots have independent TTLs and share a Redis
// Cluster hash slot. Both reservations are created atomically in one script.
var acquireUploadLeaseScript = redis.NewScript(8, `
local slots = tonumber(ARGV[3])
if not slots or slots < 1 or slots > 4 or slots ~= math.floor(slots) then
    return redis.error_reply('invalid upload slot count')
end
local global, client = 0, 0
for i = 1, 4 do
    if redis.call('EXISTS', KEYS[i]) == 0 then global = i; break end
end
for i = 1, slots do
    if redis.call('EXISTS', KEYS[4 + i]) == 0 then client = i; break end
end
if global == 0 or client == 0 then return 0 end
local result = redis.pcall('SET', KEYS[global], ARGV[1], 'PX', ARGV[2], 'NX')
if type(result) == 'table' and result.err then return result end
if not result then return redis.error_reply('global upload slot changed') end
result = redis.pcall('SET', KEYS[4 + client], ARGV[1], 'PX', ARGV[2], 'NX')
if type(result) == 'table' and result.err then
    redis.call('DEL', KEYS[global])
    return result
end
if not result then
    redis.call('DEL', KEYS[global])
    return redis.error_reply('client upload slot changed')
end
return global * 10 + client
`)

var releaseUploadLeaseScript = redis.NewScript(2, `
local removed = 0
for i = 1, 2 do
    if redis.call('GET', KEYS[i]) == ARGV[1] then
        removed = removed + redis.call('DEL', KEYS[i])
    end
end
return removed
`)

// acquireUploadLease reserves an upload slot across processes sharing the same
// Redis database and prefix. Four slots are shared globally. Public identities have one slot; private,
// loopback and link-local identities have four because a proxy may represent
// multiple clients. This fallback is not a per-visitor limit behind a proxy.
// The caller must supply a TTL longer than the permitted upload lifecycle and
// invoke the returned release once finished. A crash or uncertain Redis reply
// can retain the reservation until expiry; work exceeding its TTL is no longer
// protected by this lease.
func acquireUploadLease(r *http.Request, ttl time.Duration) (func(), error) {
	if r == nil || ttl < time.Millisecond {
		return nil, errUploadLeaseUnavailable
	}
	identity, err := utils.ClientIdentity(r)
	if err != nil {
		return nil, errUploadLeaseUnavailable
	}
	digest := sha256.Sum256([]byte(identity))
	keyBase := utils.REDIS_PREFIX + "upload_lease_{okuru-upload-lease}_"
	clientBase := keyBase + "client_" + hex.EncodeToString(digest[:]) + "_"
	keys := [8]string{keyBase + "global_1", keyBase + "global_2", keyBase + "global_3", keyBase + "global_4", clientBase + "1", clientBase + "2", clientBase + "3", clientBase + "4"}
	limit := 1
	if utils.SharedClientIdentity(identity) {
		limit = 4
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		return nil, errUploadLeaseUnavailable
	}
	token := hex.EncodeToString(secret[:])
	pool := uploadLeasePool()
	if pool == nil {
		return nil, errUploadLeaseUnavailable
	}
	conn, err := pool.GetContext(r.Context())
	if err != nil {
		return nil, errUploadLeaseUnavailable
	}
	defer conn.Close()
	slot, err := redis.Int(acquireUploadLeaseScript.DoContext(r.Context(), conn,
		keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6], keys[7], token, ttl.Milliseconds(), limit))
	if err != nil || slot < 0 {
		return nil, errUploadLeaseUnavailable
	}
	if slot == 0 {
		return nil, ErrUploadLeaseBusy
	}
	global, client := slot/10, slot%10
	if global < 1 || global > 4 || client < 1 || client > limit {
		return nil, errUploadLeaseUnavailable
	}
	globalKey, clientKey := keys[global-1], keys[client+3]
	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, e := pool.GetContext(ctx)
			if e != nil {
				log.Warn("Upload admission release failed; reservation will expire")
				return
			}
			defer c.Close()
			if _, e = releaseUploadLeaseScript.DoContext(ctx, c, globalKey, clientKey, token); e != nil {
				log.Warn("Upload admission release failed; reservation will expire")
			}
		})
	}, nil
}
