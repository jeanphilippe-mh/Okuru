package utils

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

const (
	healthProbeInterval = 5 * time.Second
	healthProbeTimeout  = 2 * time.Second
	healthFreshness     = 15 * time.Second
)

// RuntimeHealth is a local snapshot. HTTP requests never borrow a Redis
// connection or wait for a probe. Storage recovery has its own readiness gate.
type RuntimeHealth struct {
	mu           sync.RWMutex
	lastSuccess  time.Time
	storageReady bool
	diskState    archiveDiskState
	diskChecked  time.Time
	monitor      *ArchiveStorageMonitor
	running      atomic.Bool
}

func NewRuntimeHealth() *RuntimeHealth { return &RuntimeHealth{} }

func (h *RuntimeHealth) SetStorageReady(ready bool) {
	h.mu.Lock()
	h.storageReady = ready
	h.mu.Unlock()
}

func (h *RuntimeHealth) RedisReady() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.redisReadyAt(time.Now())
}

func (h *RuntimeHealth) Ready() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.availableAt(time.Now(), true)
}

// CanServe keeps reads and cleanup requests available when the original
// directory is readable but cannot accept new archive data.
func (h *RuntimeHealth) CanServe(needsArchiveSpace bool) bool {
	h.mu.RLock()
	available := h.availableAt(time.Now(), needsArchiveSpace)
	monitor := h.monitor
	h.mu.RUnlock()
	if available && needsArchiveSpace && monitor != nil {
		// An upload arriving between scheduled probes must not start on a
		// replacement mount. Disk reservations still check the exact payload.
		return monitor.acceptsArchiveWrite() && h.Ready()
	}
	return available
}

func (h *RuntimeHealth) availableAt(now time.Time, needsArchiveSpace bool) bool {
	if !h.storageReady || !h.redisReadyAt(now) || h.diskChecked.IsZero() || now.Sub(h.diskChecked) >= storageFreshness {
		return false
	}
	return h.diskState == archiveWritable || (!needsArchiveSpace && h.diskState == archiveReadable)
}

// Caller holds the lock. lastSuccess retains Go's monotonic clock reading.
func (h *RuntimeHealth) redisReadyAt(now time.Time) bool {
	return !h.lastSuccess.IsZero() && now.Sub(h.lastSuccess) < healthFreshness
}

func (h *RuntimeHealth) recordRedis(at time.Time) {
	h.mu.Lock()
	h.lastSuccess = at
	h.mu.Unlock()
}

// Run probes immediately and retries on a fixed cadence, with one outstanding
// check at most. A lost Redis connection goes back to the normal pool lifecycle.
func (h *RuntimeHealth) Run(ctx context.Context) {
	h.run(ctx, healthProbeInterval, healthProbeTimeout, probeApplicationRedis)
}

func (h *RuntimeHealth) run(ctx context.Context, interval, timeout time.Duration, probe func(context.Context) bool) {
	if !h.running.CompareAndSwap(false, true) {
		return
	}
	defer h.running.Store(false)
	defer h.recordRedis(time.Time{})
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var observed, previous bool
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, timeout)
		ok := probe(attempt)
		var success time.Time
		if ok && attempt.Err() == nil {
			success = time.Now()
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		h.recordRedis(success)
		ready := !success.IsZero()
		if !observed || ready != previous {
			entry := log.WithField("event", "health.redis_changed")
			if ready {
				entry.Info("Redis is ready for reads and writes")
			} else {
				entry.Warn("Redis is unavailable for reads or writes")
			}
			observed, previous = true, ready
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func probeApplicationRedis(ctx context.Context) bool {
	conn, err := NewPool().GetContext(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	return probeRedisConnection(ctx, conn, REDIS_PREFIX+"runtime_health_"+rand.Text())
}

// In a single script, confirm that this connection can write, read and remove
// data. NX leaves a pre-existing key untouched. If DEL is unavailable, the
// successful SET already supplied a short expiry. No exception text is logged.
const redisHealthScript = `
if not redis.call('SET', KEYS[1], 'probe', 'NX', 'PX', 10000) then return 0 end
local value = redis.pcall('GET', KEYS[1])
local removed = redis.call('DEL', KEYS[1])
if value == 'probe' and removed == 1 then return 1 end
return 0`

func probeRedisConnection(ctx context.Context, conn redis.Conn, key string) bool {
	pong, err := redis.String(redis.DoContext(conn, ctx, "PING"))
	if err != nil || pong != "PONG" {
		return false
	}
	verified, err := redis.Int(redis.DoContext(conn, ctx, "EVAL", redisHealthScript, 1, key))
	return err == nil && verified == 1
}
