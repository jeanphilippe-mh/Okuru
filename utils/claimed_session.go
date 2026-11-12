package utils

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/fernet/fernet-go"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
)

// The pending marker is not removed until the new session is indexed. If an
// ACL or Redis operation fails, any remaining marker makes cleanup fail closed.
var createClaimedDownloadSessionScript = redis.NewScript(2, `
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1001 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], ARGV[6]) ~= '1' then return 0 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return 0 end
local index = redis.call('HGET', KEYS[1], 'download_sessions') or ''
if string.len(index) >= 6500 then return redis.error_reply('session limit reached') end
local duration = math.min(ttl - 1, tonumber(ARGV[3]) * 1000, 300000)
local probe = redis.pcall('PEXPIRE', KEYS[2], duration)
if type(probe) == 'table' and probe.err then return probe end
local cleanup = redis.pcall('DEL', KEYS[2])
if type(cleanup) == 'table' and cleanup.err then return cleanup end
local created = redis.pcall('HSET', KEYS[2], 'secret', ARGV[2], 'requests', 0, 'used', 0,
  'limit', ARGV[4], 'session_version', '2', 'tracking', '1', 'active', 1, 'intervals', '', 'complete', '0',
  'representation', ARGV[8], 'unsafe', '0', ARGV[7], '1')
if type(created) == 'table' and created.err then return created end
local expiry = redis.pcall('PEXPIRE', KEYS[2], duration)
if expiry ~= 1 then
  redis.pcall('DEL', KEYS[2])
  return redis.error_reply('session expiry failed')
end
local indexed = redis.pcall('HSET', KEYS[1], 'download_sessions', index .. ARGV[5] .. ',', ARGV[7], '1')
if type(indexed) == 'table' and indexed.err then
  redis.pcall('DEL', KEYS[2])
  return indexed
end
local released = redis.pcall('HDEL', KEYS[1], ARGV[6])
if type(released) == 'table' and released.err then return released end
if released ~= 1 then return redis.error_reply('pending claim changed') end
return math.floor(duration / 1000)
`)

// CreateClaimedDownloadSession converts a pending claim into a tracked initial
// response in one Redis script. The caller must finish the returned tracker.
func CreateClaimedDownloadSession(f *models.File, secret string, size int64, claim *FileDownloadClaim, representationETag string) (string, int, *DownloadSession, error) {
	id, _, err := ParseToken(f.FileKey)
	if err != nil || claim == nil || claim.fileKey != REDIS_PREFIX+"file_"+id || len(claim.token) == 0 ||
		len(f.Token) == 0 || len(secret) > MaxSecretBytes || size < 0 || size > maxExactSessionBytes {
		return "", 0, nil, errors.New("Invalid claimed download session")
	}
	if len(representationETag) != 66 || !strings.HasPrefix(representationETag, `"`) ||
		!strings.HasSuffix(representationETag, `"`) {
		return "", 0, nil, errors.New("Invalid download representation")
	}
	if _, err := hex.DecodeString(representationETag[1:65]); err != nil {
		return "", 0, nil, errors.New("Invalid download representation")
	}
	seconds, err := downloadSessionSeconds()
	if err != nil {
		return "", 0, nil, err
	}
	var key fernet.Key
	if err := key.Generate(); err != nil {
		return "", 0, nil, errors.New("Cannot create claimed download session")
	}
	ciphertext, err := fernet.EncryptAndSign([]byte(secret), &key)
	if err != nil {
		return "", 0, nil, errors.New("Cannot create claimed download session")
	}
	cookie := key.Encode()
	sessionKey := downloadSessionKey(id, cookie)
	progressField := "operation_" + strings.TrimPrefix(claim.field, "pending_")
	c := NewPool().Get()
	defer c.Close()
	duration, err := redis.Int(createClaimedDownloadSessionScript.Do(c, claim.fileKey, sessionKey,
		claim.token, ciphertext, seconds, size, downloadSessionDigest(cookie), claim.field, progressField, representationETag))
	if err != nil || duration < 1 {
		return "", 0, nil, errors.New("Cannot create claimed download session")
	}
	return cookie, duration, &DownloadSession{fileKey: claim.fileKey, sessionKey: sessionKey,
		token: claim.token, encrypted: ciphertext, size: size, archiveID: id, tracked: true, progressField: progressField}, nil
}
