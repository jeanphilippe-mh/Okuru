package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/labstack/echo/v4"
)

// A session permits bounded continuation of one already reserved download.
// It never outlives the file's metadata, and every continuation checks that
// metadata again. The cookie is the only place containing the encryption key.
const DownloadSessionLifetime = 4 * time.Hour
const maxDownloadSessionRequests = 32
const maxExactSessionBytes = int64(1 << 53)

var createDownloadSessionScript = redis.NewScript(2, `
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1001 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return 0 end
local index = redis.call('HGET', KEYS[1], 'download_sessions') or ''
if string.len(index) >= 6500 then return redis.error_reply('session limit reached') end
local duration = math.min(ttl - 1, tonumber(ARGV[3]) * 1000)
local probe = redis.pcall('PEXPIRE', KEYS[2], duration)
if type(probe) == 'table' and probe.err then return probe end
local cleanup = redis.pcall('DEL', KEYS[2])
if type(cleanup) == 'table' and cleanup.err then return cleanup end
local created = redis.pcall('HSET', KEYS[2], 'secret', ARGV[2], 'requests', 0, 'used', 0, 'limit', ARGV[4])
if type(created) == 'table' and created.err then return created end
local expiry = redis.pcall('PEXPIRE', KEYS[2], duration)
if expiry ~= 1 then
  redis.pcall('DEL', KEYS[2])
  return redis.error_reply('session expiry failed')
end
local indexed = redis.pcall('HSET', KEYS[1], 'download_sessions', index .. ARGV[5] .. ',')
if type(indexed) == 'table' and indexed.err then
  redis.pcall('DEL', KEYS[2])
  return indexed
end
return math.floor(duration / 1000)
`)

var inspectDownloadSessionScript = redis.NewScript(2, `
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return nil end
if redis.call('TTL', KEYS[2]) < 0 then return nil end
local secret = redis.call('HGET', KEYS[2], 'secret')
local count = tonumber(redis.call('HGET', KEYS[2], 'requests'))
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
if not secret or not count or not used or not limit then return nil end
if count >= tonumber(ARGV[2]) or used >= limit then return nil end
redis.call('HINCRBY', KEYS[2], 'requests', 1)
return {redis.call('HGETALL', KEYS[1]), ttl, secret, limit}
`)

var reserveDownloadBytesScript = redis.NewScript(2, `
if redis.call('TTL', KEYS[1]) < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return -1 end
if redis.call('TTL', KEYS[2]) < 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return -1 end
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
local amount = tonumber(ARGV[3])
if not used or not limit or not amount or amount < 0 or amount ~= math.floor(amount) then return -1 end
if amount > limit - used then return 0 end
redis.call('HINCRBY', KEYS[2], 'used', amount)
return 1
`)

var refundDownloadBytesScript = redis.NewScript(2, `
if redis.call('TTL', KEYS[1]) < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
if redis.call('TTL', KEYS[2]) < 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return 0 end
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local amount = tonumber(ARGV[3])
if not used or not amount or amount < 0 or amount > used then return 0 end
redis.call('HINCRBY', KEYS[2], 'used', -amount)
return 1
`)

// DownloadSession identifies a previously authenticated continuation. Its
// unexported fields prevent callers from fabricating a Redis reservation.
type DownloadSession struct {
	fileKey, sessionKey string
	token, encrypted    []byte
	size                int64
}

func (s *DownloadSession) Size() int64 { return s.size }

func downloadSessionSeconds() (int, error) {
	value := os.Getenv("OKURU_DOWNLOAD_SESSION_TIMEOUT")
	if value == "" {
		return int(DownloadSessionLifetime / time.Second), nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < time.Second || d > 30*24*time.Hour {
		return 0, errors.New("invalid download session timeout")
	}
	return int(d / time.Second), nil
}

// ValidateDownloadSessionTimeout allows rejecting a bad operator setting
// before consuming one of a share's allowed views.
func ValidateDownloadSessionTimeout() error {
	_, err := downloadSessionSeconds()
	return err
}

func downloadSessionDigest(cookie string) string {
	digest := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(digest[:])
}

func downloadSessionKey(fileID, cookie string) string {
	return REDIS_PREFIX + "download_session_" + fileID + "_" + downloadSessionDigest(cookie)
}

func validDownloadSessionCookie(value string) bool {
	if len(value) != 44 {
		return false
	}
	keys, err := fernet.DecodeKeys(value)
	return err == nil && len(keys) == 1 && keys[0].Encode() == value
}

// CreateDownloadSession saves an encrypted archive secret under a fresh key.
// The caller must only invoke it after successfully authenticating both the
// share link and any user-supplied password, and after reserving a view.
func CreateDownloadSession(f *models.File, secret string, size int64) (string, int, error) {
	id, _, err := ParseToken(f.FileKey)
	if err != nil || len(f.Token) == 0 || len(secret) > MaxSecretBytes || size < 0 || size > maxExactSessionBytes {
		return "", 0, errors.New("invalid download session")
	}
	seconds, err := downloadSessionSeconds()
	if err != nil {
		return "", 0, err
	}
	var key fernet.Key
	if err := key.Generate(); err != nil {
		return "", 0, errors.New("cannot create download session")
	}
	ciphertext, err := fernet.EncryptAndSign([]byte(secret), &key)
	if err != nil {
		return "", 0, errors.New("cannot create download session")
	}
	cookie := key.Encode()
	c := NewPool().Get()
	defer c.Close()
	duration, err := redis.Int(createDownloadSessionScript.Do(c, REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie), f.Token, ciphertext, seconds, size, downloadSessionDigest(cookie)))
	if err != nil || duration < 1 {
		return "", 0, errors.New("cannot create download session")
	}
	return cookie, duration, nil
}

// ResumeFileDownload authenticates the link again and atomically checks both
// records, increments the bounded retry count, and obtains the session secret.
func ResumeFileDownload(f *models.File, cookie string) (string, *DownloadSession, *echo.HTTPError) {
	id, linkKey, err := ParseToken(f.FileKey)
	if err != nil || !validDownloadSessionCookie(cookie) {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	c := NewPool().Get()
	defer c.Close()
	token, err := redis.Bytes(c.Do("HGET", REDIS_PREFIX+"file_"+id, "token"))
	if err != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	if _, err := Decrypt(token, linkKey, 0); err != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
	reply, err := redis.Values(inspectDownloadSessionScript.Do(c, fileKey, sessionKey, token, maxDownloadSessionRequests))
	if err != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	var record []interface{}
	var ttl int
	var size int64
	var encrypted []byte
	if _, err := redis.Scan(reply, &record, &ttl, &encrypted, &size); err != nil || size < 0 || size > maxExactSessionBytes || redis.ScanStruct(record, f) != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	keys, err := fernet.DecodeKeys(cookie)
	if err != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	secret := fernet.VerifyAndDecrypt(encrypted, 0, keys)
	if secret == nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	f.TTL = ttl
	return string(secret), &DownloadSession{fileKey: fileKey, sessionKey: sessionKey, token: token, encrypted: encrypted, size: size}, nil
}

// ReserveDownloadBytes atomically limits both continuation count and the
// aggregate bytes reserved across concurrent requests to one archive size.
func ReserveDownloadBytes(s *DownloadSession, n int64) *echo.HTTPError {
	if s == nil || n < 0 || n > maxExactSessionBytes {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	c := NewPool().Get()
	defer c.Close()
	status, err := redis.Int(reserveDownloadBytesScript.Do(c, s.fileKey, s.sessionKey, s.token, s.encrypted, n))
	if err != nil || status < 0 {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	if status == 0 {
		return echo.NewHTTPError(http.StatusTooManyRequests)
	}
	return nil
}

// RefundDownloadBytes returns only the portion reserved but not written. A
// crash may leave a reservation charged, deliberately failing closed.
func RefundDownloadBytes(s *DownloadSession, n int64) error {
	if s == nil || n <= 0 {
		return nil
	}
	c := NewPool().Get()
	defer c.Close()
	_, err := refundDownloadBytesScript.Do(c, s.fileKey, s.sessionKey, s.token, s.encrypted, n)
	return err
}
