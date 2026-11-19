package utils

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fernet/fernet-go"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/labstack/echo/v5"
)

// A session permits bounded continuation of one already reserved download.
// It never outlives the file's metadata, and every continuation checks that
// metadata again. The cookie is the only place containing the encryption key.
const maxDownloadTimeoutSeconds = 24 * 60 * 60
const maxDownloadSessionRequests = 32
const maxExactSessionBytes = int64(1 << 53)

// All workers use Redis time for stored deadlines. Neither a worker clock
// change nor a later adjustment to a share's TTL can extend authorization.
const sessionClockLua = `local function nowMillis()
  local clock = redis.call('TIME')
  return tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
end
`

var createDownloadSessionScript = redis.NewScript(2, `
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1001 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return 0 end
local index = redis.call('HGET', KEYS[1], 'download_sessions') or ''
if string.len(index) >= 6500 then return redis.error_reply('session limit reached') end
-- Bound new continuations independently of their requested duration, and
-- never allow a session to outlive the parent share.
local duration = math.min(ttl - 1, tonumber(ARGV[3]) * 1000)
local probe = redis.pcall('PEXPIRE', KEYS[2], duration)
if type(probe) == 'table' and probe.err then return probe end
local cleanup = redis.pcall('DEL', KEYS[2])
if type(cleanup) == 'table' and cleanup.err then return cleanup end
local created = redis.pcall('HSET', KEYS[2], 'secret', ARGV[2], 'requests', 0, 'used', 0, 'limit', ARGV[4], 'session_version', '2')
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

var inspectDownloadSessionScript = redis.NewScript(2, sessionClockLua+`
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return nil end
if redis.call('TTL', KEYS[2]) < 0 then return nil end
local version = redis.call('HGET', KEYS[2], 'session_version')
if version ~= '2' and version ~= '3' then return nil end
if ARGV[3] ~= '' and ARGV[3] ~= version then return nil end
local secret = redis.call('HGET', KEYS[2], 'secret')
local count = tonumber(redis.call('HGET', KEYS[2], 'requests'))
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
if not secret or not count or not used or not limit then return nil end
local retryOwner = redis.call('HGET', KEYS[2], 'gap_retry_owner')
if retryOwner and redis.call('HEXISTS', KEYS[2], retryOwner) == 1 then return nil end
local full = ARGV[4] == '1'
local started = redis.call('HGET', KEYS[2], 'initial_started')
local initial = full and version == '3' and started == '0'
local restart = full and not initial
local changes
if initial then
  changes = {'initial_started', '1'}
else
  if version == '3' and started ~= '1' then return nil end
  if count >= tonumber(ARGV[2]) or used >= limit then return nil end
  changes = {'requests', count + 1}
  if restart then
    -- A plain GET has no offset. Reserve the entire continuation budget
    -- together with the exclusive claim before decrypting or writing.
    if version ~= '3' or used ~= 0 or redis.call('HGET', KEYS[2], 'restart_available') ~= '1' or
       redis.call('HGET', KEYS[2], 'active') ~= '0' or redis.call('HGET', KEYS[2], 'complete') ~= '0' or
       redis.call('HGET', KEYS[2], 'unsafe') ~= '0' then return nil end
    changes = {'requests', count + 1, 'restart_available', '0', 'used', redis.call('HGET', KEYS[2], 'limit')}
  end
end
local tracked = redis.call('HGET', KEYS[2], 'tracking') == '1' and ARGV[5] ~= ''
if version == '3' and redis.call('HGET', KEYS[2], 'tracking') ~= '1' then return nil end
local resume = tonumber(redis.call('HGET', KEYS[2], 'resume_seconds')) or 0
if resume > 0 then
  -- A preparation can hold the record while opening the archive, but it
  -- cannot authorize another request beyond the last valid idle deadline.
  local now = nowMillis()
  local absolute = tonumber(redis.call('HGET', KEYS[2], 'absolute_deadline'))
  local idle = tonumber(redis.call('HGET', KEYS[2], 'idle_deadline'))
  if not tracked or not absolute or not idle or now >= math.min(absolute, idle) then return nil end
  local lease = math.min(redis.call('PTTL', KEYS[1]), absolute - now, resume * 1000)
  if lease < 1 then return nil end
  redis.call('PEXPIRE', KEYS[2], lease)
end
local record = redis.call('HGETALL', KEYS[1])
local retry = false
if tracked then
  local active = tonumber(redis.call('HGET', KEYS[2], 'active'))
  if not active or active < 0 or redis.call('HEXISTS', KEYS[1], ARGV[5]) ~= 0 or
     redis.call('HEXISTS', KEYS[2], ARGV[5]) ~= 0 then return nil end
  -- The parent marker survives expiry during a slow write. Record it first
  -- so a Redis failure remains conservative about deleting the archive.
  redis.call('HSET', KEYS[1], ARGV[5], '1')
  table.insert(changes, 'active')
  table.insert(changes, active + 1)
  table.insert(changes, ARGV[5])
  table.insert(changes, '1')
  -- Only the immediately following admitted request may reclaim a verified
  -- pre-header failure. Any other admission advances count past this marker.
  retry = not full and active == 0 and ARGV[6] ~= '' and
    tonumber(redis.call('HGET', KEYS[2], 'gap_retry_after')) == count and
    redis.call('HGET', KEYS[2], 'gap_retry_request') == ARGV[6]
  if retry then
    table.insert(changes, 'gap_retry_owner')
    table.insert(changes, ARGV[5])
  end
end
redis.call('HSET', KEYS[2], unpack(changes))
local prefix = 0
if tracked and not full and (count == 1 or retry) then
  prefix = tonumber(redis.call('HGET', KEYS[2], 'interrupted_prefix')) or 0
end
return {record, ttl, secret, limit, tracked and 1 or 0, resume, restart and 1 or 0, prefix}
`)

// The preview authenticates a continuation without incrementing its request
// count. KDF admission must happen before the consuming transition above, so
// temporary overload does not spend one of the client's bounded resume tries.
var previewDownloadSessionScript = redis.NewScript(2, sessionClockLua+`
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return nil end
local version = redis.call('HGET', KEYS[2], 'session_version')
if redis.call('TTL', KEYS[2]) < 0 or (version ~= '2' and version ~= '3') then return nil end
local secret = redis.call('HGET', KEYS[2], 'secret')
local count = tonumber(redis.call('HGET', KEYS[2], 'requests'))
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local limit = tonumber(redis.call('HGET', KEYS[2], 'limit'))
if not secret or not count or not used or not limit then return nil end
local idle = redis.call('HGET', KEYS[2], 'idle_deadline')
if idle and nowMillis() >= tonumber(idle) then return nil end
local pending = version == '3' and redis.call('HGET', KEYS[2], 'initial_started') == '0'
if not pending and (count >= tonumber(ARGV[2]) or used >= limit) then return nil end
return {redis.call('HGETALL', KEYS[1]), secret}
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

// A second open-ended retry may describe bytes the server never wrote. When
// the first two interrupted responses form one verified prefix, charge their
// combined bytes to the initial allowance and reserve one full replacement.
var restartDownloadGapScript = redis.NewScript(2, sessionClockLua+`
if redis.call('PTTL', KEYS[1]) <= 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] or
   redis.call('PTTL', KEYS[2]) <= 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] or
   redis.call('HGET', KEYS[2], ARGV[3]) ~= '1' then return -1 end
local now = nowMillis()
if now >= tonumber(redis.call('HGET', KEYS[2], 'absolute_deadline')) or
   now >= tonumber(redis.call('HGET', KEYS[2], 'idle_deadline')) then return -1 end
local count = tonumber(redis.call('HGET', KEYS[2], 'requests'))
local owner = redis.call('HGET', KEYS[2], 'gap_retry_owner') == ARGV[3]
local retry = owner and
  tonumber(redis.call('HGET', KEYS[2], 'gap_retry_after')) == count-1 and
  redis.call('HGET', KEYS[2], 'gap_retry_request') == ARGV[6]
local first = count == 2 and redis.call('HGET', KEYS[2], 'restart_available') == '1'
if (not first and not retry) or redis.call('HGET', KEYS[2], 'active') ~= '1' or
   redis.call('HGET', KEYS[2], 'complete') ~= '0' or redis.call('HGET', KEYS[2], 'unsafe') ~= '0' then return owner and -1 or 0 end
local size = tonumber(redis.call('HGET', KEYS[2], 'limit'))
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local initial = tonumber(redis.call('HGET', KEYS[2], 'initial_written'))
local prefix = tonumber(redis.call('HGET', KEYS[2], 'interrupted_prefix'))
local previous = tonumber(redis.call('HGET', KEYS[2], 'first_range_written'))
local start, reserved = tonumber(ARGV[4]), tonumber(ARGV[5])
if not initial or not prefix or not previous or initial <= 0 or initial >= prefix or prefix >= size or prefix >= start or
   previous <= 0 or previous > size-initial or reserved ~= math.max(0, size-start) or used-reserved ~= previous then return owner and -1 or 0 end
redis.call('HSET', KEYS[2], 'used', redis.call('HGET', KEYS[2], 'limit'), 'restart_available', '0',
  'gap_idle_before', redis.call('HGET', KEYS[2], 'idle_deadline'), 'gap_promoted_owner', ARGV[3])
return 1
`)

var refundDownloadBytesScript = redis.NewScript(2, `
if redis.call('TTL', KEYS[1]) < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
if redis.call('TTL', KEYS[2]) < 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return 0 end
-- Even if the promotion reply was lost, only its exclusive finalizer can
-- refund this reservation. Ordinary ranges retain their usual refund.
if ARGV[4] ~= '' and redis.call('HGET', KEYS[2], 'gap_promoted_owner') == ARGV[4] then return 0 end
local used = tonumber(redis.call('HGET', KEYS[2], 'used'))
local amount = tonumber(ARGV[3])
if not used or not amount or amount < 0 or amount > used then return 0 end
redis.call('HINCRBY', KEYS[2], 'used', -amount)
return 1
`)

// DownloadSession identifies a previously authenticated continuation. Its
// unexported fields prevent callers from fabricating a Redis reservation.
type DownloadSession struct {
	fileKey, sessionKey       string
	token, encrypted          []byte
	size                      int64
	resumeSeconds             int
	archiveID                 string
	tracked, initial, restart bool
	progressField             string
	validatedOpenRange        bool
	interruptedPrefix         int64
	rangeIdentity             string
}

func (s *DownloadSession) Size() int64 { return s.size }

// IsInitialGET reports whether this operation starts the view reserved by the POST.
func (s *DownloadSession) IsInitialGET() bool { return s.initial }

// HasInterruptedRangeGap allows a valid but unsatisfiable open-ended range to
// reach representation validation only when the session recorded both cuts.
func (s *DownloadSession) HasInterruptedRangeGap(start int64) bool {
	return s.interruptedPrefix > 0 && start > s.interruptedPrefix
}

// ValidateOpenRange is called only for a dedicated GET with a matching
// explicit validator. A true result transfers its range reservation to the
// exclusive full-response finalizer.
func (s *DownloadSession) ValidateOpenRange(start, reserved int64) (bool, error) {
	s.validatedOpenRange = true
	if !s.HasInterruptedRangeGap(start) {
		return false, nil
	}
	c := NewPool().Get()
	defer c.Close()
	promoted, err := redis.Int(restartDownloadGapScript.Do(c, s.fileKey, s.sessionKey, s.token, s.encrypted, s.progressField, start, reserved, s.rangeIdentity))
	if err != nil {
		return false, err
	}
	if promoted < 0 {
		return false, errExpiredDownloadLease
	}
	if promoted == 0 {
		return false, nil
	}
	s.validatedOpenRange = false
	return true, nil
}

// Old deployments may already specify the session limit as a Go duration.
// New configurations use whole seconds for both settings.
func downloadTimeoutSeconds(name string, fallback int, allowDuration bool) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	if n, err := strconv.ParseUint(value, 10, 64); err == nil && n > 0 {
		if n > maxDownloadTimeoutSeconds {
			return maxDownloadTimeoutSeconds, nil
		}
		return int(n), nil
	}
	if allowDuration {
		if d, err := time.ParseDuration(value); err == nil && d >= time.Second {
			return int(min(d/time.Second, maxDownloadTimeoutSeconds)), nil
		}
	}
	return 0, errors.New("Invalid " + name)
}

func downloadTimeouts() (int, int, error) {
	session, err := downloadTimeoutSeconds("OKURU_DOWNLOAD_SESSION_TIMEOUT", 900, true)
	if err != nil {
		return 0, 0, err
	}
	resume, err := downloadTimeoutSeconds("OKURU_DOWNLOAD_RESUME_TIMEOUT", 300, false)
	return session, resume, err
}

// ValidateDownloadTimeouts rejects invalid settings before reserving a view.
func ValidateDownloadTimeouts() error {
	_, _, err := downloadTimeouts()
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
		return "", 0, errors.New("Invalid download session")
	}
	absolute, resume, err := downloadTimeouts()
	if err != nil {
		return "", 0, err
	}
	var key fernet.Key
	if err := key.Generate(); err != nil {
		return "", 0, errors.New("Cannot create download session")
	}
	ciphertext, err := fernet.EncryptAndSign([]byte(secret), &key)
	if err != nil {
		return "", 0, errors.New("Cannot create download session")
	}
	cookie := key.Encode()
	c := NewPool().Get()
	defer c.Close()
	duration, err := redis.Int(createDownloadSessionScript.Do(c, REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie), f.Token, ciphertext, min(absolute, resume), size, downloadSessionDigest(cookie)))
	if err != nil || duration < 1 {
		return "", 0, errors.New("Cannot create download session")
	}
	return cookie, duration, nil
}

// Redigo records failed pool checkouts and broken connections in Conn.Err.
// A nil Redis reply or invalid stored data leaves the connection usable.
func downloadRedisFailure(c redis.Conn) *echo.HTTPError {
	status := http.StatusNotFound
	if c.Err() != nil {
		status = http.StatusServiceUnavailable
	}
	return echo.NewHTTPError(status, http.StatusText(status))
}

func authenticatedDownloadToken(c redis.Conn, fileKey, linkKey string) ([]byte, *echo.HTTPError) {
	if len(linkKey) > hex.EncodedLen(len(fernet.Key{})) {
		return nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	keys, err := fernet.DecodeKeys(linkKey)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	token, err := redis.Bytes(c.Do("HGET", fileKey, "token"))
	if err != nil {
		return nil, downloadRedisFailure(c)
	}
	if fernet.VerifyAndDecrypt(token, 0, keys) == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	return token, nil
}

// PreviewDownloadSession authenticates the bearer and session cookie while
// leaving request and byte counters untouched. It must not replace the atomic
// consuming check in ResumeFileDownload, which remains authoritative.
func PreviewDownloadSession(f *models.File, cookie string) *echo.HTTPError {
	id, linkKey, err := ParseToken(f.FileKey)
	if err != nil || !validDownloadSessionCookie(cookie) {
		return echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	c := NewPool().Get()
	defer c.Close()
	fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
	token, fault := authenticatedDownloadToken(c, fileKey, linkKey)
	if fault != nil {
		return fault
	}
	reply, err := redis.Values(previewDownloadSessionScript.Do(c, fileKey, sessionKey, token, maxDownloadSessionRequests))
	if err != nil {
		return downloadRedisFailure(c)
	}
	var record []interface{}
	var encrypted []byte
	if _, err := redis.Scan(reply, &record, &encrypted); err != nil || redis.ScanStruct(record, f) != nil {
		return echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	keys, err := fernet.DecodeKeys(cookie)
	if err != nil || fernet.VerifyAndDecrypt(encrypted, 0, keys) == nil {
		return echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	return nil
}

// ResumeFileDownload takes one bounded continuation attempt without tracking
// its coverage. HTTP handlers use the tracked entry points below.
func ResumeFileDownload(f *models.File, cookie string) (string, *DownloadSession, *echo.HTTPError) {
	return admitFileDownload(f, cookie, "", false, false, "")
}

// ResumeTrackedFileDownload accepts a Range on the original share URL for a
// session issued before the POST-to-GET handoff was introduced.
func ResumeTrackedFileDownload(f *models.File, cookie string) (string, *DownloadSession, *echo.HTTPError) {
	return admitFileDownload(f, cookie, "2", false, true, "")
}

// StartTrackedFileDownload claims the initial full GET or a single budgeted
// full restart after its interruption. Neither operation reserves another view.
func StartTrackedFileDownload(f *models.File, cookie string) (string, *DownloadSession, *echo.HTTPError) {
	return admitFileDownload(f, cookie, "3", true, true, "")
}

// ResumeStartedFileDownload takes a bounded Range attempt from a session
// whose initial GET has already started.
func ResumeStartedFileDownload(f *models.File, cookie string) (string, *DownloadSession, *echo.HTTPError) {
	return admitFileDownload(f, cookie, "3", false, true, "")
}

// ResumeStartedFileRange identifies an HTTP retry without storing its headers.
// The controller still checks the validator against the archive before streaming.
func ResumeStartedFileRange(f *models.File, cookie, byteRange, validator string) (string, *DownloadSession, *echo.HTTPError) {
	identity := ""
	if strings.HasSuffix(byteRange, "-") && validator != "" {
		identity = downloadSessionDigest(byteRange + "\x00" + validator)
	}
	return admitFileDownload(f, cookie, "3", false, true, identity)
}

func admitFileDownload(f *models.File, cookie, version string, full, track bool, rangeIdentity string) (string, *DownloadSession, *echo.HTTPError) {
	id, linkKey, err := ParseToken(f.FileKey)
	if err != nil || !validDownloadSessionCookie(cookie) {
		return "", nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	c := NewPool().Get()
	defer c.Close()
	fileKey, sessionKey := REDIS_PREFIX+"file_"+id, downloadSessionKey(id, cookie)
	token, fault := authenticatedDownloadToken(c, fileKey, linkKey)
	if fault != nil {
		return "", nil, fault
	}
	var field string
	if track {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		}
		field = "operation_" + hex.EncodeToString(random[:])
	}
	reply, err := redis.Values(inspectDownloadSessionScript.Do(c, fileKey, sessionKey, token, maxDownloadSessionRequests, version, full, field, rangeIdentity))
	if err != nil {
		return "", nil, downloadRedisFailure(c)
	}
	var record []interface{}
	var ttl, resumeSeconds int
	var size, interruptedPrefix int64
	var tracked, restart bool
	var encrypted []byte
	if _, err := redis.Scan(reply, &record, &ttl, &encrypted, &size, &tracked, &resumeSeconds, &restart, &interruptedPrefix); err != nil || size < 0 || size > maxExactSessionBytes || redis.ScanStruct(record, f) != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	keys, err := fernet.DecodeKeys(cookie)
	if err != nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	secret := fernet.VerifyAndDecrypt(encrypted, 0, keys)
	if secret == nil {
		return "", nil, echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	f.TTL = ttl
	return string(secret), &DownloadSession{fileKey: fileKey, sessionKey: sessionKey, token: token, encrypted: encrypted, size: size,
		tracked: tracked, resumeSeconds: resumeSeconds, initial: full && !restart, restart: restart, archiveID: id, progressField: field, interruptedPrefix: interruptedPrefix, rangeIdentity: rangeIdentity}, nil
}

// The operation marker changes from preparation to streaming immediately
// before ZIP headers are committed. Both phases keep the record available;
// only an actual stream can extend the idle authorization for other requests.
var renewDownloadLeaseScript = redis.NewScript(2, sessionClockLua+`
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return 0 end
local phase = redis.call('HGET', KEYS[2], ARGV[3])
if phase ~= '1' and phase ~= 'streaming' then return 0 end
local now = nowMillis()
local absolute = tonumber(redis.call('HGET', KEYS[2], 'absolute_deadline'))
local resume = tonumber(redis.call('HGET', KEYS[2], 'resume_seconds'))
if not absolute or not resume then return 0 end
local lease = math.min(redis.call('PTTL', KEYS[1]), absolute - now, resume * 1000)
if lease < 1 then return 0 end
if ARGV[4] == '1' or phase == 'streaming' then
  redis.call('HSET', KEYS[2], ARGV[3], 'streaming', 'idle_deadline', now + lease)
end
return redis.call('PEXPIRE', KEYS[2], lease)
`)

var errExpiredDownloadLease = errors.New("Download session no longer available")

func (s *DownloadSession) renewLease(ctx context.Context, startStreaming bool) error {
	c, err := NewPool().GetContext(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	ok, err := redis.Bool(renewDownloadLeaseScript.DoContext(ctx, c, s.fileKey, s.sessionKey, s.token, s.encrypted, s.progressField, startStreaming))
	if err != nil {
		return err
	}
	if !ok {
		return errExpiredDownloadLease
	}
	return nil
}

// MarkDownloadStreaming starts the idle window only after archive validation.
func (s *DownloadSession) MarkDownloadStreaming() error {
	if s == nil || s.resumeSeconds == 0 {
		return nil
	}
	return s.renewLease(context.Background(), true)
}

// KeepDownloadSessionAlive renews a live transfer within the share and
// session deadlines. A terminated worker naturally stops granting renewals.
func KeepDownloadSessionAlive(ctx context.Context, session *DownloadSession) func() {
	if session == nil || session.resumeSeconds == 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		interval := min(30*time.Second, time.Duration(session.resumeSeconds)*time.Second/3)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// An unavailable Redis cannot grant an extension. Never recreate
				// missing records; a later tick may recover before lease expiry.
				if errors.Is(session.renewLease(ctx, false), errExpiredDownloadLease) {
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// ReserveDownloadBytes atomically limits both continuation count and the
// aggregate bytes reserved across concurrent requests to one archive size.
func ReserveDownloadBytes(s *DownloadSession, n int64) *echo.HTTPError {
	if s == nil || n < 0 || n > maxExactSessionBytes {
		return echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	c := NewPool().Get()
	defer c.Close()
	status, err := redis.Int(reserveDownloadBytesScript.Do(c, s.fileKey, s.sessionKey, s.token, s.encrypted, n))
	if err != nil {
		return downloadRedisFailure(c)
	}
	if status < 0 {
		return echo.NewHTTPError(http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
	if status == 0 {
		return echo.NewHTTPError(http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests))
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
	_, err := refundDownloadBytesScript.Do(c, s.fileKey, s.sessionKey, s.token, s.encrypted, n, s.progressField)
	return err
}
