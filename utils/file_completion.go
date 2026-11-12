package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/labstack/echo/v4"
)

// FileDownloadClaim is an unforgeable, one-use reservation of an already
// authenticated view. A claim remains pending until a continuation session is
// created or the reservation is released after an error.
type FileDownloadClaim struct {
	fileKey string
	field   string
	token   []byte
}

// A tracked view and its pending marker are committed by one HSET. The
// tracked counter deliberately diverges from views_count if an older process
// ever reserves a view without tracking; eager cleanup then fails closed.
var claimFileDownloadScript = redis.NewScript(1, `
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return nil end
local views = tonumber(redis.call('HGET', KEYS[1], 'views'))
local count = tonumber(redis.call('HGET', KEYS[1], 'views_count') or '0')
local tracked = tonumber(redis.call('HGET', KEYS[1], 'tracked_views') or '0')
if not views or not count or not tracked or count >= views or tracked > count then return nil end
if redis.call('HEXISTS', KEYS[1], ARGV[2]) ~= 0 then return nil end
local record = redis.call('HGETALL', KEYS[1])
local next = count + 1
redis.call('HSET', KEYS[1], 'views_count', next, 'tracked_views', tracked + 1, ARGV[2], '1')
return {record, views - next, ttl}
`)

// ClaimFileDownload authenticates the share before atomically reserving a view
// and registering the pending session. A bad password is still handled by the
// controller after the reservation, as in the existing policy.
func ClaimFileDownload(f *models.File) (*FileDownloadClaim, *echo.HTTPError) {
	id, key, err := ParseToken(f.FileKey)
	if err != nil || key == "" {
		return nil, echo.NewHTTPError(http.StatusNotFound)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError)
	}
	claim := &FileDownloadClaim{fileKey: REDIS_PREFIX + "file_" + id, field: "pending_" + hex.EncodeToString(random[:])}
	c := NewPool().Get()
	defer c.Close()
	token, err := redis.Bytes(c.Do("HGET", claim.fileKey, "token"))
	if err != nil {
		if err == redis.ErrNil {
			return nil, echo.NewHTTPError(http.StatusNotFound)
		}
		return nil, echo.NewHTTPError(http.StatusInternalServerError)
	}
	password, err := Decrypt(token, key, 0)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound)
	}
	claim.token = token
	reply, err := redis.Values(claimFileDownloadScript.Do(c, claim.fileKey, token, claim.field))
	if err != nil {
		if err == redis.ErrNil {
			return nil, echo.NewHTTPError(http.StatusNotFound)
		}
		return nil, echo.NewHTTPError(http.StatusInternalServerError)
	}
	var record []interface{}
	var remaining, ttl int
	if _, err := redis.Scan(reply, &record, &remaining, &ttl); err != nil {
		return claim, echo.NewHTTPError(http.StatusInternalServerError)
	}
	if err := redis.ScanStruct(record, f); err != nil {
		return claim, echo.NewHTTPError(http.StatusInternalServerError)
	}
	f.Views, f.TTL, f.Password = remaining, ttl, password
	return claim, nil
}

var releaseFileDownloadClaimScript = redis.NewScript(1, `
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
return redis.call('HDEL', KEYS[1], ARGV[2])
`)

// ReleaseFileDownloadClaim is idempotent: successful session creation has
// already removed the pending field. Redis errors retain metadata safely.
func ReleaseFileDownloadClaim(claim *FileDownloadClaim) error {
	if claim == nil {
		return nil
	}
	if claim.fileKey == "" || claim.field == "" || len(claim.token) == 0 {
		return errors.New("Invalid file download claim")
	}
	c := NewPool().Get()
	defer c.Close()
	released, err := redis.Int(releaseFileDownloadClaimScript.Do(c, claim.fileKey, claim.token, claim.field))
	if err != nil || released == 0 {
		return err
	}
	id := strings.TrimPrefix(claim.fileKey, REDIS_PREFIX+"file_")
	if !canonicalArchiveID(id) {
		return errors.New("Invalid file download claim")
	}
	return finalizeCompletedDownload(c, id, claim.token)
}

var beginTrackedRangeScript = redis.NewScript(2, `
if redis.call('TTL', KEYS[1]) < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return -1 end
if redis.call('TTL', KEYS[2]) < 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return -1 end
if redis.call('HGET', KEYS[2], 'tracking') ~= '1' then return 0 end
local active = tonumber(redis.call('HGET', KEYS[2], 'active'))
if not active or active < 0 then return -1 end
if redis.call('HEXISTS', KEYS[2], ARGV[3]) ~= 0 then return -1 end
if redis.call('HEXISTS', KEYS[1], ARGV[3]) ~= 0 then return -1 end
-- A parent marker survives the continuation-session timeout while this
-- response is still active. A failed later HSET safely retains the marker.
redis.call('HSET', KEYS[1], ARGV[3], '1')
redis.call('HSET', KEYS[2], 'active', active + 1, ARGV[3], '1')
return 1
`)

// ResumeTrackedFileDownload starts a tracked in-flight range after the normal
// link and cookie authentication. Older sessions are handled conservatively.
func ResumeTrackedFileDownload(f *models.File, cookie string) (string, *DownloadSession, *echo.HTTPError) {
	secret, session, httpErr := ResumeFileDownload(f, cookie)
	if httpErr != nil {
		return "", nil, httpErr
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, echo.NewHTTPError(http.StatusInternalServerError)
	}
	progressField := "operation_" + hex.EncodeToString(random[:])
	c := NewPool().Get()
	defer c.Close()
	status, err := redis.Int(beginTrackedRangeScript.Do(c, session.fileKey, session.sessionKey, session.token, session.encrypted, progressField))
	if err != nil || status < 0 {
		return "", nil, echo.NewHTTPError(http.StatusNotFound)
	}
	if status == 1 {
		id, _, err := ParseToken(f.FileKey)
		if err != nil {
			return "", nil, echo.NewHTTPError(http.StatusNotFound)
		}
		session.archiveID, session.tracked, session.progressField = id, true, progressField
	}
	return secret, session, nil
}

var verifyDownloadRepresentationScript = redis.NewScript(2, `
if redis.call('TTL', KEYS[1]) < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return -1 end
if redis.call('TTL', KEYS[2]) < 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return -1 end
if redis.call('HGET', KEYS[2], 'tracking') ~= '1' then return 0 end
if redis.call('HGET', KEYS[2], 'representation') == ARGV[3] then return 1 end
redis.call('HSET', KEYS[2], 'unsafe', '1')
return 0
`)

// VerifyDownloadRepresentation prevents intervals from different archive
// versions being combined. A mismatch disables eager cleanup for the session.
func VerifyDownloadRepresentation(session *DownloadSession, rawETag string) (bool, error) {
	if session == nil || !session.tracked {
		return false, nil
	}
	c := NewPool().Get()
	defer c.Close()
	status, err := redis.Int(verifyDownloadRepresentationScript.Do(c, session.fileKey, session.sessionKey,
		session.token, session.encrypted, rawETag))
	if err != nil {
		return false, err
	}
	if status < 0 {
		return false, errors.New("Download session no longer available")
	}
	return status == 1, nil
}

// Ranges are represented as sorted disjoint half-open intervals. The bounded
// continuation count limits the representation to at most 33 intervals.
var recordDownloadProgressScript = redis.NewScript(2, `
if redis.call('TTL', KEYS[1]) < 0 or redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], ARGV[7]) ~= '1' then return 2 end
local parentSize, parentStart, parentWritten = tonumber(ARGV[8]), tonumber(ARGV[3]), tonumber(ARGV[4])
if not parentSize or not parentStart or not parentWritten or parentStart < 0 or parentWritten < 0 or
   parentStart > parentSize or parentWritten > parentSize-parentStart then return redis.error_reply('invalid progress') end
local sessionTTL = redis.call('TTL', KEYS[2])
if sessionTTL == -2 then
  -- Authorization may expire after five minutes while an already-started response
  -- is still running. A complete successful response can still be recognized;
  -- partial coverage cannot be reconstructed and remains conservative.
  if ARGV[5] == '1' and ARGV[6] == '1' and parentStart == 0 and parentWritten == parentSize then
    redis.call('HSET', KEYS[1], 'completed_download', '1')
  else
    redis.call('HSET', KEYS[1], 'completion_unverifiable', '1')
  end
  redis.call('HDEL', KEYS[1], ARGV[7])
  return 1
end
if sessionTTL < 0 or redis.call('HGET', KEYS[2], 'secret') ~= ARGV[2] then return 0 end
if redis.call('HGET', KEYS[2], 'tracking') ~= '1' then return 0 end
if redis.call('HGET', KEYS[2], ARGV[7]) ~= '1' then return redis.error_reply('operation marker missing') end
local active = tonumber(redis.call('HGET', KEYS[2], 'active'))
local size = tonumber(redis.call('HGET', KEYS[2], 'limit'))
local start, written = tonumber(ARGV[3]), tonumber(ARGV[4])
if not active or active < 1 or not size or not start or not written or
   start < 0 or written < 0 or start ~= math.floor(start) or written ~= math.floor(written) or
   start > size or written > size - start then return redis.error_reply('invalid progress') end
local encoded = redis.call('HGET', KEYS[2], 'intervals') or ''
if string.len(encoded) > 2500 then return redis.error_reply('invalid interval index') end
local intervals, rebuilt = {}, ''
for left, right in string.gmatch(encoded, '(%d+):(%d+),') do
  local a, b = tonumber(left), tonumber(right)
  if not a or not b or a < 0 or a >= b or b > size then return redis.error_reply('invalid interval') end
  intervals[#intervals+1] = {a, b}
  rebuilt = rebuilt .. left .. ':' .. right .. ','
end
if rebuilt ~= encoded or #intervals > 33 then return redis.error_reply('invalid interval index') end
if ARGV[5] == '1' and written > 0 then intervals[#intervals+1] = {start, start + written} end
table.sort(intervals, function(a,b) return a[1] < b[1] end)
local merged = {}
for _, r in ipairs(intervals) do
  local last = merged[#merged]
  if last and r[1] <= last[2] then
    if r[2] > last[2] then last[2] = r[2] end
  else
    merged[#merged+1] = {r[1], r[2]}
  end
end
if #merged > 33 then return redis.error_reply('too many intervals') end
local result = ''
for _, r in ipairs(merged) do result = result .. string.format('%.0f:%.0f,', r[1], r[2]) end
local complete = redis.call('HGET', KEYS[2], 'complete') or '0'
local unsafe = redis.call('HGET', KEYS[2], 'unsafe') or '0'
if ARGV[5] ~= '1' and written > 0 then unsafe = '1' end
if ARGV[5] == '1' and ARGV[6] == '1' and start == 0 and written == size then
  -- A fresh complete response of the validated representation replaces any
  -- earlier uncertain partial coverage for this session.
  unsafe = '0'
end
if ARGV[5] == '1' and ARGV[6] == '1' and
   ((size == 0) or (#merged == 1 and merged[1][1] == 0 and merged[1][2] == size)) then
  complete = '1'
end
-- Removing the operation first makes a replay harmless. If a subsequent HSET
-- fails, the active counter remains positive and eager cleanup fails closed.
redis.call('HDEL', KEYS[2], ARGV[7])
redis.call('HSET', KEYS[2], 'active', active - 1, 'intervals', result, 'complete', complete, 'unsafe', unsafe)
if complete == '1' and unsafe ~= '1' then redis.call('HSET', KEYS[1], 'completed_download', '1') end
redis.call('HDEL', KEYS[1], ARGV[7])
return 1
`)

// RecordDownloadProgress finishes one initial or range response. Authenticated
// bytes already written can be retained after a transport interruption, but
// completion additionally requires a successful response and full coverage.
func RecordDownloadProgress(session *DownloadSession, start, written int64, integrityOK, responseOK bool) error {
	if session == nil || !session.tracked {
		return nil
	}
	if start < 0 || written < 0 || start > session.size || written > session.size-start {
		return errors.New("Invalid download progress")
	}
	valid, success := "0", "0"
	if integrityOK {
		valid = "1"
	}
	if responseOK {
		success = "1"
	}
	c := NewPool().Get()
	defer c.Close()
	status, err := redis.Int(recordDownloadProgressScript.Do(c, session.fileKey, session.sessionKey,
		session.token, session.encrypted, strconv.FormatInt(start, 10), strconv.FormatInt(written, 10), valid, success, session.progressField,
		strconv.FormatInt(session.size, 10)))
	if err != nil {
		return err
	}
	if status != 1 && status != 2 {
		return errors.New("Download session no longer available")
	}
	return finalizeCompletedDownload(c, session.archiveID, session.token)
}

// A single DEL checks access to every related key before deleting any of
// them. Unknown legacy sessions, stale claims, and concurrent responses all
// prevent eager cleanup; ordinary expiry remains the safe fallback.
var finalizeCompletedDownloadScript = redis.NewScript(2, `
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
local views = tonumber(redis.call('HGET', KEYS[1], 'views'))
local count = tonumber(redis.call('HGET', KEYS[1], 'views_count'))
local tracked = tonumber(redis.call('HGET', KEYS[1], 'tracked_views') or '0')
if not views or not count or not tracked or views < 1 or count ~= views or tracked ~= count then return 0 end
if redis.call('HGET', KEYS[1], 'completed_download') ~= '1' then return 0 end
if redis.call('HGET', KEYS[1], 'completion_unverifiable') == '1' then return 0 end
local provided = redis.call('HGET', KEYS[1], 'provided') or '0'
if provided == 'true' then provided = '1' elseif provided == 'false' then provided = '0' end
local associated = redis.call('HGET', KEYS[1], 'provided_key') or ''
if provided ~= ARGV[2] or associated ~= ARGV[3] then return 0 end
for _, field in ipairs(redis.call('HKEYS', KEYS[1])) do
  if string.sub(field, 1, 8) == 'pending_' or string.sub(field, 1, 10) == 'operation_' then return 0 end
end
local index = redis.call('HGET', KEYS[1], 'download_sessions') or ''
if string.len(index) > 6500 then return redis.error_reply('invalid session index') end
local keys, rebuilt = {KEYS[1], KEYS[2]}, ''
for digest in string.gmatch(index, '([^,]+)') do
  if string.len(digest) ~= 64 or string.find(digest, '[^0-9a-f]') then
    return redis.error_reply('invalid session index')
  end
  rebuilt = rebuilt .. digest .. ','
  local key = ARGV[4] .. digest
  if redis.call('EXISTS', key) == 1 then
    if redis.call('HGET', key, 'tracking') ~= '1' or redis.call('HGET', key, 'complete') ~= '1' or
       redis.call('HGET', key, 'active') ~= '0' or redis.call('HGET', key, 'unsafe') == '1' then return 0 end
    for _, field in ipairs(redis.call('HKEYS', key)) do
      if string.sub(field, 1, 10) == 'operation_' then return 0 end
    end
  end
  keys[#keys+1] = key
end
if rebuilt ~= index then return redis.error_reply('invalid session index') end
redis.call('DEL', unpack(keys))
return 1
`)

func finalizeCompletedDownload(c redis.Conn, id string, token []byte) error {
	if !canonicalArchiveID(id) || len(token) == 0 {
		return errors.New("Invalid completed download identifier")
	}
	fileKey := REDIS_PREFIX + "file_" + id
	fields, err := redis.StringMap(c.Do("HGETALL", fileKey))
	if err != nil {
		return err
	}
	if len(fields) == 0 || !bytes.Equal([]byte(fields["token"]), token) {
		return nil
	}
	if fields["completed_download"] != "1" || fields["tracked_views"] == "" ||
		fields["tracked_views"] != fields["views_count"] {
		return nil
	}
	provided, associated, passwordKey := "0", fields["provided_key"], fileKey
	if fields["provided"] == "1" || fields["provided"] == "true" {
		provided = "1"
		// Historical protected archives may have no separate password link.
		// A present association must still be a canonical identifier.
		if associated != "" {
			if !canonicalArchiveID(associated) {
				return errors.New("Invalid associated password identifier")
			}
			passwordKey = REDIS_PREFIX + associated
		}
	}
	removed, err := redis.Int(finalizeCompletedDownloadScript.Do(c, fileKey, passwordKey,
		token, provided, associated, REDIS_PREFIX+"download_session_"+id+"_"))
	if err != nil || removed == 0 {
		return err
	}
	return CleanFile(id)
}
