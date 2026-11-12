package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fernet/fernet-go"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

/**
 * Return url with http or https based on NO_SSL env value.
 */
func GetBaseUrl(context echo.Context) string {
	r := context.Request()
	currentURL := context.Scheme() + "://" + r.Host
	var url string
	if !NO_SSL && context.Scheme() == "http" {
		url = strings.ReplaceAll(currentURL, "http", "https")
	} else {
		url = currentURL
	}
	return url
}

/**
 * Transform TTL from form to seconds.
 */
func GetTtlSeconds(ttl int) int {
	if ttl >= 1 && ttl <= 24 {
		ttl = ttl * 3600
	} else if ttl > 24 && ttl <= 30 {
		ttl = (ttl - 23) * 86400
	}
	return ttl
}

/*
 * Transform TTL to text.
 */
func GetTTLText(ttl int) (ttlText string) {
	if ttl <= 3600 {
		ttlText = "one more hour"
	} else if ttl > 3600 && ttl <= 86400 {
		cttl := ttl / 3600
		ttlText = strings.Split(strconv.Itoa(cttl), ".")[0] + " more hours"
	} else if ttl == 86400 {
		ttlText = "one more day"
	} else {
		cttl := ttl / 86400
		ttlText = strings.Split(strconv.Itoa(cttl), ".")[0] + " more days"
	}
	return
}

/*
 * Transform Views to text.
 */
func GetViewsText(ttlViews int) (viewsText string) {
	if ttlViews == 0 {
		viewsText = "0 view"
	} else if ttlViews == 1 {
		viewsText = "1 view"
	} else if ttlViews > 1 && ttlViews <= 100 {
		cttlViews := ttlViews / 1
		viewsText = strings.Split(strconv.Itoa(cttlViews), ".")[0] + " views"
	}
	return
}

/*
 * Transform Downloads to text.
 */
func GetDownloadsText(ttlViews int) (viewsDownload string) {
	if ttlViews == 0 {
		viewsDownload = "0 download"
	} else if ttlViews == 1 {
		viewsDownload = "1 download"
	} else if ttlViews > 1 && ttlViews <= 100 {
		cttlViews := ttlViews / 1
		viewsDownload = strings.Split(strconv.Itoa(cttlViews), ".")[0] + " downloads"
	}
	return
}

func GetMaxFileSizeText() string {
	size := MaxFileSize / 1024 / 1024
	var text string
	if size >= 1024 {
		text = strconv.FormatInt(size/1024, 10) + " GB"
	} else {
		text = strconv.FormatInt(size, 10) + " MB"
	}
	return text
}

/**
 * Return splitted token.
 * @param token
 */
func ParseToken(token string) (string, string, error) {
	tokenFragments := strings.Split(token, TOKEN_SEPARATOR)
	if len(tokenFragments) != 2 || tokenFragments[1] == "" {
		return "", "", errors.New("Invalid token")
	}
	// Identifiers never contain resource prefixes. In particular a password
	// route must not accept file_<UUID> and read file metadata from Redis.
	id, err := uuid.Parse(tokenFragments[0])
	if err != nil || id.String() != tokenFragments[0] {
		return "", "", errors.New("Invalid token identifier")
	}
	return id.String(), tokenFragments[1], nil
}

/*
*
Take a password string, encrypt it with Fernet symmetric encryption and return the result (bytes), with the decryption key (bytes).
* @param password
*/
func Encrypt(password string) ([]byte, string, error) {
	var k fernet.Key
	err := k.Generate()
	if err != nil {
		log.Errorf("Encrypt() Generate err : %+v\n", err)
		return nil, "", err
	}

	tok, err := fernet.EncryptAndSign([]byte(password), &k)
	if err != nil {
		log.Errorf("Encrypt() EncryptAndSign err : %+v\n", err)
		return nil, "", err
	}

	return tok, k.Encode(), err
}

/**
 * Decrypt a password (bytes) using the provided key (bytes) and return the plain-text password (bytes).
 * @param password
 * @param decryption_key
 */
func Decrypt(password []byte, decryptionKey string, ttl int) (string, error) {
	k, err := fernet.DecodeKeys(decryptionKey)
	if err != nil {
		return "", err
	}
	// Redis expiry is checked when the record is read. Its remaining TTL is
	// not the token's maximum age, which would expire it halfway through.
	message := fernet.VerifyAndDecrypt(password, 0, k)
	if message == nil {
		return "", errors.New("Invalid encrypted token")
	}
	return string(message), nil
}

/**
 * Encrypt and store the password for the specified lifetime.
 * Returns a token comprised of the key where the encrypted password is stored, and the decryption key.
 * @param {string} password
 * @param {number} ttl
 * @param {number} views
 * @param {boolean} deletable
 * @return {string, error} token, error
 */
func SetPassword(password string, ttl, views int, deletable bool) (string, *echo.HTTPError) {
	if ttl <= 0 {
		return "", echo.NewHTTPError(http.StatusBadRequest)
	}
	if err := ValidateSecretLength(password); err != nil {
		return "", echo.NewHTTPError(http.StatusRequestEntityTooLarge)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password was created by a user while an associated key has been stored in Redis /\n")

	if !Ping(c) {
		println("Ping failed")
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey := uuid.New()

	encryptedPassword, encryptionKey, err := Encrypt(password)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = createExpiringHash(c, REDIS_PREFIX+storageKey.String(), ttl,
		"token", encryptedPassword,
		"views", views,
		"views_count", 0,
		"deletable", deletable)
	if err != nil {
		log.Error("Could not create expiring password metadata")
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	return storageKey.String() + TOKEN_SEPARATOR + encryptionKey, nil
}

func RetrievePassword(p *models.Password) *echo.HTTPError {
	storageKey, decryptionKey, err := ParseToken(p.PasswordKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password has been retrieved by a viewver /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	record, remaining, ttl, password, err := authenticateAndConsumeAttempt(c, REDIS_PREFIX+storageKey, decryptionKey, true)
	if err == redis.ErrNil {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	if err = redis.ScanStruct(record, p); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	p.Views = remaining
	p.TTL = ttl

	p.Password = password

	return nil
}

/*
* Get a password from the Redis store.
Source: https://gist.github.com/pohzipohzi/a202f8fb7cc30e33176dd97a9def5aac.
Source: https://www.alexedwards.net/blog/working-with-redis.
*/
func GetPassword(p *models.Password) *echo.HTTPError {
	storageKey, decryptionKey, err := ParseToken(p.PasswordKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password key was called from Redis and Secret page has been returned to a viewver /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Errorf("GetPassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, p)
	if err != nil {
		log.Errorf("GetPassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if len(p.Token) == 0 {
		log.Error("Empty token")
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if _, err := Decrypt(p.Token, decryptionKey, 0); err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	vc := p.ViewsCount
	vcLeft := p.Views - vc
	if vcLeft <= 0 {
		vcLeft = 0
	}

	p.TTL, err = redis.Int(c.Do("TTL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Errorf("GetPassword() Redis err GET views count TTL : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}
	p.Views = vcLeft

	return nil
}

/**
 * Remove a password from the Redis store. If an error occur we return a not found.
 */
func RemovePassword(p *models.Password) *echo.HTTPError {
	storageKey, decryptionKey, err := ParseToken(p.PasswordKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if storageKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password key has been removed from Redis /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Errorf("RemovePassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, p)
	if err != nil {
		log.Errorf("RemovePassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if _, err := Decrypt(p.Token, decryptionKey, 0); err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if !p.Deletable {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	_, err = c.Do("DEL", REDIS_PREFIX+storageKey)
	if err != nil {
		log.Errorf("DeletePassword() Redis err : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	return nil
}

func CleanFile(fileName string) error {
	if !canonicalArchiveID(fileName) {
		return errors.New("Invalid archive identifier")
	}
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return err
	}
	defer guard.Close()
	filePathName := filepath.Join(FILEFOLDER, fileName+".zip")
	info, err := os.Lstat(filePathName)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("Archive is not a regular file")
	}
	if err := os.Remove(filePathName); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

/**
 * GenerateRandomString. Source: https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
 */
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[num.Int64()]
	}

	return string(b), nil
}

/**
 * Encrypt and store the password for the specified lifetime.
 * Returns a token comprised of the key where the encrypted password is stored, and the decryption key.
 * @param {string} password
 * @param {number} ttl
 * @param {number} views
 * @param {boolean} deletable
 * @return {string} token
 */
func SetFile(password string, ttl, views int, deletable, provided bool, providedKey string, archiveFormat ...string) (string, *echo.HTTPError) { //done
	if ttl <= 0 {
		return "", echo.NewHTTPError(http.StatusBadRequest)
	}
	if err := ValidateSecretLength(password); err != nil {
		return "", echo.NewHTTPError(http.StatusRequestEntityTooLarge)
	}
	if len(archiveFormat) > 1 || (len(archiveFormat) == 1 && archiveFormat[0] != ArchiveFormatAge && archiveFormat[0] != ArchiveFormatAgeUserPassword && archiveFormat[0] != ArchiveFormatAgeX25519) {
		return "", echo.NewHTTPError(http.StatusBadRequest)
	}
	format := ""
	if len(archiveFormat) == 1 {
		format = archiveFormat[0]
	}
	if format == ArchiveFormatAgeUserPassword && !canonicalArchiveID(providedKey) {
		return "", echo.NewHTTPError(http.StatusBadRequest)
	}
	if format == ArchiveFormatAgeX25519 && providedKey != "" {
		return "", echo.NewHTTPError(http.StatusBadRequest)
	}
	metadataSecret, err := fileMetadataSecret(password, provided, format)
	if err != nil {
		if errors.Is(err, errArchivePasswordRequired) || errors.Is(err, errArchiveIdentityRequired) {
			return "", echo.NewHTTPError(http.StatusBadRequest)
		}
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File was uploaded by a user while an associated key has been stored in Redis /\n")

	if !Ping(c) {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey := uuid.New()

	encryptedPassword, encryptionKey, err := Encrypt(metadataSecret)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = createExpiringHash(c, REDIS_PREFIX+"file_"+storageKey.String(), ttl,
		"token", encryptedPassword,
		"views", views,
		"views_count", 0,
		"deletable", deletable,
		"provided", provided,
		"provided_key", providedKey,
		"archive_format", format)

	if err != nil {
		log.Error("Could not create expiring file metadata")
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	return storageKey.String() + TOKEN_SEPARATOR + encryptionKey, nil
}

func RetrieveFilePassword(f *models.File) *echo.HTTPError {
	storageKey, decryptionKey, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File has been downloaded by a viewver/\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	// Keep exhausted file metadata until expiry so the last response can
	// stream its archive safely. Further reservations are rejected atomically.
	record, remaining, ttl, password, err := authenticateAndConsumeAttempt(c, REDIS_PREFIX+"file_"+storageKey, decryptionKey, false)
	if err == redis.ErrNil {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	if err = redis.ScanStruct(record, f); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	f.Views = remaining
	f.TTL = ttl

	f.Password = password

	return nil
}

func GetFile(f *models.File) *echo.HTTPError { return getFile(f, true) }

// An exhausted but unexpired archive may still be deleted with its valid key.
func GetFileForDeletion(f *models.File) *echo.HTTPError { return getFile(f, false) }

func getFile(f *models.File, requireDownloads bool) *echo.HTTPError {
	storageKey, decryptionKey, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File key was called from Redis and Secret File page has been returned to a viewver /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	// Preview is read-only: it must not reserve and then undo a download.
	record, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	if err = redis.ScanStruct(record, f); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	if len(f.Token) == 0 || (requireDownloads && f.ViewsCount >= f.Views) {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	f.TTL, err = redis.Int(c.Do("TTL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil || f.TTL < 0 {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	f.Views -= f.ViewsCount

	password, err := Decrypt(f.Token, decryptionKey, f.TTL)
	if err != nil {
		log.Error("Error while decrypting password")
		return echo.NewHTTPError(http.StatusNotFound)
	}
	f.Password = password

	return nil
}

func RemoveFile(f *models.File) *echo.HTTPError {
	storageKey, decryptionKey, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if storageKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	defer guard.Close()
	pool := NewPool()
	c := pool.Get()
	defer c.Close()

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		log.Errorf("RemoveFile() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, f)
	if err != nil {
		log.Errorf("RemoveFile() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if _, err := Decrypt(f.Token, decryptionKey, 0); err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if !f.Deletable {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	fileKey := REDIS_PREFIX + "file_" + storageKey
	passwordKey := fileKey
	if f.PasswordProvided {
		if !canonicalArchiveID(f.PasswordProvidedKey) {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}
		passwordKey = REDIS_PREFIX + f.PasswordProvidedKey
	}
	if err := deleteAuthenticatedFileMetadata(c, fileKey, passwordKey, REDIS_PREFIX+"download_session_"+storageKey+"_", f.Token, f.PasswordProvidedKey, f.PasswordProvided); err != nil {
		log.Error("Could not delete file metadata")
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	// The metadata is already gone. Reconciliation retries failed archive
	// cleanup, but a failed removal must not be reported as complete.
	if err := CleanFile(storageKey); err != nil {
		log.Error("Could not remove archive")
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	return nil
}

// DEL checks authorization for all keys before changing any of them. The
// script also ties deletion to the exact token and association authenticated.
var deleteFileMetadataScript = redis.NewScript(2, `
if redis.call('HGET', KEYS[1], 'token') ~= ARGV[1] then return 0 end
local deletable = redis.call('HGET', KEYS[1], 'deletable') or '0'
if deletable ~= '1' and deletable ~= 'true' then return 0 end
local provided = redis.call('HGET', KEYS[1], 'provided') or '0'
if provided == 'true' then provided = '1' elseif provided == 'false' then provided = '0' end
local associated = redis.call('HGET', KEYS[1], 'provided_key') or ''
if provided ~= ARGV[2] or associated ~= ARGV[3] then return 0 end
-- Validate the bounded index before deleting anything; never allow a corrupt
-- record to redirect deletion to arbitrary Redis keys.
local index = redis.call('HGET', KEYS[1], 'download_sessions') or ''
if string.len(index) > 6500 then return redis.error_reply('invalid session index') end
local keys = {KEYS[1], KEYS[2]}
local rebuilt = ''
for digest in string.gmatch(index, '([^,]+)') do
    if string.len(digest) ~= 64 or string.find(digest, '[^0-9a-f]') then
        return redis.error_reply('invalid session index')
    end
    rebuilt = rebuilt .. digest .. ','
    keys[#keys + 1] = ARGV[4] .. digest
end
if rebuilt ~= index then return redis.error_reply('invalid session index') end
-- A single DEL makes Redis check ACLs for every key before deleting any.
redis.call('DEL', unpack(keys))
return 1
`)

func deleteAuthenticatedFileMetadata(c redis.Conn, fileKey, passwordKey, sessionPrefix string, token []byte, associatedKey string, provided bool) error {
	flag := "0"
	if provided {
		flag = "1"
	}
	n, err := redis.Int(deleteFileMetadataScript.Do(c, fileKey, passwordKey, token, flag, associatedKey, sessionPrefix))
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("File metadata changed")
	}
	return nil
}
