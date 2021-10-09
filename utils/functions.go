package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

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
	if len(tokenFragments) != 2 {
		return "", "", errors.New("not enough token fragments")
	}
	return tokenFragments[0], tokenFragments[1], nil
}

/**
Take a password string, encrypt it with Fernet symmetric encryption and return the result (bytes), with the decryption key (bytes).
* @param password
*/
func Encrypt(password string) ([]byte, string, error) {
	var k fernet.Key
	err := k.Generate()
	if err != nil {
		log.Error("Encrypt() Generate err : %+v\n", err)
		return nil, "", err
	}

	tok, err := fernet.EncryptAndSign([]byte(password), &k)
	if err != nil {
		log.Error("Encrypt() EncryptAndSign err : %+v\n", err)
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
	message := fernet.VerifyAndDecrypt(password, time.Duration(ttl)*time.Second, k)
	return string(message), err
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

	_, err = c.Do("HMSET", REDIS_PREFIX+storageKey.String(),
		"token", encryptedPassword,
		"views", views,
		"views_count", 0,
		"deletable", deletable)
	if err != nil {
		log.Error("SetPassword() Redis err set : %+v\n", err)
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	_, err = c.Do("EXPIRE", REDIS_PREFIX+storageKey.String(), ttl)
	if err != nil {
		log.Error("SetPassword() Redis err expire : %+v\n", err)
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	return storageKey.String() + TOKEN_SEPARATOR + encryptionKey, nil
}

func RetrievePassword(p *models.Password) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password has been retrieved by a viewver /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey, decryptionKey, err := ParseToken(p.PasswordKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Error("RetrievePassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, p)
	if err != nil {
		log.Error("RetrievePassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if string(p.Token) == "" {
		log.Error("Empty token")
		return echo.NewHTTPError(http.StatusNotFound)
	}

	vc := p.ViewsCount + 1
	vcLeft := p.Views - vc
	if vcLeft <= 0 {
		vcLeft = 0
	}

	p.TTL, err = redis.Int(c.Do("TTL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Error("GetPassword() Redis err GET views count TTL : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if vc >= p.Views {
		_, err := c.Do("DEL", REDIS_PREFIX+storageKey)
		if err != nil {
			log.Error("DeletePassword() Redis err DEL main key : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
	} else {
		_, err := c.Do("HSET", REDIS_PREFIX+storageKey, "views_count", vc)
		if err != nil {
			log.Error("GetPassword() Redis err SET views count : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
	}
	p.Views = vcLeft

	password, err := Decrypt(p.Token, decryptionKey, p.TTL)
	if err != nil {
		log.Error("Error while decrypting password")
		return echo.NewHTTPError(http.StatusNotFound)
	}
	p.Password = password

	return nil
}

/*
Source: https://gist.github.com/pohzipohzi/a202f8fb7cc30e33176dd97a9def5aac.
Source: https://www.alexedwards.net/blog/working-with-redis.
*/
func GetPassword(p *models.Password) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password key was called from Redis and Secret page has been returned to a viewver /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey, decryptionKey, err := ParseToken(p.PasswordKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Error("GetPassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, p)
	if err != nil {
		log.Error("GetPassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if string(p.Token) == "" {
		log.Error("Empty token")
		return echo.NewHTTPError(http.StatusNotFound)
	}

	vc := p.ViewsCount
	vcLeft := p.Views - vc
	if vcLeft <= 0 {
		vcLeft = 0
	}

	p.TTL, err = redis.Int(c.Do("TTL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Error("GetPassword() Redis err GET views count TTL : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}
	p.Views = vcLeft

	return nil
}

/**
 * Remove a password from the Redis store. If an error occur we return a not found.
 */
func RemovePassword(p *models.Password) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Password key has been removed from Redis /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey, _, err := ParseToken(p.PasswordKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if storageKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+storageKey))
	if err != nil {
		log.Error("RemovePassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, p)
	if err != nil {
		log.Error("RemovePassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if !p.Deletable {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	_, err = c.Do("DEL", REDIS_PREFIX+storageKey)
	if err != nil {
		log.Error("DeletePassword() Redis err : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	return nil
}

/**
 * Subscribe to Redis and create a goroutine to check when a key expire then clean the associated file.
 */
func CleanFileWatch() {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ Subscribe to Redis has been started. A periodic check will clean associated file when a File Key expire /\n")

	if !Ping(c) {
		log.Printf("Error: Can't open Redis pool")
	}

	psc := redis.PubSubConn{Conn: c}

	if err := psc.PSubscribe("__keyevent@*__:expired"); err != nil {
		log.Printf("Error from subscribe Redis expired keys events : %s", err)
	}

	for {
		switch v := psc.Receive().(type) {

		case redis.Message:
			log.Debug("Message from Redis %s %s \n", string(v.Data), v.Channel)
			keyName := string(v.Data)
			keyName = strings.ReplaceAll(keyName, REDIS_PREFIX+"file_", "")
			if strings.Contains(keyName, "_") {
				return
			}

			CleanFile(keyName)
			println("\n/ File key expired from Redis and associated file has been deleted from data folder /\n")

		case redis.Subscription:
			log.Debug("Message from Redis subscription is OK : %s %s\n", v.Channel, v.Kind, v.Count)
		}
	}
}

func CleanFile(fileName string) {
	log.Debug("CleanFile fileName : %s\n", fileName)
	filePathName := FILEFOLDER + "/" + fileName + ".zip"

	err := os.Remove(filePathName)
	if err != nil {
		log.Error("CleanFile: deleting file error : %+v\n", err)
	}
}

// Source: https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
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
func SetFile(password string, ttl, views int, deletable, provided bool, providedKey string) (string, *echo.HTTPError) { //done
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File was uploaded by a user while an associated key has been stored in Redis /\n")

	if !Ping(c) {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey := uuid.New()

	encryptedPassword, encryptionKey, err := Encrypt(password)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	_, err = c.Do("HMSET", REDIS_PREFIX+"file_"+storageKey.String(),
		"token", encryptedPassword,
		"views", views,
		"views_count", 0,
		"deletable", deletable,
		"provided", provided,
		"provided_key", providedKey)

	if err != nil {
		log.Error("SetPassword() Redis err set : %+v\n", err)
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	_, err = c.Do("EXPIRE", REDIS_PREFIX+"file_"+storageKey.String(), ttl)
	if err != nil {
		log.Error("SetPassword() Redis err expire : %+v\n", err)
		return "", echo.NewHTTPError(http.StatusInternalServerError)
	}

	return storageKey.String() + TOKEN_SEPARATOR + encryptionKey, nil
}

func RetrieveFilePassword(f *models.File) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File has been downloaded by a viewver/\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey, decryptionKey, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		log.Error("RetrieveFilePassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, f)
	if err != nil {
		log.Error("RetrieveFilePassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if string(f.Token) == "" {
		log.Error("Empty token")
		return echo.NewHTTPError(http.StatusNotFound)
	}

	vc := f.ViewsCount
	vcLeft := f.Views - vc
	if vcLeft <= 0 {
		vcLeft = 0
	}

	f.TTL, err = redis.Int(c.Do("TTL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		log.Error("GetFile() Redis err GET views count TTL : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if f.ViewsCount >= f.Views {
		_, err := c.Do("DEL", REDIS_PREFIX+"file_"+storageKey)
		if err != nil {
			log.Error("DeleteFile() Redis err DEL main key : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}

		CleanFile(storageKey)

	} else {
		_, err := c.Do("HINCRBY", REDIS_PREFIX+"file_"+storageKey, "views_count", 1)
		if err != nil {
			log.Error("GetFile() Redis err HINCRBY views count : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
		if f.PasswordProvided {
			_, err := c.Do("HINCRBY", REDIS_PREFIX+f.PasswordProvidedKey, "views_count", 1)
			if err != nil {
				log.Error("GetPassword() Redis err HINCRBY views count password provided error : %+v\n", err)
				return echo.NewHTTPError(http.StatusNotFound)
			}
		}
	}

	password, err := Decrypt(f.Token, decryptionKey, f.TTL)
	if err != nil {
		log.Error("Error while decrypting password")
		return echo.NewHTTPError(http.StatusNotFound)
	}
	f.Password = password

	return nil
}

func GetFile(f *models.File) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File key was called from Redis and Secret File page has been returned to a viewver /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey, decryptionKey, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	var err2 *echo.HTTPError = RetrieveFilePassword(f)
	if err2 != nil {
		return err2
	}

	vc := f.ViewsCount
	vcLeft := f.Views - vc
	if vcLeft <= 0 {
		vcLeft = 0
	}

	f.TTL, err = redis.Int(c.Do("TTL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		log.Error("GetFile() Redis err GET views count TTL : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if f.TTL == -2 {
		log.Error("GetFile() Redis err TTL : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	f.PasswordProvided, err = redis.Bool(c.Do("HGET", REDIS_PREFIX+"file_"+storageKey, "provided"))
	if err != nil {
		log.Error("GetPassword() Redis err GET file password provided value : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if f.ViewsCount >= f.Views {
		_, err := c.Do("DEL", REDIS_PREFIX+"file_"+storageKey)
		if err != nil {
			log.Error("DeleteFile() Redis err DEL main key : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
		if f.PasswordProvided {
			_, err := c.Do("DEL", REDIS_PREFIX+f.PasswordProvidedKey)
			if err != nil {
				log.Error("DeletePassword() Redis err DEL password provided key : %+v\n", err)
				return echo.NewHTTPError(http.StatusNotFound)
			}
		}

		CleanFile(storageKey)

	} else {
		_, err := c.Do("HINCRBY", REDIS_PREFIX+"file_"+storageKey, "views_count", -1)
		if err != nil {
			log.Error("GetFile() Redis err SET views count : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
		if f.PasswordProvided {
			_, err := c.Do("HINCRBY", REDIS_PREFIX+f.PasswordProvidedKey, "views_count", -1)
			if err != nil {
				log.Error("GetPassword() Redis err SET views count password provided error : %+v\n", err)
				return echo.NewHTTPError(http.StatusNotFound)
			}
		}
	}
	f.Views = vcLeft

	password, err := Decrypt(f.Token, decryptionKey, f.TTL)
	if err != nil {
		log.Error("Error while decrypting password")
		return echo.NewHTTPError(http.StatusNotFound)
	}
	f.Password = password

	return nil
}

func RemoveFile(f *models.File) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	println("\n/ File key was removed from Redis and associated file has been deleted from data folder /\n")

	if !Ping(c) {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	storageKey, _, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if storageKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		log.Error("RemoveFile() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, f)
	if err != nil {
		log.Error("RemoveFile() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if !f.Deletable {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	_, err = c.Do("DEL", REDIS_PREFIX+"file_"+storageKey)
	if err != nil {
		log.Error("DeleteFile() Redis err : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if f.PasswordProvided {
		_, err = c.Do("DEL", REDIS_PREFIX+f.PasswordProvidedKey)
		if err != nil {
			log.Error("DeletePassword() Redis err : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
	}

	CleanFile(storageKey)

	return nil
}
