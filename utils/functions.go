package utils

import (
	"errors"
	"github.com/eraffaelli/Okuru/models"
	"github.com/fernet/fernet-go"
	"github.com/garyburd/redigo/redis"
	"github.com/google/uuid"
	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

/**
 * Return url with http or https based on NO_SSL env value
 */
func GetBaseUrl(context echo.Context) string {
	r := context.Request()
	currentURL := context.Scheme() + "://" + r.Host
	var url string
	if !NO_SSL && context.Scheme() == "http" {
		url = strings.Replace(currentURL, "http", "https", -1)
	} else {
		url = currentURL
	}
	return url
}

/**
 * Transforme TTL from form to seconds
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
 * Transforme TTL to text
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
 * Return splitted token
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
Take a password string, encrypt it with Fernet symmetric encryption and return the result (bytes), with the decryption key (bytes)
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
func SetPassword(password string, ttl int, views int, deletable bool) (string, *echo.HTTPError) {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	if Ping(c) == false {
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
	if Ping(c) == false {
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
			log.Error("GetPassword() Redis err DEL main key : %+v\n", err)
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
https://gist.github.com/pohzipohzi/a202f8fb7cc30e33176dd97a9def5aac
https://www.alexedwards.net/blog/working-with-redis
*/
func GetPassword(p *models.Password) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	if Ping(c) == false {
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

	return nil
}

/**
 * Remove a password from the redis store. If an error occur we return a not found
 */
func RemovePassword(p *models.Password) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	if Ping(c) == false {
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
		log.Error("SetPassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, p)
	if err != nil {
		log.Error("SetPassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if p.Deletable == false {
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
 * Subscribe to redis and check when a key expire then clean the associated file
 */
func CleanFileWatch() {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	if Ping(c) == false {
		log.Fatal("Can't open redis pool")
	}

	psc := redis.PubSubConn{c}
	if err := psc.PSubscribe("__keyevent@*__:expired"); err != nil {
		log.Fatal("Error from sub redis : %s", err)
	}

	for {
		switch v := psc.Receive().(type) {
		case redis.Message:
			log.Debug("Message from redis %s %s \n", string(v.Data), v.Channel)
			keyName := string(v.Data)
			keyName = strings.Replace(keyName, REDIS_PREFIX+"_file", "", -1)
			if strings.Contains(keyName, "_") {
				return
			}
			CleanFile(keyName)

		case redis.PMessage:
			log.Debug("PMessage from redis %s\n", string(v.Data))
			keyName := string(v.Data)
			//if !strings.Contains(keyName, "file") { return }
			CleanFile(keyName)

		case redis.Subscription:
			log.Debug("Message from redis subscription ok : %s %s\n", v.Kind, v.Channel)
		}
	}
}

func CleanFile(fileName string) {
	log.Debug("CleanFile fileName : %s\n", fileName)
	filePathName := FILEFOLDER + "/" + fileName + ".zip"

	err := os.Remove(filePathName)
	if err != nil {
		log.Error("Delete file remove error : %+v\n", err)
	}
}

//https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandomSequence(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
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
func SetFile(password string, ttl int, views int, deletable, provided bool, providedKey string) (string, *echo.HTTPError) { //done
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	if Ping(c) == false {
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
	if Ping(c) == false {
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
		log.Error("SetPassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, f)
	if err != nil {
		log.Error("SetPassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if string(f.Token) == "" {
		log.Error("Empty token")
		return echo.NewHTTPError(http.StatusNotFound)
	}

	password, err := Decrypt(f.Token, decryptionKey, f.TTL)
	if err != nil {
		log.Error("Error while decrypting password")
		return echo.NewHTTPError(http.StatusNotFound)
	}
	f.Password = password

	if f.ViewsCount >= f.Views {
		_, err := c.Do("DEL", REDIS_PREFIX+"file_"+storageKey)
		if err != nil {
			log.Error("SetFile() Redis err DEL main key : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
	}

	return nil
}

func GetFile(f *models.File) *echo.HTTPError {
	pool := NewPool()
	c := pool.Get()
	defer c.Close()

	storageKey, decryptionKey, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	if decryptionKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	var err2 *echo.HTTPError
	err2 = RetrieveFilePassword(f)
	if err2 != nil {
		return err2
	}

	vc := f.ViewsCount + 1
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
		log.Error("GetFile() Redis err GET file password provided value : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if vc >= f.Views {
		_, err := c.Do("DEL", REDIS_PREFIX+"file_"+storageKey)
		if err != nil {
			log.Error("GetFile() Redis err DEL main key : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
		if f.PasswordProvided {
			_, err := c.Do("DEL", REDIS_PREFIX+f.PasswordProvidedKey)
			if err != nil {
				log.Error("GetFile() Redis err DEL password provided key : %+v\n", err)
				return echo.NewHTTPError(http.StatusNotFound)
			}
		}
	} else {
		_, err := c.Do("HSET", REDIS_PREFIX+"file_"+storageKey, "views_count", vc)
		if err != nil {
			log.Error("GetFile() Redis err SET views count : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
		if f.PasswordProvided {
			_, err := c.Do("HSET", REDIS_PREFIX+f.PasswordProvidedKey, "views_count", vc)
			if err != nil {
				log.Error("GetFile() Redis err SET views count password provided error : %+v\n", err)
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
	println("RemoveFile")

	storageKey, _, err := ParseToken(f.FileKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	if storageKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	v, err := redis.Values(c.Do("HGETALL", REDIS_PREFIX+"file_"+storageKey))
	if err != nil {
		log.Error("SetPassword() Redis err set : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	err = redis.ScanStruct(v, f)
	if err != nil {
		log.Error("SetPassword() Redis err scan struct : %+v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	if f.Deletable == false {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	_, err = c.Do("DEL", REDIS_PREFIX+"file_"+storageKey)
	if err != nil {
		log.Error("DeletePassword() Redis err : %+v\n", err)
		return echo.NewHTTPError(http.StatusNotFound)
	}

	if f.PasswordProvided == true {
		_, err = c.Do("DEL", REDIS_PREFIX+f.PasswordProvidedKey)
		if err != nil {
			log.Error("DeletePassword() Redis err : %+v\n", err)
			return echo.NewHTTPError(http.StatusNotFound)
		}
	}

	CleanFile(storageKey)

	return nil
}
