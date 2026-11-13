package utils

import (
	"errors"
	"fmt"
	"github.com/fernet/fernet-go"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenOnlyConn detects any attempt to reserve or mutate state after an
// incorrect key. It does not contact Redis and works in offline test runs.
type tokenOnlyConn struct {
	token     []byte
	mutations int
}

func (c *tokenOnlyConn) Close() error                      { return nil }
func (c *tokenOnlyConn) Err() error                        { return nil }
func (c *tokenOnlyConn) Send(string, ...interface{}) error { return errors.New("unexpected send") }
func (c *tokenOnlyConn) Flush() error                      { return errors.New("unexpected flush") }
func (c *tokenOnlyConn) Receive() (interface{}, error)     { return nil, errors.New("unexpected receive") }
func (c *tokenOnlyConn) Do(command string, _ ...interface{}) (interface{}, error) {
	if command == "HGET" {
		return c.token, nil
	}
	c.mutations++
	return nil, errors.New("unexpected reservation")
}

func TestInvalidBearerKeyCannotReserveOffline(t *testing.T) {
	var correct, wrong fernet.Key
	if err := correct.Generate(); err != nil {
		t.Fatal(err)
	}
	if err := wrong.Generate(); err != nil {
		t.Fatal(err)
	}
	token, err := fernet.EncryptAndSign([]byte("test-secret"), &correct)
	if err != nil {
		t.Fatal(err)
	}
	c := &tokenOnlyConn{token: token}
	if _, _, _, _, err := authenticateAndConsumeAttempt(c, "test-key", wrong.Encode(), true); err != redis.ErrNil {
		t.Fatalf("wrong key was not rejected: %v", err)
	}
	if c.mutations != 0 {
		t.Fatal("wrong bearer key reached reservation")
	}
}

func TestCreateExpiringHashRejectsInvalidTTLWithoutWriting(t *testing.T) {
	c := &tokenOnlyConn{}
	if err := createExpiringHash(c, "test-key", 0, "token", "test"); err == nil {
		t.Fatal("zero TTL was accepted")
	}
	if c.mutations != 0 {
		t.Fatal("invalid TTL reached Redis")
	}
}

func TestRedisSecretKeyLimitConfigurationAndTTL(t *testing.T) {
	for _, raw := range []string{"0", "-1", "1.5", "broken", "9007199254740992"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", raw)
			if _, err := redisSecretMaxKeys(); err == nil {
				t.Fatal("invalid Redis limit was accepted")
			}
			if _, httpErr := SetPassword("secret", 60, 1, false); httpErr == nil || httpErr.Code != 503 {
				t.Fatalf("invalid capacity configuration did not fail closed: %v", httpErr)
			}
		})
	}
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "4")
	if limit, err := redisSecretMaxKeys(); err != nil || limit != 4 {
		t.Fatalf("valid Redis limit rejected: limit=%d err=%v", limit, err)
	}
	if _, httpErr := SetPassword("secret", maxSecretTTLSeconds+1, 1, false); httpErr == nil || httpErr.Code != 400 {
		t.Fatalf("secret lifetime above seven days was accepted: %v", httpErr)
	}
}

func TestRedisSecretKeyLimitIncludesLegacyAndCoordinatesCreators(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	admin, err := redis.Dial("tcp", addr, redis.DialDatabase(15))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	prefix := fmt.Sprintf("okuru_quota_test_%d_", time.Now().UnixNano())
	legacy := prefix + "legacy"
	if _, err := admin.Do("SET", legacy, "existing", "EX", 60); err != nil {
		t.Fatal(err)
	}
	keys := []interface{}{legacy, prefix + "after-expiry"}
	for i := 0; i < 24; i++ {
		keys = append(keys, fmt.Sprintf("%s%d", prefix, i))
	}
	defer func() { _, _ = admin.Do("DEL", keys...) }()
	baseline, err := redis.Int64(admin.Do("DBSIZE"))
	if err != nil {
		t.Fatal(err)
	}
	limit := baseline + 3
	var admitted, rejected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := redis.Dial("tcp", addr, redis.DialDatabase(15))
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			err = createExpiringHashWithKeyLimit(conn, fmt.Sprintf("%s%d", prefix, i), 60, limit, "token", "encrypted")
			if err == nil {
				admitted.Add(1)
			} else if errors.Is(err, ErrRedisSecretCapacity) {
				rejected.Add(1)
			} else {
				t.Errorf("unexpected creation error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if admitted.Load() != 3 || rejected.Load() != 21 {
		t.Fatalf("concurrent admissions exceeded or missed limit: admitted=%d rejected=%d", admitted.Load(), rejected.Load())
	}
	if value, err := redis.String(admin.Do("GET", legacy)); err != nil || value != "existing" {
		t.Fatalf("existing key changed: %q %v", value, err)
	}
	if _, err := admin.Do("EXPIRE", legacy, 1); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		exists, err := redis.Int(admin.Do("EXISTS", legacy))
		if err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("legacy test key did not expire")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := createExpiringHashWithKeyLimit(admin, prefix+"after-expiry", 60, limit, "token", "encrypted"); err != nil {
		t.Fatalf("expiration did not free capacity: %v", err)
	}
}

func TestRedisSecretKeyLimitFailsClosedWhenDBSizeIsDenied(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	admin, err := redis.Dial("tcp", addr, redis.DialDatabase(15))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	key, username := "okuru_secret_quota_acl_"+suffix, "okuru_secret_quota_user_"+suffix
	if _, err := admin.Do("ACL", "SETUSER", username, "on", ">temporary-test-password", "~"+key, "+@all", "-dbsize"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Do("DEL", key); _, _ = admin.Do("ACL", "DELUSER", username) }()
	conn, err := redis.Dial("tcp", addr, redis.DialUsername(username), redis.DialPassword("temporary-test-password"), redis.DialDatabase(15))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := createExpiringHashWithKeyLimit(conn, key, 60, 10000, "token", "encrypted"); err == nil {
		t.Fatal("creation succeeded without permission to inspect capacity")
	}
	if exists, err := redis.Int(admin.Do("EXISTS", key)); err != nil || exists != 0 {
		t.Fatalf("capacity permission failure left a record: exists=%d err=%v", exists, err)
	}
}

func TestRedisSecretCapacityKeepsLegacyLinksReadable(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX
	REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD = host, port, "15", ""
	REDIS_PREFIX = fmt.Sprintf("okuru_legacy_quota_%d_", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = CloseRedisPool()
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX = oldHost, oldPort, oldDB, oldPassword, oldPrefix
	})
	conn, err := redis.Dial("tcp", addr, redis.DialDatabase(15))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	id := uuid.NewString()
	storageKey := REDIS_PREFIX + id
	defer func() { _, _ = conn.Do("DEL", storageKey) }()
	encrypted, key, err := Encrypt("legacy-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Do("HSET", storageKey, "token", encrypted, "views", 1, "views_count", 0, "deletable", false); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Do("EXPIRE", storageKey, 60); err != nil {
		t.Fatal(err)
	}
	count, err := redis.Int64(conn.Do("DBSIZE"))
	if err != nil || count < 1 {
		t.Fatalf("database count: %d %v", count, err)
	}
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", strconv.FormatInt(count, 10))
	if _, httpErr := SetPassword("new-secret", 60, 1, false); httpErr == nil || httpErr.Code != 503 {
		t.Fatalf("full database did not reject new secret: %v", httpErr)
	}
	p := &models.Password{PasswordKey: id + TOKEN_SEPARATOR + key}
	if httpErr := RetrievePassword(p); httpErr != nil || p.Password != "legacy-secret" {
		t.Fatalf("legacy link stopped working at capacity: value=%q err=%v", p.Password, httpErr)
	}
}

func TestSecretCreationRejectsOversizedValuesBeforeRedis(t *testing.T) {
	oversized := strings.Repeat("x", MaxSecretBytes+1)
	if _, err := SetPassword(oversized, 60, 1, false); err == nil || err.Code != 413 {
		t.Fatalf("oversized password was not rejected before storage: %v", err)
	}
	if _, err := SetFile(oversized, 60, 1, false, true, ""); err == nil || err.Code != 413 {
		t.Fatalf("oversized file password was not rejected before storage: %v", err)
	}
}

func TestCreateExpiringHashSetsTTLAndRejectsCollision(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	key := "okuru_test_create_" + time.Now().Format("150405.000000000")
	defer func() { c.Do("DEL", key); c.Close() }()
	if err := createExpiringHash(c, key, 60, "token", "first", "views", 1); err != nil {
		t.Fatal(err)
	}
	if ttl, err := redis.Int(c.Do("TTL", key)); err != nil || ttl <= 0 || ttl > 60 {
		t.Fatalf("missing or invalid expiry: %d, %v", ttl, err)
	}
	if err := createExpiringHash(c, key, 60, "token", "replacement", "views", 1); err == nil {
		t.Fatal("existing record was overwritten")
	}
	if token, err := redis.String(c.Do("HGET", key, "token")); err != nil || token != "first" {
		t.Fatalf("existing record changed: %q, %v", token, err)
	}
}

func TestCreateExpiringHashFailsClosedWhenRequiredCommandDenied(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	admin, err := redis.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, denied := range []string{"expire", "del"} {
		t.Run(denied, func(t *testing.T) {
			suffix := time.Now().Format("150405000000000")
			key, username := "okuru_test_acl_"+suffix, "okuru_test_nocmd_"+suffix
			if _, err := admin.Do("ACL", "SETUSER", username, "on", ">temporary-test-password", "~"+key, "+@all", "-"+denied); err != nil {
				t.Fatalf("create isolated Redis ACL user: %v", err)
			}
			defer func() { admin.Do("DEL", key); admin.Do("ACL", "DELUSER", username) }()
			c, err := redis.Dial("tcp", addr, redis.DialUsername(username), redis.DialPassword("temporary-test-password"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := createExpiringHash(c, key, 60, "token", "test", "views", 1); err == nil {
				t.Fatalf("write succeeded when %s was forbidden", denied)
			}
			if exists, err := redis.Int(admin.Do("EXISTS", key)); err != nil || exists != 0 {
				t.Fatalf("failure left a record: exists=%d, err=%v", exists, err)
			}
		})
	}
}

func TestConcurrentAttemptReservation(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	for _, remove := range []bool{true, false} {
		c, err := redis.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		key := "okuru_test_attempt_" + time.Now().Format("150405.000000000")
		if _, err = c.Do("HSET", key, "views", 3, "views_count", 0, "token", "test-record"); err != nil {
			t.Fatal(err)
		}
		if _, err = c.Do("EXPIRE", key, 60); err != nil {
			t.Fatal(err)
		}
		var successes atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := redis.Dial("tcp", addr)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				record, remaining, ttl, err := consumeAttempt(conn, key, remove, []byte("test-record"))
				if err == redis.ErrNil {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				if len(record) == 0 || remaining < 0 || ttl < 0 {
					t.Error("invalid reservation")
				}
				successes.Add(1)
			}()
		}
		wg.Wait()
		if successes.Load() != 3 {
			t.Fatalf("accepted %d attempts; want 3", successes.Load())
		}
		exists, err := redis.Int(c.Do("EXISTS", key))
		if err != nil {
			t.Fatal(err)
		}
		if remove && exists != 0 {
			t.Fatal("exhausted secret retained")
		}
		if !remove && exists != 1 {
			t.Fatal("archive metadata deleted before response")
		}
		c.Do("DEL", key)
		c.Close()
	}
}

func TestAttemptReservationRejectsChangedToken(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	key := "okuru_test_attempt_replaced_" + time.Now().Format("150405.000000000")
	defer func() {
		c.Do("DEL", key)
		c.Close()
	}()
	if _, err := c.Do("HSET", key, "views", 1, "views_count", 0, "token", "new-record"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("EXPIRE", key, 60); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := consumeAttempt(c, key, true, []byte("old-record")); err != redis.ErrNil {
		t.Fatalf("changed token was consumed: %v", err)
	}
	count, err := redis.Int(c.Do("HGET", key, "views_count"))
	if err != nil || count != 0 {
		t.Fatalf("changed token's attempt count was modified: %d, %v", count, err)
	}
}

func TestDecryptRejectsInvalidKeyAndUsesRedisExpiry(t *testing.T) {
	var key, wrong fernet.Key
	if err := key.Generate(); err != nil {
		t.Fatal(err)
	}
	if err := wrong.Generate(); err != nil {
		t.Fatal(err)
	}
	token, err := fernet.EncryptAndSignAtTime([]byte("test-secret"), &key, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decrypt(token, key.Encode(), 60); err != nil || got != "test-secret" {
		t.Fatalf("valid stored secret rejected: %q %v", got, err)
	}
	if _, err := Decrypt(token, wrong.Encode(), 60); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestInvalidKeyDoesNotConsumeAttemptAndPreviewIsReadOnly(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OKURU_TEST_REDIS_ADDR to an isolated Redis")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX
	REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX = host, port, "0", "", "okuru_integration_"
	defer func() {
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX = oldHost, oldPort, oldDB, oldPassword, oldPrefix
	}()
	link, httpErr := SetPassword("test-secret", 60, 1, true)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	var wrong fernet.Key
	if err := wrong.Generate(); err != nil {
		t.Fatal(err)
	}
	altered := strings.Split(link, TOKEN_SEPARATOR)[0] + TOKEN_SEPARATOR + wrong.Encode()
	if err := RetrievePassword(&models.Password{PasswordKey: altered}); err == nil {
		t.Fatal("invalid key accepted")
	}
	if err := RetrievePassword(&models.Password{PasswordKey: link}); err != nil {
		t.Fatalf("invalid key consumed the legitimate attempt: %v", err)
	}
	fileLink, httpErr := SetFile("test-password", 60, 1, true, false, "", ArchiveFormatAge)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	for i := 0; i < 2; i++ {
		f := &models.File{FileKey: fileLink}
		if err := GetFile(f); err != nil || f.Views != 1 {
			t.Fatalf("preview consumed attempt: %v", err)
		}
	}
	wrongFileLink := strings.Split(fileLink, TOKEN_SEPARATOR)[0] + TOKEN_SEPARATOR + wrong.Encode()
	if err := RetrieveFilePassword(&models.File{FileKey: wrongFileLink}); err == nil {
		t.Fatal("invalid file key accepted")
	}
	retrieved := &models.File{FileKey: fileLink}
	if err := RetrieveFilePassword(retrieved); err != nil {
		t.Fatalf("invalid file key consumed the legitimate attempt: %v", err)
	}
	if retrieved.ArchiveFormat != ArchiveFormatAge {
		t.Fatalf("archive format not preserved: %q", retrieved.ArchiveFormat)
	}
	if err := RetrieveFilePassword(&models.File{FileKey: fileLink}); err == nil {
		t.Fatal("file downloaded twice")
	}
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Do("DEL", REDIS_PREFIX+"file_"+strings.Split(fileLink, TOKEN_SEPARATOR)[0])
}
