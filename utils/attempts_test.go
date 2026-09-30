package utils

import (
	"github.com/fernet/fernet-go"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
				record, remaining, ttl, err := consumeAttempt(conn, key, remove)
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

func TestInvalidKeyConsumesAttemptAndPreviewIsReadOnly(t *testing.T) {
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
	if err := RetrievePassword(&models.Password{PasswordKey: link}); err == nil {
		t.Fatal("invalid key failed to consume attempt")
	}
	fileLink, httpErr := SetFile("test-password", 60, 1, true, false, "")
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	for i := 0; i < 2; i++ {
		f := &models.File{FileKey: fileLink}
		if err := GetFile(f); err != nil || f.Views != 1 {
			t.Fatalf("preview consumed attempt: %v", err)
		}
	}
	if err := RetrieveFilePassword(&models.File{FileKey: fileLink}); err != nil {
		t.Fatal(err)
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
