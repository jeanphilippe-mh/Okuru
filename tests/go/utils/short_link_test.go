package utils

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
)

// The caller must supply a dedicated disposable Redis instance. Unique
// prefixes and separate databases keep this suite isolated from other tests.
func shortTestRedis(t *testing.T) (redis.Conn, redis.Conn, string) {
	t.Helper()
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort, oldDB, oldPass, oldPrefix := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX
	REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD = host, port, "10", ""
	REDIS_PREFIX = "short_test_" + strings.ReplaceAll(uuid.NewString(), "-", "") + "_"
	t.Setenv("OKURU_SHORTLINK_REDIS_DB", "11")
	t.Setenv("OKURU_SHORTLINK_BITS", "")
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "4096")
	mainConn, err := redis.Dial("tcp", addr, redis.DialDatabase(10))
	if err != nil {
		t.Fatal(err)
	}
	aliasConn, err := redis.Dial("tcp", addr, redis.DialDatabase(11))
	if err != nil {
		mainConn.Close()
		t.Fatal(err)
	}
	prefix := REDIS_PREFIX
	t.Cleanup(func() {
		for _, c := range []redis.Conn{mainConn, aliasConn} {
			keys, _ := redis.Strings(c.Do("KEYS", prefix+"*"))
			for _, key := range keys {
				_, _ = c.Do("DEL", key)
			}
			_ = c.Close()
		}
		_ = CloseShortLinkPool()
		_ = CloseRedisPool()
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX = oldHost, oldPort, oldDB, oldPass, oldPrefix
	})
	return mainConn, aliasConn, addr
}

func TestShortLinkEncryptedRoundTripAndExpiry(t *testing.T) {
	mainConn, aliasConn, _ := shortTestRedis(t)
	for _, isFile := range []bool{false, true} {
		var token string
		var shareErr error
		if isFile {
			fileToken, err := SetFile(archiveTestIdentity(t), 120, 2, true, false, "", ArchiveFormatAgeX25519)
			if err != nil {
				shareErr = err
			} else {
				token = fileToken
			}
		} else {
			secretToken, err := SetPassword("short-test-secret", 120, 2, true)
			if err != nil {
				shareErr = err
			} else {
				token = secretToken
			}
		}
		if shareErr != nil {
			t.Fatalf("create share: %v", shareErr)
		}
		alias, err := CreateShortLink(context.Background(), token, isFile)
		if err != nil {
			t.Fatalf("create alias: %v", err)
		}
		if len(alias) != 22 {
			t.Fatalf("alias length = %d, want 22", len(alias))
		}
		if decoded, err := base64.RawURLEncoding.Strict().DecodeString(alias); err != nil || len(decoded) != 16 {
			t.Fatal("alias is not a canonical 128-bit value")
		}
		another, err := CreateShortLink(context.Background(), token, isFile)
		if err != nil || another == alias {
			t.Fatal("separate aliases should be independently generated")
		}
		want := "/" + token
		if isFile {
			want = "/file/" + token
		}
		if got, err := ResolveShortLink(context.Background(), alias); err != nil || got != want {
			t.Fatalf("resolve failed: %v", err)
		}
		id, _, err := ParseToken(token)
		if err != nil {
			t.Fatal(err)
		}
		primaryKey := REDIS_PREFIX + id
		if isFile {
			primaryKey = REDIS_PREFIX + "file_" + id
		}
		primaryExpiry, err := redis.Int64(mainConn.Do("PEXPIRETIME", primaryKey))
		if err != nil {
			t.Fatal(err)
		}
		index, _, err := shortAliasMaterial(alias)
		if err != nil {
			t.Fatal(err)
		}
		aliasKey := shortStorageKey(index)
		aliasExpiry, err := redis.Int64(aliasConn.Do("PEXPIRETIME", aliasKey))
		if err != nil || aliasExpiry != primaryExpiry {
			t.Fatalf("alias expiry does not match original: %d != %d (%v)", aliasExpiry, primaryExpiry, err)
		}
		ciphertext, err := redis.Bytes(aliasConn.Do("GET", aliasKey))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{token, alias, "short-test-secret", "short-test-password"} {
			if strings.Contains(aliasKey, secret) || bytes.Contains(ciphertext, []byte(secret)) {
				t.Fatal("Redis exposes a share credential in cleartext")
			}
		}
		ciphertext[len(ciphertext)-1] ^= 1
		if _, err := aliasConn.Do("SET", aliasKey, ciphertext, "KEEPTTL"); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveShortLink(context.Background(), alias); !errors.Is(err, ErrShortLinkNotFound) {
			t.Fatal("tampered ciphertext was not rejected")
		}
		if got, err := ResolveShortLink(context.Background(), another); err != nil || got != want {
			t.Fatal("tampering changed another alias")
		}
	}
}

func TestShortLinkRejectsNonCanonicalAndWrongAliases(t *testing.T) {
	_, _, _ = shortTestRedis(t)
	token, httpErr := SetPassword("sample", 120, 2, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	alias, err := CreateShortLink(context.Background(), token, false)
	if err != nil {
		t.Fatal(err)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, alias[len(alias)-1])
	if last < 0 || last%16 != 0 {
		t.Fatal("unexpected base64 padding bits")
	}
	noncanonical := alias[:len(alias)-1] + string(alphabet[last+1])
	for _, bad := range []string{"", alias + "=", alias[:len(alias)-1], "../" + alias, alias[:4] + "/" + alias[5:], noncanonical} {
		if _, err := ResolveShortLink(context.Background(), bad); !errors.Is(err, ErrShortLinkNotFound) {
			t.Fatalf("accepted invalid alias of length %d", len(bad))
		}
	}
	mutated := alias
	if mutated[0] == 'A' {
		mutated = "B" + mutated[1:]
	} else {
		mutated = "A" + mutated[1:]
	}
	if _, err := ResolveShortLink(context.Background(), mutated); !errors.Is(err, ErrShortLinkNotFound) {
		t.Fatal("unknown alias not rejected")
	}
}

// Both strengths use v2. A valid v1 record is deliberately unreachable.
func TestShortLinkStrengthConfigurationAndRotation(t *testing.T) {
	mainConn, aliasConn, _ := shortTestRedis(t)
	token, httpErr := SetPassword("sample", 120, 2, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	aliases := make([]string, 0, 4)
	for _, tc := range []struct {
		setting string
		length  int
	}{
		{"", 22},
		{"128", 22},
		{"256", 43},
	} {
		t.Setenv("OKURU_SHORTLINK_BITS", tc.setting)
		alias, err := CreateShortLink(context.Background(), token, false)
		if err != nil || len(alias) != tc.length {
			t.Fatalf("setting %q returned alias length %d: %v", tc.setting, len(alias), err)
		}
		aliases = append(aliases, alias)
	}

	seed := bytes.Repeat([]byte{0x42}, 32)
	legacyAlias := base64.RawURLEncoding.EncodeToString(seed)
	index, err := hkdf.Key(sha256.New, seed, nil, "okuru/short-link/v1/lookup", 32)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hkdf.Key(sha256.New, seed, nil, "okuru/short-link/v1/aes-256-gcm", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	aad := append([]byte("okuru/short-link/v1/record:"), index...)
	ciphertext := aead.Seal(nil, nil, []byte("s"+token), aad)
	id, _, err := ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := redis.Int64(mainConn.Do("PEXPIRETIME", REDIS_PREFIX+id))
	if err != nil {
		t.Fatal(err)
	}
	legacyKey := REDIS_PREFIX + "short_v1_" + hex.EncodeToString(index)
	if _, err := aliasConn.Do("SET", legacyKey, ciphertext, "PXAT", expiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveShortLink(t.Context(), legacyAlias); !errors.Is(err, ErrShortLinkNotFound) {
		t.Fatal("retired alias resolved")
	}

	for _, setting := range []string{"128", "256", "", "invalid"} {
		t.Setenv("OKURU_SHORTLINK_BITS", setting)
		for _, alias := range aliases {
			if got, err := ResolveShortLink(context.Background(), alias); err != nil || got != "/"+token {
				t.Fatalf("setting %q could not resolve an existing alias: %v", setting, err)
			}
		}
	}
	for _, invalid := range []string{"129", " 128", "128 ", "garbage"} {
		t.Setenv("OKURU_SHORTLINK_BITS", invalid)
		if alias, err := CreateShortLink(context.Background(), token, false); err == nil || alias != "" {
			t.Fatalf("invalid strength %q issued an alias", invalid)
		}
	}

}

func TestShortLinkRefusesMissingOrSoonExpiringTargetAndBadConfiguration(t *testing.T) {
	mainConn, _, _ := shortTestRedis(t)
	token, httpErr := SetPassword("sample", 120, 2, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	for _, db := range []string{"", "10", "-1", "not-a-db"} {
		t.Setenv("OKURU_SHORTLINK_REDIS_DB", db)
		if alias, err := CreateShortLink(context.Background(), token, false); err == nil || alias != "" {
			t.Fatal("invalid alias database was accepted")
		}
	}
	t.Setenv("OKURU_SHORTLINK_REDIS_DB", "11")
	id, _, _ := ParseToken(token)
	if _, err := mainConn.Do("PEXPIRE", REDIS_PREFIX+id, 500); err != nil {
		t.Fatal(err)
	}
	if alias, err := CreateShortLink(context.Background(), token, false); err == nil || alias != "" {
		t.Fatal("near-expiry alias was issued")
	}
	if _, err := mainConn.Do("DEL", REDIS_PREFIX+id); err != nil {
		t.Fatal(err)
	}
	if alias, err := CreateShortLink(context.Background(), token, false); err == nil || alias != "" {
		t.Fatal("alias for missing share was issued")
	}
}

func TestShortLinkCapacityCheckIsAtomic(t *testing.T) {
	_, _, addr := shortTestRedis(t)
	const workers = 24
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := redis.Dial("tcp", addr, redis.DialDatabase(11))
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			result, err := redis.Int(shortCreateScript.Do(c, fmt.Sprintf("%sconcurrent_%d", REDIS_PREFIX, i), []byte("ciphertext"), time.Now().Add(time.Minute).UnixMilli(), 1))
			if err != nil {
				t.Error(err)
				return
			}
			if result == 1 {
				successes.Add(1)
			} else if result != 0 {
				t.Errorf("unexpected script result %d", result)
			}
		}(i)
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("quota allowed %d concurrent insertions", got)
	}
}

func TestShortLinkCanceledContextDoesNotIssueAlias(t *testing.T) {
	_, aliasConn, _ := shortTestRedis(t)
	token, httpErr := SetPassword("sample", 120, 2, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if alias, err := CreateShortLink(ctx, token, false); err == nil || alias != "" {
		t.Fatal("canceled creation returned an alias")
	}
	keys, err := redis.Strings(aliasConn.Do("KEYS", REDIS_PREFIX+"short_v*_"+"*"))
	if err != nil || len(keys) != 0 {
		t.Fatal("canceled creation wrote alias metadata")
	}
}
