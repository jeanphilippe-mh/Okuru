package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	log "github.com/sirupsen/logrus"
)

// errorLogRedis returns a deliberately sensitive error without using a real
// Redis instance, so tests can verify the production logging boundary.
type errorLogRedis struct {
	failCommand string
	secret      string
	token       []byte
	missing     bool
	badRecord   bool
	negativeTTL bool
}

func (c *errorLogRedis) Close() error              { return nil }
func (c *errorLogRedis) Err() error                { return nil }
func (c *errorLogRedis) Send(string, ...any) error { return nil }
func (c *errorLogRedis) Flush() error              { return nil }
func (c *errorLogRedis) Receive() (any, error)     { return nil, nil }
func (c *errorLogRedis) Do(command string, _ ...any) (any, error) {
	if command == c.failCommand && command != "" {
		return nil, errors.New(c.secret)
	}
	switch command {
	case "PING":
		return "PONG", nil
	case "HGETALL":
		if c.missing {
			return []any{}, nil
		}
		if c.badRecord {
			return []any{[]byte("views"), []byte(c.secret)}, nil
		}
		return []any{[]byte("token"), c.token, []byte("views"), []byte("1"), []byte("deletable"), []byte("1"), []byte("archive_format"), []byte(ArchiveFormatAgeX25519)}, nil
	case "TTL":
		if c.negativeTTL {
			return int64(-2), nil
		}
		return int64(30), nil
	case "DEL":
		return int64(1), nil
	default:
		return nil, nil
	}
}

func TestStorageFailureLogsAvoidSensitiveRedisDetails(t *testing.T) {
	const privateError = "sensitive-redis-error-with-token-and-password"
	for _, tc := range []struct {
		name, action, failCommand, event, operation string
		badRecord                                   bool
		status                                      int
	}{
		{"secret read", "read", "HGETALL", "redis.command_failed", "secret.preview_read", false, http.StatusInternalServerError},
		{"secret decode", "read", "", "storage.record_decode_failed", "secret.preview_decode", true, http.StatusInternalServerError},
		{"secret TTL", "read", "TTL", "redis.command_failed", "secret.preview_ttl", false, http.StatusNotFound},
		{"file preview TTL", "read-file", "TTL", "redis.command_failed", "file.preview_ttl", false, http.StatusNotFound},
		{"secret delete read", "delete", "HGETALL", "redis.command_failed", "secret.delete_read", false, http.StatusInternalServerError},
		{"secret delete decode", "delete", "", "storage.record_decode_failed", "secret.delete_decode", true, http.StatusInternalServerError},
		{"secret delete", "delete", "DEL", "redis.command_failed", "secret.delete", false, http.StatusNotFound},
		{"file delete read", "delete-file", "HGETALL", "redis.command_failed", "file.delete_read", false, http.StatusInternalServerError},
		{"file delete decode", "delete-file", "", "storage.record_decode_failed", "file.delete_decode", true, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poolTestConfig(t)
			oldFolder := FILEFOLDER
			FILEFOLDER = t.TempDir()
			t.Cleanup(func() { FILEFOLDER = oldFolder })
			logger := log.StandardLogger()
			oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
			var output bytes.Buffer
			logger.SetOutput(&output)
			logger.SetFormatter(&log.JSONFormatter{})
			logger.SetLevel(log.InfoLevel)
			t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetFormatter(oldFormatter); logger.SetLevel(oldLevel) })
			ciphertext, key, err := Encrypt("private-password-not-for-logs")
			if err != nil {
				t.Fatal(err)
			}
			bearer := uuid.NewString() + TOKEN_SEPARATOR + key
			fake := &errorLogRedis{failCommand: tc.failCommand, secret: privateError + bearer, token: ciphertext, badRecord: tc.badRecord}
			redisDialContext = func(context.Context, string, string, ...redis.DialOption) (redis.Conn, error) { return fake, nil }
			var code int
			switch tc.action {
			case "read":
				if e := GetPassword(&models.Password{PasswordKey: bearer}); e != nil {
					code = e.Code
				}
			case "delete":
				if e := RemovePassword(&models.Password{PasswordKey: bearer}); e != nil {
					code = e.Code
				}
			case "delete-file":
				if e := RemoveFile(&models.File{FileKey: bearer}); e != nil {
					code = e.Code
				}
			case "read-file":
				if e := GetFile(&models.File{FileKey: bearer}); e != nil {
					code = e.Code
				}
			}
			if code != tc.status {
				t.Fatalf("status = %d, want %d", code, tc.status)
			}
			data := output.String()
			if strings.Contains(data, privateError) || strings.Contains(data, bearer) || strings.Contains(data, key) {
				t.Fatal("storage error leaked credentials or untrusted content")
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(data), &record); err != nil {
				t.Fatalf("invalid log record: %v", err)
			}
			if record["event"] != tc.event || record["operation"] != tc.operation || record["level"] != "error" {
				t.Fatalf("unexpected structured storage event: %v", record)
			}
		})
	}
}

func TestMissingOrUndecryptableEntriesAreNotServerErrorLogs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		missing     bool
		negativeTTL bool
	}{
		{"missing secret", true, false},
		{"undecryptable file metadata", false, false},
		{"expired file metadata", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poolTestConfig(t)
			logger := log.StandardLogger()
			oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
			var output bytes.Buffer
			logger.SetOutput(&output)
			logger.SetFormatter(&log.JSONFormatter{})
			logger.SetLevel(log.InfoLevel)
			t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetFormatter(oldFormatter); logger.SetLevel(oldLevel) })
			ciphertext, _, err := Encrypt("private-file-password")
			if err != nil {
				t.Fatal(err)
			}
			_, otherKey, err := Encrypt("different-key")
			if err != nil {
				t.Fatal(err)
			}
			bearer := uuid.NewString() + TOKEN_SEPARATOR + otherKey
			fake := &errorLogRedis{token: ciphertext, missing: tc.missing, negativeTTL: tc.negativeTTL}
			redisDialContext = func(context.Context, string, string, ...redis.DialOption) (redis.Conn, error) { return fake, nil }
			var status int
			if tc.missing {
				if e := GetPassword(&models.Password{PasswordKey: bearer}); e != nil {
					status = e.Code
				}
			} else if e := GetFile(&models.File{FileKey: bearer}); e != nil {
				status = e.Code
			}
			if status != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", status)
			}
			if strings.Contains(output.String(), `"level":"error"`) || strings.Contains(output.String(), bearer) {
				t.Fatal("unavailable entry emitted a server error or exposed a bearer")
			}
		})
	}
}
