package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func TestFileReceiptIntegrityAndLifetime(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	id := uuid.NewString()
	key := utils.REDIS_PREFIX + "file_" + id
	now := time.Now()
	view := fileConfirmation{FilePath: "/file/synthetic", TTL: 3600, Views: 1}

	if _, err := issueFileReceipt(id, view, now); !errors.Is(err, errFileReceiptUnavailable) {
		t.Fatal("attached a receipt to an absent share")
	}
	if exists, err := redis.Bool(conn.Do("EXISTS", key)); err != nil || exists {
		t.Fatal("receipt creation resurrected a missing share")
	}
	if _, err := conn.Do("HSET", key, "token", "fixture"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Do("DEL", key) })
	if _, err := conn.Do("EXPIRE", key, 600); err != nil {
		t.Fatal(err)
	}
	receipt, err := issueFileReceipt(id, view, now)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(receipt))
	stored, err := redis.Bytes(conn.Do("HGET", key, "confirmation_digest"))
	if err != nil || !bytes.Equal(stored, digest[:]) {
		t.Fatal("Redis did not store the expected digest")
	}
	if ttl, err := redis.Int(conn.Do("TTL", key)); err != nil || ttl < 1 || ttl > 600 {
		t.Fatal("receipt registration changed the file expiry")
	}
	for _, age := range []time.Duration{0, fileReceiptLifetime - time.Second} {
		got, err := verifyFileReceipt(receipt, now.Add(age))
		if err != nil || got != view {
			t.Fatal("valid receipt did not restore the original view")
		}
	}
	for _, tc := range []struct {
		receipt string
		age     time.Duration
	}{
		{receipt, -time.Second},
		{receipt, fileReceiptLifetime},
		{receipt + "A", 0},
	} {
		if _, err := verifyFileReceipt(tc.receipt, now.Add(tc.age)); !errors.Is(err, errFileReceiptUnavailable) {
			t.Fatal("accepted an invalid or expired receipt")
		}
	}
	if _, err := conn.Do("DEL", key); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFileReceipt(receipt, now); !errors.Is(err, errFileReceiptUnavailable) {
		t.Fatal("accepted a receipt after removal of the share")
	}
}

func TestFileUploadJSONValidationError(t *testing.T) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for key, value := range map[string]string{"ttl": "1", "ttlViews": "1"} {
		if err := form.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/file", &body)
	req.Header.Set(echo.HeaderContentType, form.FormDataContentType())
	req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e := echo.New()
	e.Validator = uploadValidator{}
	if err := AddFile(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Cache-Control") != "private, no-store" ||
		json.Unmarshal(rec.Body.Bytes(), &result) != nil || len(result) != 1 || result["error"] != "No files selected" {
		t.Fatalf("unexpected JSON validation response: status=%d body=%q", rec.Code, rec.Body.String())
	}
}
