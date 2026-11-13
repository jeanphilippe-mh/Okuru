package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

func TestFileCreationLimitRejectsWithoutPublishingArchive(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	u.REDIS_PREFIX += uuid.NewString() + "_"
	prefix := u.REDIS_PREFIX + "admission_file_create_"
	digest := sha256.Sum256([]byte("192.0.2.1"))
	t.Cleanup(func() {
		_, _ = conn.Do("DEL", prefix+"global", prefix+hex.EncodeToString(digest[:]))
	})
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/file", nil)
		allowed, err := u.AllowClientAction(req, "file_create", 20, 100, 24*time.Hour)
		if err != nil || !allowed {
			t.Fatalf("seed creation budget %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for key, value := range map[string]string{"ttl": "30", "ttlViews": "1", "password": ""} {
		if err := form.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := form.CreateFormFile("files", "tiny.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Renderer, e.Validator = &compatibilityRenderer{}, uploadValidator{}
	req := httptest.NewRequest(http.MethodPost, "/file", &body)
	req.Header.Set(echo.HeaderContentType, form.FormDataContentType())
	rec := httptest.NewRecorder()
	if err := AddFile(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "86400" {
		t.Fatalf("status=%d retry=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	entries, err := os.ReadDir(u.FILEFOLDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".zip") || strings.HasPrefix(entry.Name(), ".okuru-upload-") {
			t.Fatalf("archive was published or staging was retained after refusal: %q", entry.Name())
		}
	}
}
