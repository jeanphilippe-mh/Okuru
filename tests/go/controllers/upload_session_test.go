package controllers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func TestUploadSessionRejectsInvalidRequestsPrivately(t *testing.T) {
	old := utils.MaxFileSize
	utils.MaxFileSize = 1024
	t.Cleanup(func() { utils.MaxFileSize = old })
	e := echo.New()
	e.POST("/api/v2/uploads", PrepareUploadSession)
	e.GET("/api/v2/uploads/:id", GetUploadSession)
	for _, tc := range []struct {
		method, path, media, key, auth, body string
		status                               int
		code                                 string
	}{
		{"POST", "/api/v2/uploads", "text/plain", "", "", "", 415, "unsupported_media_type"},
		{"POST", "/api/v2/uploads", "application/json", "", "", "", 400, "invalid_id"},
		{"POST", "/api/v2/uploads", "application/json", uuid.NewString(), "", "{}", 404, "not_found"},
		{"POST", "/api/v2/uploads", "application/json", uuid.NewString(), "Bearer " + strings.Repeat("A", 43), `{"mode":"multipart","password":"private-marker","files":[]}`, 400, "invalid_manifest"},
		{"GET", "/api/v2/uploads/" + uuid.NewString(), "", "", "", "", 404, "not_found"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.media)
		if tc.key != "" {
			r.Header.Set("Idempotency-Key", tc.key)
		}
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		var got struct{ Code string }
		if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Code != tc.code || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("Referrer-Policy") != "no-referrer" || strings.Contains(w.Body.String(), "private-marker") {
			t.Fatalf("private %s %s: %d %s", tc.method, tc.path, w.Code, w.Body)
		}
	}
}
