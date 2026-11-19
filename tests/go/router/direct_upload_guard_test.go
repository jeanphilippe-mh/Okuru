package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

type directUploadPadding struct{}

type unexpectedUploadRead struct{ t *testing.T }

func (r unexpectedUploadRead) Read([]byte) (int, error) {
	r.t.Fatal("read upload before checking the request headers")
	return 0, io.EOF
}

func TestDirectUploadRejectsBeforeReading(t *testing.T) {
	for _, tc := range []struct {
		name        string
		token       string
		contentType string
		size        int64
		want        int
	}{
		{"missing header", "", "multipart/form-data; boundary=b", -1, http.StatusForbidden},
		{"wrong cookie", "other", "multipart/form-data; boundary=b", -1, http.StatusForbidden},
		{"wrong media type", "correct", "application/json", -1, http.StatusUnsupportedMediaType},
		{"missing boundary", "correct", "multipart/form-data", -1, http.StatusBadRequest},
		{"too large", "correct", "multipart/form-data; boundary=b", directRequestLimit + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			e.Use(directUploadGuard)
			e.POST(directFilePath, func(*echo.Context) error {
				t.Fatal("invalid upload reached handler")
				return nil
			})
			r := httptest.NewRequest(http.MethodPost, directFilePath, unexpectedUploadRead{t})
			r.ContentLength = tc.size
			r.Header.Set(echo.HeaderSecFetchSite, "same-origin")
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set(echo.HeaderXCSRFToken, tc.token)
			r.AddCookie(&http.Cookie{Name: directCSRFCookie, Value: "correct"})
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, r)
			if rec.Code != tc.want || !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("unexpected response: status=%d cache=%q", rec.Code, rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func (directUploadPadding) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestDirectUploadLimitCountsChunkedEpilogue(t *testing.T) {
	folder, oldFolder, oldLimit := t.TempDir(), utils.FILEFOLDER, utils.MaxFileSize
	utils.FILEFOLDER, utils.MaxFileSize = folder, 32
	t.Cleanup(func() { utils.FILEFOLDER, utils.MaxFileSize = oldFolder, oldLimit })

	const envelope = "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n" +
		`{"ttl_seconds":3600,"views":1,"files":[{"name":"hello.txt","size":1}]}` +
		"\r\n--b\r\nContent-Disposition: form-data; name=\"files\"; filename=\"hello.txt\"\r\n\r\nx\r\n--b--\r\n"
	for _, tc := range []struct {
		name string
		size int64
		want int
	}{
		{"at limit", directRequestLimit, http.StatusNoContent},
		{"over limit", directRequestLimit + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			e.Use(directUploadGuard, secureMultipart)
			e.POST(directFilePath, func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
			padding := io.LimitReader(directUploadPadding{}, tc.size-int64(len(envelope)))
			body := io.MultiReader(strings.NewReader(envelope), padding)
			r := httptest.NewRequest(http.MethodPost, directFilePath, body)
			r.Header.Set("Content-Type", "multipart/form-data; boundary=b")
			r.Header.Set(echo.HeaderXCSRFToken, "test-token")
			r.AddCookie(&http.Cookie{Name: directCSRFCookie, Value: "test-token"})
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
