package router

import (
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestErrorsKeepStatusAndAreWrittenOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "400.html"), []byte("<p>bad input</p>"), 0600); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	ConfigureErrorHandler(e, dir)
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError:   true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error { return nil },
	}))
	e.GET("/api/test", func(c *echo.Context) error { return echo.NewHTTPError(400, "private message") })
	e.GET("/web", func(c *echo.Context) error { return echo.NewHTTPError(400, http.StatusText(400)) })
	e.GET("/fallback", func(c *echo.Context) error { return errors.New("private failure") })
	for _, path := range []string{"/api/test", "/web", "/fallback"} {
		response := httptest.NewRecorder()
		e.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if path == "/fallback" {
			if response.Code != 500 || response.Body.String() != "Internal Server Error" {
				t.Fatalf("bad fallback: %d %s", response.Code, response.Body)
			}
		} else if response.Code != 400 {
			t.Fatalf("lost error status: %d", response.Code)
		}
		if path == "/api/test" {
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal("duplicate or malformed JSON:", err)
			}
			if len(body) != 2 || body["code"] != "bad_request" || body["message"] != "Bad Request" {
				t.Fatalf("unexpected JSON: %v", body)
			}
		}
		if path == "/web" && response.Body.String() != "<p>bad input</p>" {
			t.Fatal("error HTML not served")
		}
	}
}

func TestFormNavigationErrorsReturnToOriginalForm(t *testing.T) {
	e := echo.New()
	e.Renderer = selectionLimitRenderer{}
	ConfigureErrorHandler(e, t.TempDir())
	e.Pre(func(_ echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Retry-After", "60")
			return echo.NewHTTPError(http.StatusTooManyRequests, "private detail")
		}
	})
	for _, tc := range []struct {
		method, path, mode, accept, xhr, destination string
	}{
		{http.MethodPost, "/", "navigate", echo.MIMETextHTML, "", "/"},
		{http.MethodPost, "/file", "navigate", echo.MIMETextHTML, "", "/file"},
		{http.MethodPost, "/file/", "", echo.MIMETextHTML, "", "/file"},
		{http.MethodPost, "/file", "cors", echo.MIMEApplicationJSON, "", ""},
		{http.MethodPost, "/file", "", echo.MIMETextHTML, "XMLHttpRequest", ""},
		{http.MethodPost, "/api/v2/files/direct", "navigate", echo.MIMETextHTML, "", ""},
		{http.MethodGet, "/file/key/download/session", "navigate", echo.MIMETextHTML, "", ""},
		{http.MethodHead, "/file", "navigate", echo.MIMETextHTML, "", ""},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set(echo.HeaderAccept, tc.accept)
		req.Header.Set("Sec-Fetch-Mode", tc.mode)
		req.Header.Set("X-Requested-With", tc.xhr)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" ||
			strings.Contains(rec.Body.String(), "private detail") {
			t.Fatalf("%s %s returned status=%d, headers=%v, body=%q", tc.method, tc.path, rec.Code, rec.Header(), rec.Body.String())
		}
		if tc.destination == "" {
			if rec.Header().Get("Refresh") != "" || tc.method == http.MethodHead && rec.Body.Len() != 0 {
				t.Fatalf("%s %s received an unexpected form return", tc.method, tc.path)
			}
			continue
		}
		if rec.Header().Get("Refresh") != "3; url="+tc.destination || !strings.Contains(rec.Body.String(), `href="`+tc.destination+`">Return now`) ||
			!strings.Contains(rec.Body.String(), "Too Many Requests") || strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
			t.Fatalf("%s %s has no unique form return for %s", tc.method, tc.path, tc.destination)
		}
	}
}
