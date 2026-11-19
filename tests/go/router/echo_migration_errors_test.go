package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// These cases protect Okuru's public error contract when Echo changes its
// representation of router-generated errors or its response writer.
func TestMigrationRouterErrorsAndCommittedResponses(t *testing.T) {
	e := echo.New()
	ConfigureErrorHandler(e, t.TempDir())
	logged := 0
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError: true,
		LogStatus:   true,
		LogValuesFunc: func(c *echo.Context, values middleware.RequestLoggerValues) error {
			logged++
			return nil
		},
	}))
	for _, path := range []string{"/web/exists", "/api/exists"} {
		e.GET(path, func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	}
	e.HEAD("/head-error", func(c *echo.Context) error {
		return echo.NewHTTPError(http.StatusBadRequest, "private detail")
	})
	e.GET("/wrapped", func(c *echo.Context) error {
		return fmt.Errorf("private detail: %w", echo.NewHTTPError(http.StatusBadRequest, http.StatusText(http.StatusBadRequest)))
	})
	e.GET("/committed", func(c *echo.Context) error {
		if err := c.String(http.StatusAccepted, "original response"); err != nil {
			return err
		}
		return errors.New("private detail")
	})

	cases := []struct {
		name, method, path string
		status             int
		body               string
		api                bool
	}{
		{"web not found", http.MethodGet, "/web/missing", http.StatusNotFound, "Not Found", false},
		{"api not found", http.MethodGet, "/api/missing", http.StatusNotFound, "Not Found", true},
		{"web method not allowed", http.MethodPost, "/web/exists", http.StatusMethodNotAllowed, "Method Not Allowed", false},
		{"api method not allowed", http.MethodPost, "/api/exists", http.StatusMethodNotAllowed, "Method Not Allowed", true},
		{"head error", http.MethodHead, "/head-error", http.StatusBadRequest, "", false},
		{"wrapped status", http.MethodGet, "/wrapped", http.StatusBadRequest, "Bad Request", false},
		{"committed response", http.MethodGet, "/committed", http.StatusAccepted, "original response", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			previousLogCount := logged
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %q", rec.Code, tc.status, rec.Body.String())
			}
			if logged != previousLogCount+1 {
				t.Fatalf("request logger invoked %d times, want once", logged-previousLogCount)
			}
			if strings.Contains(rec.Body.String(), "private detail") {
				t.Fatal("private error detail exposed")
			}
			if tc.api {
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("invalid or duplicate JSON response: %v", err)
				}
				if len(body) != 2 || body["message"] != tc.body || body["code"] != strings.ToLower(strings.ReplaceAll(tc.body, " ", "_")) {
					t.Fatalf("JSON body = %#v, want error %q", body, tc.body)
				}
				if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
					t.Fatalf("Cache-Control = %q, want no-store", got)
				}
			} else if got := rec.Body.String(); got != tc.body {
				t.Fatalf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

// An unknown response wrapper must not turn an internal error into an empty
// success response. net/http treats ErrAbortHandler as a request abort.
func TestMigrationErrorHandlerAbortsUnknownResponseWriter(t *testing.T) {
	e := echo.New()
	ConfigureErrorHandler(e, t.TempDir())
	w := &migrationWriteObserver{header: make(http.Header)}
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/missing", nil), httptest.NewRecorder())
	c.SetResponse(w)
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("panic = %v, want http.ErrAbortHandler", got)
		}
		if w.wroteHeader || w.written != 0 {
			t.Fatalf("response already written: header=%t bytes=%d", w.wroteHeader, w.written)
		}
	}()
	e.HTTPErrorHandler(c, errors.New("private internal error"))
}

type migrationWriteObserver struct {
	header      http.Header
	wroteHeader bool
	written     int
}

func (w *migrationWriteObserver) Header() http.Header { return w.header }
func (w *migrationWriteObserver) WriteHeader(int)     { w.wroteHeader = true }
func (w *migrationWriteObserver) Write(p []byte) (int, error) {
	w.written += len(p)
	return len(p), nil
}
