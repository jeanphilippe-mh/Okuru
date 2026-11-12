package router

import (
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		HandleError: true, LogError: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error { return nil },
	}))
	e.GET("/api/test", func(c echo.Context) error { return echo.NewHTTPError(400, "private message") })
	e.GET("/web", func(c echo.Context) error { return echo.NewHTTPError(400) })
	e.GET("/fallback", func(c echo.Context) error { return errors.New("private failure") })
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
			if body["error"] != "Bad Request" {
				t.Fatalf("unexpected JSON: %v", body)
			}
		}
		if path == "/web" && response.Body.String() != "<p>bad input</p>" {
			t.Fatal("error HTML not served")
		}
	}
}
