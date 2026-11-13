package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
)

func TestSensitiveURLsAreNotLogged(t *testing.T) {
	e := echo.New()
	e.GET("/:password_key", func(c echo.Context) error {
		route := safeLogRoute(c)
		if route != "/:password_key" || strings.Contains(route, "secret-key") {
			t.Fatalf("unsafe route %q", route)
		}
		return c.NoContent(204)
	})
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/uuid~secret-key?password=private", nil))
	c := e.NewContext(httptest.NewRequest("GET", "/unknown~secret-key", nil), httptest.NewRecorder())
	if safeLogRoute(c) != "unmatched" {
		t.Fatal("unmatched path logged")
	}
	if safeLogError(errors.New("failure at /uuid~secret-key")) != "request failed" {
		t.Fatal("raw error logged")
	}
	if safeLogError(echo.NewHTTPError(400, "private-payload")) != "Bad Request" {
		t.Fatal("HTTP error body logged")
	}
}

func TestBoundedRequestLogMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limit       int
		want        string
	}{
		{"unchanged", "normal host", 12, "normal host"},
		{"byte boundary", "aééz", 5, "a..."},
		{"replacement", "a\xffb", 5, "a\ufffdb"},
		{"replacement truncation", "a\xffb", 4, "a..."},
		{"tiny limit", "éé", 1, ""},
		{"zero limit", "abc", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := boundedLogText(tc.input, tc.limit)
			if got != tc.want || len(got) > tc.limit || !utf8.ValidString(got) {
				t.Fatalf("boundedLogText(%q, %d) = %q, want %q", tc.input, tc.limit, got, tc.want)
			}
		})
	}

	// Verify the values remain bounded, valid JSON strings even with control
	// characters and invalid UTF-8. A suffix beyond the limit is not logged.
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	input := "\n\xff" + strings.Repeat("é", 1024) + "secret-beyond-limit"
	logger.Info("http_request",
		slog.String("host", boundedLogText(input, maxLoggedHostBytes)),
		slog.String("user_agent", boundedLogText(input, maxLoggedUserAgentBytes)))
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("log was not valid JSON: %v", err)
	}
	for _, field := range []struct {
		name  string
		limit int
	}{{"host", maxLoggedHostBytes}, {"user_agent", maxLoggedUserAgentBytes}} {
		got, ok := record[field.name].(string)
		if !ok || len(got) > field.limit || !utf8.ValidString(got) || strings.Contains(got, "secret-beyond-limit") {
			t.Fatalf("unsafe %s field %q", field.name, got)
		}
	}
}
