package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type fakeProxyTransport func(*http.Request) (*http.Response, error)

func (f fakeProxyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// This checks Echo's unconfigured extractor with the exact dependency in go.mod.
func TestAdvisoryDefaultRealIPIgnoresSpoofedForwarding(t *testing.T) {
	e := echo.New()
	e.GET("/", func(c echo.Context) error { return c.String(http.StatusOK, c.RealIP()) })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	r.Header.Set("X-Real-IP", "198.51.100.8")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "203.0.113.9" {
		t.Fatalf("unexpected peer: %d %q", w.Code, w.Body.String())
	}
}

// Echo proxy is not registered by Okuru; test the upstream behavior independently.
func TestAdvisoryProxyOverwritesSpoofedRealIP(t *testing.T) {
	e := echo.New()
	target, _ := url.Parse("http://upstream.invalid")
	seen := ""
	proxy := middleware.ProxyWithConfig(middleware.ProxyConfig{
		Balancer: middleware.NewRoundRobinBalancer([]*middleware.ProxyTarget{{URL: target}}),
		Transport: fakeProxyTransport(func(r *http.Request) (*http.Response, error) {
			seen = r.Header.Get("X-Real-IP")
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		}),
	})
	e.Use(proxy)
	e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Real-IP", "198.51.100.8")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusOK || seen != "203.0.113.9" {
		t.Fatalf("unexpected upstream: %d %q", w.Code, seen)
	}
}
