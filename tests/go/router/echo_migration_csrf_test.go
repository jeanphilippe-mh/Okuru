package router

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

// An absolute assets directory must work independently of the current working
// directory. API and alias paths remain reserved even if files collide.
func TestMigrationAbsolutePublicAssetsAndFallback(t *testing.T) {
	public := t.TempDir()
	if !filepath.IsAbs(public) {
		t.Fatal("fixture root must be absolute")
	}
	if err := os.Mkdir(filepath.Join(public, "api"), 0700); err != nil {
		t.Fatal(err)
	}
	const alias = "AAAAAAAAAAAAAAAAAAAAAA"
	for name, value := range map[string]string{
		"asset.css":   "static fixture",
		"index.html":  "html fallback",
		"api/fixture": "api collision",
		alias:         "alias collision",
	} {
		if err := os.WriteFile(filepath.Join(public, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := echo.New()
	ConfigureErrorHandler(e, t.TempDir())
	e.Use(publicAssets(public))
	e.GET("/api/fixture", func(c *echo.Context) error { return c.String(http.StatusOK, "api handler") })
	e.GET("/"+alias, func(c *echo.Context) error { return c.String(http.StatusOK, "alias handler") })
	e.POST("/submit", func(c *echo.Context) error { return c.NoContent(http.StatusAccepted) })
	e.GET("/handler-not-found", func(c *echo.Context) error { return echo.ErrNotFound })
	for _, tc := range []struct {
		name, method, path string
		status             int
		body               string
	}{
		{"asset", http.MethodGet, "/asset.css", http.StatusOK, "static fixture"},
		{"head asset", http.MethodHead, "/asset.css", http.StatusOK, ""},
		{"html fallback", http.MethodGet, "/unknown/deep/path", http.StatusOK, "html fallback"},
		{"api file collision", http.MethodGet, "/api/fixture", http.StatusOK, "api handler"},
		{"alias file collision", http.MethodGet, "/" + alias, http.StatusOK, "alias handler"},
		{"post reaches handler", http.MethodPost, "/submit", http.StatusAccepted, ""},
		{"handler 404", http.MethodGet, "/handler-not-found", http.StatusNotFound, "Not Found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.status || rec.Body.String() != tc.body {
				t.Fatalf("status=%d body=%q; want %d %q", rec.Code, rec.Body.String(), tc.status, tc.body)
			}
		})
	}
	missingAPI := httptest.NewRecorder()
	e.ServeHTTP(missingAPI, httptest.NewRequest(http.MethodGet, "/api/missing", nil))
	if missingAPI.Code != http.StatusNotFound || strings.Contains(missingAPI.Body.String(), "html fallback") {
		t.Fatalf("missing API hidden by static fallback: status=%d body=%q", missingAPI.Code, missingAPI.Body.String())
	}
}

// Exercise the actual router configuration while using a harmless handler so
// the CSRF contract can be checked without touching Redis or creating shares.
func TestProductionRouterCSRFContract(t *testing.T) {
	e := New()
	e.POST("/csrf-contract-probe", func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	e.GET("/csrf-contract-probe", func(c *echo.Context) error {
		c.Response().Header().Set("X-CSRF-Token", c.Get("csrf").(string))
		return c.NoContent(http.StatusOK)
	})
	get := httptest.NewRecorder()
	e.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/csrf-contract-probe", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("Web CSRF probe returned %d, want %d", get.Code, http.StatusOK)
	}
	var cookie *http.Cookie
	for _, candidate := range get.Result().Cookies() {
		if candidate.Name == "_csrf" {
			if cookie != nil {
				t.Fatal("more than one CSRF cookie")
			}
			cookie = candidate
		}
	}
	if cookie == nil || len(cookie.Value) != 32 {
		t.Fatal("expected a 32-character CSRF cookie")
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("insecure CSRF cookie attributes: Secure=%t HttpOnly=%t SameSite=%v", cookie.Secure, cookie.HttpOnly, cookie.SameSite)
	}
	if token := get.Header().Get("X-CSRF-Token"); token != cookie.Value {
		t.Fatal("Web CSRF response header does not match the cookie")
	}

	for _, tc := range []struct {
		name      string
		token     string
		form      bool
		cookie    bool
		fetchSite string
		status    int
	}{
		{name: "valid header", token: cookie.Value, cookie: true, status: http.StatusNoContent},
		{name: "valid form", token: cookie.Value, form: true, cookie: true, status: http.StatusNoContent},
		{name: "missing token", cookie: true, status: http.StatusBadRequest},
		{name: "mismatched token", token: "incorrect-csrf-token", cookie: true, status: http.StatusForbidden},
		{name: "missing cookie", token: cookie.Value, status: http.StatusForbidden},
		{name: "cross-site with valid token", token: cookie.Value, cookie: true, fetchSite: "cross-site", status: http.StatusForbidden},
		{name: "same-site with valid token", token: cookie.Value, cookie: true, fetchSite: "same-site", status: http.StatusNoContent},
		{name: "same-site without token", cookie: true, fetchSite: "same-site", status: http.StatusBadRequest},
		{name: "same-site with invalid token", token: "incorrect-csrf-token", cookie: true, fetchSite: "same-site", status: http.StatusForbidden},
		{name: "unknown fetch site with valid token", token: cookie.Value, cookie: true, fetchSite: "unexpected", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := url.Values{}
			if tc.form {
				values.Set("_csrf", tc.token)
			}
			req := httptest.NewRequest(http.MethodPost, "/csrf-contract-probe", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if !tc.form && tc.token != "" {
				req.Header.Set("X-CSRF-Token", tc.token)
			}
			if tc.cookie {
				req.AddCookie(cookie)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("CSRF request returned %d, want %d", rec.Code, tc.status)
			}
		})
	}

	// Echo v5 examines the first value of each configured source. Later
	// duplicate values must not turn a rejected token into a valid request.
	for _, form := range []bool{false, true} {
		name := "repeated header"
		values := url.Values{}
		if form {
			name = "repeated form field"
			values["_csrf"] = []string{"incorrect-csrf-token", cookie.Value}
		}
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/csrf-contract-probe", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if !form {
				req.Header.Add("X-CSRF-Token", "incorrect-csrf-token")
				req.Header.Add("X-CSRF-Token", cookie.Value)
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("duplicate CSRF values returned %d, want 403", rec.Code)
			}
		})
	}
}
