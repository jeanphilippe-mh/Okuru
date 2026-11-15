package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestShortLinkRedirectTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		status int
	}{
		{"root", "/", http.StatusFound},
		{"secret", "/01234567-89ab-cdef-0123-456789abcdef~key", http.StatusFound},
		{"file", "/file/01234567-89ab-cdef-0123-456789abcdef~key", http.StatusFound},
		{"empty", "", http.StatusNotFound},
		{"relative", "abc", http.StatusNotFound},
		{"absolute", "https://evil.example/path", http.StatusNotFound},
		{"scheme_relative", "//evil.example/path", http.StatusNotFound},
		{"backslash_authority", "/\\evil.example/path", http.StatusNotFound},
		{"backslash_in_path", "/file\\evil", http.StatusNotFound},
		{"tab_authority", "/\t/evil.example", http.StatusNotFound},
		{"carriage_return", "/\r/evil.example", http.StatusNotFound},
		{"newline", "/\n/evil.example", http.StatusNotFound},
		{"null", "/file/abc\x00def", http.StatusNotFound},
		{"delete_control", "/file/abc\x7fdef", http.StatusNotFound},
		{"query", "/abc?next=evil", http.StatusNotFound},
		{"fragment", "/abc#fragment", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			rec := httptest.NewRecorder()
			ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/alias", nil), rec)
			if err := redirectShortLinkTarget(ctx, tc.target); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.status {
				t.Fatalf("status=%d, want %d", rec.Code, tc.status)
			}
			location := rec.Header().Get("Location")
			if tc.status == http.StatusFound && location != tc.target {
				t.Fatalf("location=%q, want %q", location, tc.target)
			}
			if tc.status != http.StatusFound && location != "" {
				t.Fatalf("rejected target produced Location %q", location)
			}
		})
	}
}

func TestShortLinkResolutionGuardSaturationAndRelease(t *testing.T) {
	if len(shortLinkResolveSlots) != 0 {
		t.Fatal("unexpected active short-link resolutions")
	}
	for i := 0; i < cap(shortLinkResolveSlots); i++ {
		shortLinkResolveSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for len(shortLinkResolveSlots) > 0 {
			<-shortLinkResolveSlots
		}
	})
	e := echo.New()
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/invalid", nil), rec)
	ctx.SetPathValues(echo.PathValues{{Name: "alias", Value: "invalid"}})
	if err := redirectShortLink(ctx, "invalid"); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("saturation status=%d", rec.Code)
	}
	<-shortLinkResolveSlots
	rec = httptest.NewRecorder()
	ctx = e.NewContext(httptest.NewRequest(http.MethodGet, "/invalid", nil), rec)
	ctx.SetPathValues(echo.PathValues{{Name: "alias", Value: "invalid"}})
	if err := redirectShortLink(ctx, "invalid"); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("slot was not reusable: status=%d", rec.Code)
	}
	if len(shortLinkResolveSlots) != cap(shortLinkResolveSlots)-1 {
		t.Fatal("resolution slot leaked on error")
	}
}

func TestShortLinkPublicOriginCanonicalHosts(t *testing.T) {
	for _, tc := range []struct {
		origin string
		valid  bool
	}{
		{"https://share.example.test", true},
		{"https://share.example.test:8443", true},
		{"https://example.123a", true},
		{"https://192.0.2.1", true},
		{"https://127.0.0.1", true},
		{"https://[2001:db8::1]", true},
		{"https://[2001:db8::1]:8443", true},
		{"https://999.999.999.999", false},
		{"https://example.123", false},
		{"https://127.0.0.01", false},
		{"https://0x7f000001", false},
		{"https://example.0x8", false},
		{"https://1.2.3.04", false},
		{"https://[::ffff:192.0.2.1]", false},
		{"https://[::ffff:c000:201]", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			got, ok := shortLinkPublicOrigin(tc.origin)
			if ok != tc.valid {
				t.Fatalf("valid=%v, expected %v", ok, tc.valid)
			}
			if ok && got != tc.origin {
				t.Fatal("canonical origin changed during validation")
			}
		})
	}
}
