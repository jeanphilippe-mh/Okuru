package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

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
	ctx.SetParamNames("alias")
	ctx.SetParamValues("invalid")
	if err := redirectShortLink(ctx, "invalid"); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("saturation status=%d", rec.Code)
	}
	<-shortLinkResolveSlots
	rec = httptest.NewRecorder()
	ctx = e.NewContext(httptest.NewRequest(http.MethodGet, "/invalid", nil), rec)
	ctx.SetParamNames("alias")
	ctx.SetParamValues("invalid")
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
