package utils

import (
	"strings"
	"testing"

	"github.com/flosch/pongo2"
)

func TestGeoIPAttributionTracksOnlyActiveDBIPLite(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	if err := ConfigureGeoIPCountry(""); err != nil {
		t.Fatal(err)
	}
	if GeoIPUsesDBIP() || NewDataContext()["geoip_dbip_attribution"] != false {
		t.Fatal("disabled GeoIP unexpectedly requested attribution")
	}
	if err := ConfigureGeoIPCountry(geoIPFixture(t)); err != nil {
		t.Fatal(err)
	}
	// The fixture is a valid MaxMind test database, not DB-IP.
	if GeoIPUsesDBIP() {
		t.Fatal("non-DB-IP database was attributed to DB-IP")
	}
	for _, tc := range []struct {
		databaseType string
		want         bool
	}{
		{"DBIP-Country-Lite", true},
		{"DBIP-City-Lite", true},
		{"dbip-country-lite", true},
		{"DBIP-Country", false},
		{"GeoLite2-Country", false},
		{"Unrelated-Country", false},
	} {
		t.Run(tc.databaseType, func(t *testing.T) {
			// Change only the fixture metadata to exercise provider detection;
			// GeoIPUsesDBIP reads it under the same shared lock as reload.
			geoIPCountry.Lock()
			geoIPCountry.reader.Metadata.DatabaseType = tc.databaseType
			geoIPCountry.Unlock()
			if got := GeoIPUsesDBIP(); got != tc.want {
				t.Fatalf("GeoIPUsesDBIP(%q) = %v, want %v", tc.databaseType, got, tc.want)
			}
			if got := NewDataContext()["geoip_dbip_attribution"]; got != tc.want {
				t.Fatalf("template context = %v, want %v", got, tc.want)
			}
		})
	}
	if err := ConfigureGeoIPCountry(""); err != nil {
		t.Fatal(err)
	}
	if GeoIPUsesDBIP() {
		t.Fatal("attribution remained active after database was disabled")
	}
}

func TestGeoIPAttributionFooterIsConditionalAndPrivate(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	if err := ConfigureGeoIPCountry(""); err != nil {
		t.Fatal(err)
	}
	template, err := pongo2.FromFile("../views/base.html")
	if err != nil {
		t.Fatal(err)
	}
	render := func() string {
		t.Helper()
		context := NewDataContext()
		context["logo"] = "logo@2x.png"
		context["APP_NAME"] = "Snappass"
		context["copyright"] = "Existing copyright"
		context["client_ip"] = "203.0.113.99"
		body, err := template.Execute(context)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "Existing copyright") || !strings.Contains(body, `href="https://www.jeanphilippe.io/"`) || !strings.Contains(body, `alt="Jean-Philippe Mench"`) {
			t.Fatal("existing footer or navigation identity changed")
		}
		if strings.Contains(body, "203.0.113.99") {
			t.Fatal("attribution exposed a visitor IP")
		}
		return body
	}
	if body := render(); strings.Contains(body, "IP Geolocation by DB-IP") {
		t.Fatal("attribution is visible without an active DB-IP database")
	}
	if err := ConfigureGeoIPCountry(geoIPFixture(t)); err != nil {
		t.Fatal(err)
	}
	geoIPCountry.Lock()
	geoIPCountry.reader.Metadata.DatabaseType = "DBIP-Country-Lite"
	geoIPCountry.Unlock()
	body := render()
	for _, want := range []string{
		`href="https://db-ip.com/" rel="noreferrer noopener nofollow" target="_blank">IP Geolocation by DB-IP</a>`,
		`href="https://creativecommons.org/licenses/by/4.0/" rel="noreferrer noopener nofollow" target="_blank">CC BY 4.0</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing safe provider attribution: %s", want)
		}
	}
	if strings.Contains(body, `src="https://db-ip.com`) || strings.Contains(body, `src='https://db-ip.com`) {
		t.Fatal("attribution created an automatic external request")
	}
}
