package utils

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func geoIPFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "tests", "fixtures", "geoip", "GeoIP2-Country-Test.mmdb")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("missing fictional GeoIP fixture: %v", err)
	}
	return path
}

func TestGeoIPCountryLocalDatabaseAndAddressClasses(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	if err := ConfigureGeoIPCountry(geoIPFixture(t)); err != nil {
		t.Fatalf("load fictional country database: %v", err)
	}
	if _, ok := GeoIPCountryBuildTime(); !ok {
		t.Fatal("loaded database build time unavailable")
	}
	for _, tc := range []struct {
		ip, code, status string
	}{
		{"81.2.69.160", "GB", GeoIPFound},
		{"::ffff:81.2.69.160", "GB", GeoIPFound},
		{"2001:218::1", "JP", GeoIPFound},
		{"127.0.0.1", "", GeoIPNonPublic},
		{"::1", "", GeoIPNonPublic},
		{"10.1.2.3", "", GeoIPNonPublic},
		{"172.16.0.1", "", GeoIPNonPublic},
		{"192.168.1.1", "", GeoIPNonPublic},
		{"169.254.1.1", "", GeoIPNonPublic},
		{"100.64.0.1", "", GeoIPNonPublic},
		{"0.2.3.4", "", GeoIPNonPublic},
		{"192.0.0.8", "", GeoIPNonPublic},
		{"192.0.2.1", "", GeoIPNonPublic},
		{"198.18.0.1", "", GeoIPNonPublic},
		{"198.51.100.1", "", GeoIPNonPublic},
		{"203.0.113.1", "", GeoIPNonPublic},
		{"240.0.0.1", "", GeoIPNonPublic},
		{"fc00::1", "", GeoIPNonPublic},
		{"fe80::1", "", GeoIPNonPublic},
		{"64:ff9b:1::1", "", GeoIPNonPublic},
		{"100::1", "", GeoIPNonPublic},
		{"2001:2::1", "", GeoIPNonPublic},
		{"2001:db8::1", "", GeoIPNonPublic},
		{"3fff::1", "", GeoIPNonPublic},
		{"5f00::1", "", GeoIPNonPublic},
		{"ff02::1", "", GeoIPNonPublic},
		{"fe80::1%en0", "", GeoIPInvalidIP},
		{"not an address", "", GeoIPInvalidIP},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			country, name, status := LookupGeoIPCountry(tc.ip)
			wantName := map[string]string{"GB": "Royaume-Uni", "JP": "Japon"}[tc.code]
			if country != tc.code || name != wantName || status != tc.status {
				t.Fatalf("LookupGeoIPCountry(%q) = %q, %q, %q; want %q, %q, %q", tc.ip, country, name, status, tc.code, wantName, tc.status)
			}
		})
	}
}

func TestGeoIPCountryMissingInvalidAndDisabledRemainNonBlocking(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	if err := ConfigureGeoIPCountry(""); err != nil {
		t.Fatal(err)
	}
	if _, _, status := LookupGeoIPCountry("81.2.69.160"); status != GeoIPDisabled {
		t.Fatalf("empty configuration status = %q", status)
	}
	secretPath := filepath.Join(t.TempDir(), "private-name.mmdb")
	if err := ConfigureGeoIPCountry(secretPath); !errors.Is(err, ErrGeoIPDatabase) || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("missing database returned an unsafe error: %v", err)
	}
	if _, _, status := LookupGeoIPCountry("81.2.69.160"); status != GeoIPDatabaseUnavailable {
		t.Fatalf("missing database status = %q", status)
	}
	if _, _, status := LookupGeoIPCountry("127.0.0.1"); status != GeoIPNonPublic {
		t.Fatalf("loopback treated as a visitor: %q", status)
	}
	if err := os.WriteFile(secretPath, []byte("not an mmdb"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureGeoIPCountry(secretPath); !errors.Is(err, ErrGeoIPDatabase) {
		t.Fatalf("malformed database accepted: %v", err)
	}
	if err := ConfigureGeoIPCountry(filepath.Dir(secretPath)); !errors.Is(err, ErrGeoIPDatabase) {
		t.Fatalf("directory accepted as database: %v", err)
	}
	if err := ConfigureGeoIPCountry(geoIPFixture(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, status := LookupGeoIPCountry("1.1.1.1"); status != GeoIPNotFound {
		t.Fatalf("unknown public address status = %q", status)
	}
	if err := CloseGeoIPCountry(); err != nil {
		t.Fatal(err)
	}
	if _, ok := GeoIPCountryBuildTime(); ok {
		t.Fatal("closed database still reports a build time")
	}
}

func TestGeoIPCountryRejectsOversizedDatabase(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	path := filepath.Join(t.TempDir(), "oversized.mmdb")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxGeoIPDatabaseBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureGeoIPCountry(path); !errors.Is(err, ErrGeoIPDatabase) {
		t.Fatalf("oversized database accepted: %v", err)
	}
}

func TestGeoIPCountryConcurrentLookupAndReload(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	path := geoIPFixture(t)
	if err := ConfigureGeoIPCountry(path); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 500; j++ {
				country, _, status := LookupGeoIPCountry("81.2.69.160")
				if (status != GeoIPFound || country != "GB") && (status != GeoIPDisabled || country != "") {
					t.Errorf("concurrent lookup = %q, %q", country, status)
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		if err := CloseGeoIPCountry(); err != nil {
			t.Error(err)
		}
		if err := ConfigureGeoIPCountry(path); err != nil {
			t.Error(err)
		}
	}
	group.Wait()
}

func TestGeoIPCountryNameValidation(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{" Royaume-Uni ", "Royaume-Uni"},
		{"Émirats arabes unis", "Émirats arabes unis"},
		{"Côte d’Ivoire", "Côte d’Ivoire"},
		{"La Réunion", "La Réunion"},
		{"France\u202eEX", ""},
		{"France\u2066EX", ""},
		{"France\u200dEX", ""},
		{"bad\x1b[31mname", ""},
		{"bad\nname", ""},
		{string([]byte{0xff}), ""},
		{strings.Repeat("a", 129), ""},
	} {
		if got := geoIPSafeCountryName(tc.value); got != tc.want {
			t.Errorf("geoIPSafeCountryName(%q) = %q; want %q", tc.value, got, tc.want)
		}
	}
}

func TestGeoIPCountryNameFrenchAndEnglishFallback(t *testing.T) {
	for _, tc := range []struct {
		french, english, want string
	}{
		{"France", "France", "France"},
		{"", "United Kingdom", "United Kingdom"},
		{"bad\nname", "Japan", "Japan"},
		{"France\u202eEX", "France", "France"},
		{strings.Repeat("a", 129), "Australia", "Australia"},
		{"", "", ""},
	} {
		if got := geoIPCountryName(tc.french, tc.english); got != tc.want {
			t.Errorf("geoIPCountryName(%q, %q) = %q; want %q", tc.french, tc.english, got, tc.want)
		}
	}
}

func TestGeoIPCountryDatabaseSnapshotSurvivesReplacement(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	data, err := os.ReadFile(geoIPFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureGeoIPCountry(path); err != nil {
		t.Fatal(err)
	}
	// A database updater may replace or truncate the file. Existing lookups
	// use the immutable in-memory snapshot until an explicit reload.
	if err := os.WriteFile(path, []byte("replacement is invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, name, status := LookupGeoIPCountry("81.2.69.160"); code != "GB" || name != "Royaume-Uni" || status != GeoIPFound {
		t.Fatalf("snapshot changed after replacement: %q, %q, %q", code, name, status)
	}
	if err := ConfigureGeoIPCountry(path); !errors.Is(err, ErrGeoIPDatabase) {
		t.Fatalf("invalid replacement accepted: %v", err)
	}
	if _, _, status := LookupGeoIPCountry("81.2.69.160"); status != GeoIPDatabaseUnavailable {
		t.Fatalf("invalid replacement not surfaced: %q", status)
	}
}

func TestGeoIPCountryUnavailableAddressAndGlobalExceptions(t *testing.T) {
	if code, name, status := LookupGeoIPCountry(""); code != "" || name != "" || status != GeoIPAddressUnavailable {
		t.Fatalf("empty address = %q, %q, %q", code, name, status)
	}
	for _, address := range []string{"192.0.0.9", "192.0.0.10", "2001:1::1", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1"} {
		parsed := netip.MustParseAddr(address)
		if !geoIPPublicAddress(parsed) {
			t.Errorf("globally reachable IANA exception %s rejected", address)
		}
	}
}

func TestGeoIPCountryDatabaseTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"GeoLite2-Country", true},
		{"GeoIP2-Country", true},
		{"DBIP-Country-Lite", true},
		{"GeoIP2-City", true},
		{"GeoIP2-Enterprise", true},
		{"GeoLite2-ASN", false},
		{"", false},
	} {
		if got := geoIPCountryDatabaseType(tc.name); got != tc.want {
			t.Errorf("geoIPCountryDatabaseType(%q) = %v; want %v", tc.name, got, tc.want)
		}
	}
}
