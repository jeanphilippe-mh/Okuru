package utils

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

const maxGeoIPDatabaseBytes = 64 << 20

const (
	GeoIPFound               = "found"
	GeoIPNotFound            = "not_found"
	GeoIPNonPublic           = "non_public"
	GeoIPInvalidIP           = "invalid_ip"
	GeoIPAddressUnavailable  = "address_unavailable"
	GeoIPDisabled            = "disabled"
	GeoIPDatabaseUnavailable = "database_unavailable"
	GeoIPLookupError         = "lookup_error"
)

// ErrGeoIPDatabase avoids disclosing configured filesystem paths or database
// contents through startup errors. A failed optional database never blocks
// request handling; lookup results explicitly identify the unavailable state.
var ErrGeoIPDatabase = errors.New("country database unavailable or invalid")

var geoIPCountry = struct {
	sync.RWMutex
	reader *maxminddb.Reader
	status string
}{status: GeoIPDisabled}

// The IANA special-purpose registries mark these ranges as non-globally
// reachable, for documentation, benchmarking, or as deprecated allocations.
// Explicit global anycast exceptions are handled separately below.
// Source: https://www.iana.org/assignments/iana-ipv4-special-registry
//
//	https://www.iana.org/assignments/iana-ipv6-special-registry
var geoIPSpecialRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

var geoIPGlobalExceptions = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"),
	netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"),
	netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
}

// ConfigureGeoIPCountry loads and validates an optional local country-capable
// MMDB. It reads a bounded, immutable snapshot rather than memory-mapping a file
// an updater might truncate in place. Empty path disables lookups. A failed
// reload retains the previous verified snapshot; if none exists, lookups
// report GeoIPDatabaseUnavailable.
//
// Updates are picked up by calling this again or by restarting the service.
func ConfigureGeoIPCountry(path string) error {
	var reader *maxminddb.Reader
	status := GeoIPDisabled
	var result error
	if path != "" {
		status = GeoIPDatabaseUnavailable
		data, err := readGeoIPDatabase(path)
		if err == nil {
			reader, err = maxminddb.OpenBytes(data)
		}
		if err == nil {
			err = reader.Verify()
		}
		if err == nil && !geoIPCountryDatabaseType(reader.Metadata.DatabaseType) {
			err = ErrGeoIPDatabase
		}
		if err != nil {
			if reader != nil {
				_ = reader.Close()
				reader = nil
			}
			result = ErrGeoIPDatabase
		} else {
			status = GeoIPFound
		}
	}

	if result != nil {
		// A transient download, filesystem or validation failure must never
		// discard the last verified snapshot. Only mark the database as
		// unavailable when no such snapshot is loaded.
		MarkGeoIPDatabaseUnavailable()
		return result
	}
	geoIPCountry.Lock()
	old := geoIPCountry.reader
	geoIPCountry.reader = reader
	geoIPCountry.status = status
	if old != nil {
		_ = old.Close() // no lookup can hold the old reader while we hold the lock
	}
	geoIPCountry.Unlock()
	return result
}

// MarkGeoIPDatabaseUnavailable records a failed initialization when no verified
// snapshot exists, without discarding a snapshot used by concurrent requests.
// It accepts no path or error and therefore cannot disclose private data.
func MarkGeoIPDatabaseUnavailable() {
	geoIPCountry.Lock()
	if geoIPCountry.reader == nil {
		geoIPCountry.status = GeoIPDatabaseUnavailable
	}
	geoIPCountry.Unlock()
}

// Country, City and Enterprise databases can provide country.iso_code. Avoid
// silently accepting an ASN-only or another incompatible MMDB as country data.
func geoIPCountryDatabaseType(databaseType string) bool {
	databaseType = strings.ToLower(databaseType)
	return strings.Contains(databaseType, "country") || strings.Contains(databaseType, "city") || strings.Contains(databaseType, "enterprise")
}

func readGeoIPDatabase(path string) ([]byte, error) {
	// Check before opening to reject directories, devices and ordinary FIFOs.
	// The administrator must keep the configured directory protected from
	// replacement by untrusted local users.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxGeoIPDatabaseBytes {
		return nil, ErrGeoIPDatabase
	}
	file, err := openGeoIPSnapshot(path)
	if err != nil {
		return nil, ErrGeoIPDatabase
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxGeoIPDatabaseBytes {
		return nil, ErrGeoIPDatabase
	}
	data, err := io.ReadAll(io.LimitReader(file, maxGeoIPDatabaseBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxGeoIPDatabaseBytes {
		return nil, ErrGeoIPDatabase
	}
	return data, nil
}

// LookupGeoIPCountry returns the estimated ISO alpha-2 code, a French country
// name (falling back to English), and a status. Empty values mean no reliable
// value was inferred. The caller must supply the validated client address
// selected by ResolveClientAddress, not the proxy address. No network or DNS
// lookup is performed. Country names are limited to 128 bytes, checked for
// valid UTF-8, and rejected if they contain control or formatting characters.
func LookupGeoIPCountry(rawIP string) (countryCode, countryName, status string) {
	if rawIP == "" {
		return "", "", GeoIPAddressUnavailable
	}
	address, err := netip.ParseAddr(rawIP)
	if err != nil || address.Zone() != "" {
		return "", "", GeoIPInvalidIP
	}
	address = address.Unmap()
	if !geoIPPublicAddress(address) {
		return "", "", GeoIPNonPublic
	}

	geoIPCountry.RLock()
	defer geoIPCountry.RUnlock()
	if geoIPCountry.reader == nil {
		return "", "", geoIPCountry.status
	}
	match := geoIPCountry.reader.Lookup(address)
	if match.Err() != nil {
		return "", "", GeoIPLookupError
	}
	if !match.Found() {
		return "", "", GeoIPNotFound
	}
	// Decode into fixed-size fields so a malicious local database cannot force
	// large name allocations. The library enforces maxsize before allocation.
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code,maxsize:2"`
			Names   struct {
				French  string `maxminddb:"fr,maxsize:128"`
				English string `maxminddb:"en,maxsize:128"`
			} `maxminddb:"names"`
		} `maxminddb:"country"`
	}
	if err := match.Decode(&record); err != nil {
		return "", "", GeoIPLookupError
	}
	code := record.Country.ISOCode
	if code == "" {
		return "", "", GeoIPNotFound
	}
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "", "", GeoIPLookupError
	}
	return code, geoIPCountryName(record.Country.Names.French, record.Country.Names.English), GeoIPFound
}

func geoIPCountryName(french, english string) string {
	name := geoIPSafeCountryName(french)
	if name == "" {
		name = geoIPSafeCountryName(english)
	}
	return name
}

func geoIPSafeCountryName(name string) string {
	if len(name) > 128 || !utf8.ValidString(name) {
		return ""
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ""
		}
	}
	return strings.TrimSpace(name)
}

// GeoIPCountryBuildTime reports the local database build time, if loaded. It
// can be used in a startup event to identify the age of an estimate.
func GeoIPCountryBuildTime() (time.Time, bool) {
	geoIPCountry.RLock()
	defer geoIPCountry.RUnlock()
	if geoIPCountry.reader == nil {
		return time.Time{}, false
	}
	return geoIPCountry.reader.Metadata.BuildTime().UTC(), true
}

func geoIPPublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range geoIPGlobalExceptions {
		if prefix.Contains(address) {
			return true
		}
	}
	for _, prefix := range geoIPSpecialRanges {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// CloseGeoIPCountry waits for in-flight lookups before releasing the snapshot.
func CloseGeoIPCountry() error {
	geoIPCountry.Lock()
	defer geoIPCountry.Unlock()
	old := geoIPCountry.reader
	geoIPCountry.reader = nil
	geoIPCountry.status = GeoIPDisabled
	if old != nil {
		return old.Close()
	}
	return nil
}
