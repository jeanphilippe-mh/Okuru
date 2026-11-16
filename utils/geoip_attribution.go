package utils

import "strings"

// GeoIPUsesDBIP reports whether a validated, active DB-IP Lite database is
// supplying country lookups. It exposes neither its path nor any visitor data.
func GeoIPUsesDBIP() bool {
	geoIPCountry.RLock()
	defer geoIPCountry.RUnlock()
	if geoIPCountry.reader == nil || geoIPCountry.status != GeoIPFound {
		return false
	}
	switch strings.ToLower(geoIPCountry.reader.Metadata.DatabaseType) {
	case "dbip-country-lite", "dbip-city-lite":
		return true
	default:
		return false
	}
}
