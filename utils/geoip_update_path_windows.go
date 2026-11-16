//go:build windows

package utils

// File ACLs are not validated by the portable cache code. Fail closed rather
// than trust inherited ACLs: the service continues with GeoIP unavailable.
func secureGeoIPCacheRoot(_ string) (string, error) {
	return "", errGeoIPUpdateFilesystem
}
