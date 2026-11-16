//go:build !darwin && !linux && !windows

package utils

func secureGeoIPCacheRoot(string) (string, error) {
	return "", errGeoIPUpdateFilesystem
}
