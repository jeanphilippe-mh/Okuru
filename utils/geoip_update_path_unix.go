//go:build darwin || linux

package utils

import (
	"os"
	"path/filepath"
)

// secureGeoIPCacheRoot validates all existing ancestors before creation, then
// validates the created directory again. Trusted sticky roots such as /tmp are
// permitted; attacker-writable ancestors and symlinks are not.
func secureGeoIPCacheRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", errGeoIPUpdateFilesystem
	}
	ancestor := abs
	for {
		_, err = os.Lstat(ancestor)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(ancestor) == ancestor {
			return "", errGeoIPUpdateFilesystem
		}
		ancestor = filepath.Dir(ancestor)
	}
	if err := trustedArchiveKDFPath(ancestor); err != nil {
		return "", errGeoIPUpdateFilesystem
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return "", errGeoIPUpdateFilesystem
	}
	root, err := stagingRoot(abs)
	if err != nil {
		return "", errGeoIPUpdateFilesystem
	}
	if err := trustedArchiveKDFPath(root); err != nil {
		return "", errGeoIPUpdateFilesystem
	}
	return root, nil
}
