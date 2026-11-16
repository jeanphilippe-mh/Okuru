//go:build !unix

package utils

import "os"

func openGeoIPSnapshot(path string) (*os.File, error) {
	return os.Open(path)
}
