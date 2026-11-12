//go:build !windows

package utils

import "os"

func OpenStorageArchive(path string) (*os.File, error) { return os.Open(path) }
