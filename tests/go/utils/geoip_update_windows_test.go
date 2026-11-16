//go:build windows

package utils

import (
	"errors"
	"testing"
)

func TestGeoIPWindowsAutomaticCacheFailsClosed(t *testing.T) {
	if _, err := secureGeoIPCacheRoot(t.TempDir()); !errors.Is(err, errGeoIPUpdateFilesystem) {
		t.Fatalf("expected explicit unavailable status, got %v", err)
	}
}
