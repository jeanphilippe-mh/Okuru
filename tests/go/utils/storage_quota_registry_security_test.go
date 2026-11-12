//go:build darwin || linux

package utils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestQuotaRegistryRejectsUntrustedDirectoryAndMarkers(t *testing.T) {
	t.Run("group-writable registry", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, quotaRegistryName)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0770); err != nil {
			t.Fatal(err)
		}
		if _, err := ReserveEncryptedUploadStorage(root, 0, 1); !errors.Is(err, ErrStorageCapacity) {
			t.Fatalf("untrusted registry accepted: %v", err)
		}
	})
	t.Run("symlink admission lock", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, quotaRegistryName)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(dir, quotaAdmissionName)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReserveEncryptedUploadStorage(root, 0, 1); !errors.Is(err, ErrStorageCapacity) {
			t.Fatalf("symlink lock accepted: %v", err)
		}
	})
	t.Run("unrecognized record", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, quotaRegistryName)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "unexpected"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReserveEncryptedUploadStorage(root, 0, 1); !errors.Is(err, ErrStorageCapacity) {
			t.Fatalf("unrecognized record accepted: %v", err)
		}
	})
}
