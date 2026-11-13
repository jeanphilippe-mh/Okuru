//go:build darwin || linux

package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func archiveKDFTestRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func TestArchiveKDFProcessLockRejectsInsecurePermissions(t *testing.T) {
	root := useArchiveKDFTestRoot(t)
	path := filepath.Join(root, archiveKDFProcessLockName)
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	release, busy, err := tryArchiveKDFProcessLock()
	if release != nil {
		release()
	}
	if err == nil || busy {
		t.Fatalf("Lock with insecure permissions accepted: busy=%v err=%v", busy, err)
	}
}
