//go:build windows

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsGuardBlocksRenameUntilClosed(t *testing.T) {
	root := privateWindowsTestRoot(t)
	guard, err := AcquireStoragePathGuard(root)
	if err != nil {
		t.Fatalf("cannot anchor test root and ancestors; check their ACLs: %v", err)
	}
	defer guard.Close()
	if err := os.WriteFile(filepath.Join(root, "ordinary"), []byte("test"), 0600); err != nil {
		t.Fatalf("guard blocked an ordinary child write: %v", err)
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err == nil {
		_ = os.Rename(moved, root)
		t.Fatal("directory renamed while ancestor handles were held")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, moved); err != nil {
		t.Fatalf("directory still locked after guard closed: %v", err)
	}
	if err := os.Rename(moved, root); err != nil {
		t.Fatalf("cannot restore test directory: %v", err)
	}
}

func TestWindowsGuardRejectsExistingDeleteHandle(t *testing.T) {
	root := privateWindowsTestRoot(t)
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("cannot create test delete-capable handle: %v", err)
	}
	defer windows.CloseHandle(h)
	guard, err := AcquireStoragePathGuard(root)
	if err == nil {
		_ = guard.Close()
		t.Fatal("guard accepted a pre-existing conflicting DELETE handle")
	}
}

func TestWindowsArchiveOpenRejectsReparseLeaf(t *testing.T) {
	root := privateWindowsTestRoot(t)
	regular := filepath.Join(root, "regular.zip")
	if err := os.WriteFile(regular, []byte("expected"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenStorageArchive(regular)
	if err != nil {
		t.Fatalf("regular archive refused: %v", err)
	}
	_ = f.Close()
	outside := filepath.Join(t.TempDir(), "outside.zip")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.zip")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("Windows symlink creation unavailable; run with Developer Mode or sufficient privilege: %v", err)
	}
	f, err = OpenStorageArchive(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("archive reparse point was accepted")
	}
}

func TestWindowsGuardRetainedForStagingAndQuota(t *testing.T) {
	root := privateWindowsTestRoot(t)
	stage, err := CreateLockedStagingDir(root, ".okuru-upload-")
	if err != nil {
		t.Fatal(err)
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err == nil {
		_ = os.Rename(moved, root)
		t.Fatal("active staging did not hold the root guard")
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "8388608")
	reservation, err := ReserveEncryptedUploadStorage(root, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, moved); err == nil {
		_ = os.Rename(moved, root)
		reservation.Release()
		t.Fatal("active quota reservation did not hold the root guard")
	}
	reservation.Release()
	if err := os.Rename(root, moved); err != nil {
		t.Fatalf("root remained locked after reservation release: %v", err)
	}
	if err := os.Rename(moved, root); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsStoragePathRejectsAmbiguousNames(t *testing.T) {
	for _, path := range []string{`C:\safe\name.\data`, `C:\safe\name \data`, `C:\safe\NUL.txt\data`, `C:\safe\COM¹\data`, `C:relative\data`, `\\server\share\data`, `\\?\C:\data`} {
		if err := validateWindowsStoragePath(path); err == nil {
			t.Errorf("accepted ambiguous path %q", path)
		}
	}
	for _, path := range []string{`C:\safe\data`, `C:\safe\COM10\data`, `relative\data`} {
		if err := validateWindowsStoragePath(path); err != nil {
			t.Errorf("rejected ordinary path %q: %v", path, err)
		}
	}
}

func TestWindowsStoragePathShortAliasMatchesObject(t *testing.T) {
	root := privateWindowsTestRoot(t)
	longPath, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, err := windows.GetShortPathName(longPath, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Skipf("8.3 aliases unavailable on this volume: %v", err)
	}
	shortPath := windows.UTF16ToString(buf[:n])
	if shortPath == root {
		t.Skip("volume did not provide a distinct 8.3 alias")
	}
	guard, err := AcquireStoragePathGuard(shortPath)
	if err != nil {
		t.Fatalf("short path did not resolve to the anchored Win32 object: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
}
