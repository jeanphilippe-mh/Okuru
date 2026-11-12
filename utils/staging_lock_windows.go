//go:build windows

package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const stagingLockName = ".okuru-staging-lock-v1"
const stagingLockContents = "okuru-staging-lock-v1\n"

type LockedStagingDir struct {
	Path       string
	lock       *os.File
	guard      *StoragePathGuard
	stageGuard *StoragePathGuard
	mu         sync.Mutex
	closed     bool
	err        error
}

func validStagingPrefix(prefix string) bool {
	return prefix == ".okuru-upload-" || prefix == ".okuru-multipart-"
}

func validStagingName(name string) bool {
	for _, prefix := range []string{".okuru-upload-", ".okuru-multipart-"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if len(suffix) == 0 || len(suffix) > 20 {
			return false
		}
		for _, c := range suffix {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// Windows mode bits do not describe access controls. Require an owner and
// DACL that only give mutation rights to the service identity, administrators,
// or LocalSystem. Unknown ACE types fail closed. Parents must also be trusted.
func trustedWindowsDirectory(path string) error {
	return trustedWindowsDirectoryAccess(path, false)
}

func trustedWindowsDirectoryAccess(path string, ancestor bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Staging directory is not trusted")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("Staging directory is a reparse point")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("Staging owner unavailable")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	if !trusted(owner) {
		return errors.New("Staging owner is not trusted")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("Staging DACL is missing")
	}
	var mutations uint32 = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES | 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_WRITE | windows.GENERIC_ALL | 0x02000000
	if ancestor {
		// Creating unrelated siblings in an ancestor does not permit replacing
		// a protected child. Delete-child, deletion, ACL changes and generic
		// write/all still fail closed; this allows common Windows drive ACLs.
		mutations = windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40 |
			windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
			windows.GENERIC_WRITE | windows.GENERIC_ALL | 0x02000000
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return errors.New("Staging DACL cannot be inspected")
		}
		// Inherit-only entries do not grant access to this directory. Newly
		// created staging and quota directories are validated independently.
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if uint32(ace.Mask)&mutations != 0 {
				sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
				if !trusted(sid) {
					return errors.New("Staging DACL allows untrusted mutation")
				}
			}
		default:
			return errors.New("Staging DACL contains unsupported entries")
		}
	}
	return nil
}

func stagingRoot(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	// A writable parent permits path substitution even if the final directory
	// itself has a restrictive DACL. Check every component before resolving any
	// reparse points; the check is deliberately conservative and fails closed.
	if err := trustedWindowsPathChain(root); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if err := trustedWindowsPathChain(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// Ancestor checks require trusted ownership, restrict rights that can change
// a component or its protected children, and reject reparse points. This does
// not revoke rights on pre-existing handles; see deployment guidance.
func trustedWindowsPathChain(path string) error {
	ancestor := false
	for {
		if err := trustedWindowsDirectoryAccess(path, ancestor); err != nil {
			return fmt.Errorf("Untrusted staging path component: %w", err)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
		ancestor = true
	}
}

// SHARE_DELETE is essential on Windows: the marker must be renamed while
// locked and marked for deletion before its handle is closed.
func openSharedMarker(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		_ = windows.CloseHandle(h)
		return nil, errors.New("Invalid staging marker")
	}
	return os.NewFile(uintptr(h), path), nil
}

func CreateLockedStagingDir(root, prefix string) (_ *LockedStagingDir, resultErr error) {
	if !validStagingPrefix(prefix) {
		return nil, errors.New("Invalid staging prefix")
	}
	guard, err := AcquireStoragePathGuard(root)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			resultErr = errors.Join(resultErr, guard.Close())
		}
	}()
	root, err = stagingRoot(root)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(root, prefix)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			resultErr = errors.Join(resultErr, os.RemoveAll(dir))
		}
	}()
	if err := trustedWindowsDirectory(dir); err != nil {
		return nil, err
	}
	stageGuard, err := AcquireStoragePathGuard(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = stageGuard.Close()
		}
	}()
	initial, err := os.CreateTemp(dir, ".okuru-lock-init-")
	if err != nil {
		return nil, err
	}
	name := initial.Name()
	if err := initial.Close(); err != nil {
		return nil, err
	}
	marker, err := openSharedMarker(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = marker.Close()
		}
	}()
	locked, err := quotaTryLock(marker)
	if err != nil || !locked {
		return nil, errors.New("Could not lock staging marker")
	}
	if _, err = io.WriteString(marker, stagingLockContents); err != nil {
		return nil, err
	}
	if err = os.Rename(name, filepath.Join(dir, stagingLockName)); err != nil {
		return nil, err
	}
	ok = true
	retained = true
	return &LockedStagingDir{Path: dir, lock: marker, guard: guard, stageGuard: stageGuard}, nil
}

// Remove the marker while holding its lock, close the handle to complete
// deletion, and only then remove the directory (required by Windows).
func removeLockedStaging(dir string, marker *os.File, stageGuard *StoragePathGuard) error {
	defer stageGuard.Close()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return marker.Close()
	}
	if err != nil {
		return errors.Join(err, marker.Close())
	}
	var all error
	for _, e := range entries {
		if e.Name() == stagingLockName {
			continue
		}
		all = errors.Join(all, os.RemoveAll(filepath.Join(dir, e.Name())))
	}
	if all != nil {
		return errors.Join(all, marker.Close())
	}
	err = os.Remove(filepath.Join(dir, stagingLockName))
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return errors.Join(err, marker.Close())
	}
	if err = marker.Close(); err != nil {
		return err
	}
	// A directory cannot be removed while our own no-share-delete handle is
	// open. Its parent remains guarded until the surrounding operation ends.
	if err = stageGuard.Close(); err != nil {
		return err
	}
	if err = os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (d *LockedStagingDir) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		d.err = errors.Join(removeLockedStaging(d.Path, d.lock, d.stageGuard), d.guard.Close())
	}
	return d.err
}

func CleanupStaleStagingDirs(root string) error {
	guard, err := AcquireStoragePathGuard(root)
	if err != nil {
		return err
	}
	defer guard.Close()
	root, err = stagingRoot(root)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var all error
	for _, entry := range entries {
		if entry.IsDir() && validStagingName(entry.Name()) {
			all = errors.Join(all, cleanupStaleWindowsStaging(filepath.Join(root, entry.Name())))
		}
	}
	return all
}

func cleanupStaleWindowsStaging(dir string) error {
	dirInfo, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := trustedWindowsDirectory(dir); err != nil {
		return nil
	}
	markerPath := filepath.Join(dir, stagingLockName)
	marker, err := openSharedMarker(markerPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	locked, err := quotaTryLock(marker)
	if err != nil || !locked {
		_ = marker.Close()
		return err
	}
	stageGuard, err := AcquireStoragePathGuard(dir)
	if err != nil {
		_ = marker.Close()
		return err
	}
	defer stageGuard.Close()
	var contents [len(stagingLockContents) + 1]byte
	n, readErr := marker.ReadAt(contents[:], 0)
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || string(contents[:n]) != stagingLockContents {
		_ = marker.Close()
		return nil
	}
	currentDir, err := os.Lstat(dir)
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		_ = marker.Close()
		return nil
	}
	currentMarker, err := os.Lstat(markerPath)
	openedMarker, statErr := marker.Stat()
	if err != nil || statErr != nil || !os.SameFile(currentMarker, openedMarker) {
		_ = marker.Close()
		return nil
	}
	if err := removeLockedStaging(dir, marker, stageGuard); err != nil {
		return fmt.Errorf("Remove stale staging directory: %w", err)
	}
	return nil
}
