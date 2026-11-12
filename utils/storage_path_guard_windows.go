//go:build windows

package utils

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// StoragePathGuard holds directory handles from the volume root through the
// storage root, without FILE_SHARE_DELETE. It blocks a conflicting rename or
// deletion for the lifetime of the guard. The ACL and reparse checks are made
// on those same handles. No claim is made about pre-existing handles that can
// modify attributes, ACLs or reparse data; storage paths must be trusted before
// service startup. Callers must retain the guard throughout path-based I/O.
type StoragePathGuard struct {
	mu      sync.Mutex
	handles []windows.Handle
	closed  bool
}

func AcquireStoragePathGuard(root string) (_ *StoragePathGuard, resultErr error) {
	if err := validateWindowsStoragePath(root); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("invalid storage path")
	}
	root = filepath.Clean(root)
	if err := validateWindowsStoragePath(root); err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(root)
	// Restrict this implementation to drive-letter paths. Network shares,
	// device namespaces and junctions need separate filesystem validation.
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(root) || strings.Contains(root[len(volume):], ":") {
		return nil, errors.New("storage path must be on a local drive")
	}
	var paths []string
	for current := root; ; current = filepath.Dir(current) {
		paths = append(paths, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	guard := &StoragePathGuard{}
	defer func() {
		if resultErr != nil {
			_ = guard.Close()
		}
	}()
	for i := len(paths) - 1; i >= 0; i-- {
		var h windows.Handle
		if i == len(paths)-1 {
			// The local drive root is the only component opened by absolute name.
			name, nameErr := windows.UTF16PtrFromString(paths[i])
			if nameErr != nil {
				return nil, errors.New("invalid storage path")
			}
			h, err = windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_EXECUTE,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
				windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		} else {
			// Resolve each next component relative to the previously anchored
			// directory handle, and fail closed on a reparse point.
			name, nameErr := windows.NewNTUnicodeString(filepath.Base(paths[i]))
			if nameErr != nil {
				return nil, errors.New("invalid storage path")
			}
			attributes := windows.OBJECT_ATTRIBUTES{
				RootDirectory: guard.handles[len(guard.handles)-1],
				ObjectName:    name,
				Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
			}
			attributes.Length = uint32(unsafe.Sizeof(attributes))
			var status windows.IO_STATUS_BLOCK
			err = windows.NtCreateFile(&h, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_EXECUTE|windows.SYNCHRONIZE,
				&attributes, &status, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
				windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
		}
		if err != nil {
			return nil, errors.New("cannot anchor storage path")
		}
		guard.handles = append(guard.handles, h)
		if err := checkWindowsGuardHandle(h, i != 0); err != nil {
			return nil, err
		}
		if err := checkWindowsPathIdentity(paths[i], h); err != nil {
			return nil, err
		}
	}
	return guard, nil
}

// Check the user-supplied spelling before Win32 can normalize it and the
// resulting absolute spelling again. Relative . and .. are resolved by Abs;
// drive-relative and UNC/device paths are rejected as ambiguous.
func validateWindowsStoragePath(path string) error {
	if path == "" || strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return errors.New("invalid storage path")
	}
	volume := filepath.VolumeName(path)
	if volume != "" && (len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path)) {
		return errors.New("invalid storage volume")
	}
	for _, component := range strings.FieldsFunc(path[len(volume):], func(r rune) bool { return r == '/' || r == '\\' }) {
		if component != "." && component != ".." && !safeWindowsPathComponent(component) {
			return errors.New("ambiguous storage path component")
		}
	}
	return nil
}

// Compare the object opened through the anchored NT handle with the object
// Win32 path-based operations would open. This detects name aliases that
// resolve differently at the time of the check; it cannot stop a pre-existing
// handle from changing attributes or reparse data after that check.
func checkWindowsPathIdentity(path string, anchored windows.Handle) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("invalid storage path")
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("cannot verify storage path identity")
	}
	defer windows.CloseHandle(h)
	var a, b windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(anchored, &a) != nil || windows.GetFileInformationByHandle(h, &b) != nil ||
		b.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || b.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		a.VolumeSerialNumber != b.VolumeSerialNumber || a.FileIndexHigh != b.FileIndexHigh || a.FileIndexLow != b.FileIndexLow ||
		(a.FileIndexHigh == 0 && a.FileIndexLow == 0) {
		return errors.New("storage path resolves to a different object")
	}
	return nil
}

func checkWindowsGuardHandle(h windows.Handle, ancestor bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("storage path component is not a trusted directory")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("cannot inspect storage path security")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("storage path owner unavailable")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.New("service identity unavailable")
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	if !trusted(owner) {
		return errors.New("storage path owner is not trusted")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("storage path DACL unavailable")
	}
	var mutations uint32 = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES | 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_WRITE | windows.GENERIC_ALL | 0x02000000
	if ancestor {
		mutations = windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40 |
			windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
			windows.GENERIC_WRITE | windows.GENERIC_ALL | 0x02000000
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return errors.New("cannot inspect storage path DACL")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if uint32(ace.Mask)&mutations != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
				return errors.New("storage path allows untrusted mutation")
			}
		default:
			return errors.New("unsupported storage path DACL")
		}
	}
	return nil
}

func (g *StoragePathGuard) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	var all error
	for i := len(g.handles) - 1; i >= 0; i-- {
		all = errors.Join(all, windows.CloseHandle(g.handles[i]))
	}
	return all
}
