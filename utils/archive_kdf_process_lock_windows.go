//go:build windows

package utils

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const archiveKDFProcessLockName = ".okuru-archive-kdf.lock"

// trustedArchiveKDFLock rejects file ACLs that would let an unrelated local
// principal open or lock the shared file. The descriptor is checked on the
// same handle used for the byte-range lock, not on a pathname lookup.
func trustedArchiveKDFLock(handle windows.Handle, serviceSID *windows.SID) error {
	security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("Cannot inspect archive KDF lock security")
	}
	owner, _, err := security.Owner()
	if err != nil || owner == nil {
		return errors.New("Archive KDF lock owner unavailable")
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(serviceSID) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	if !trusted(owner) {
		return errors.New("Untrusted archive KDF lock owner")
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil {
		return errors.New("Archive KDF lock DACL unavailable")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return errors.New("Cannot inspect archive KDF lock DACL")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Mask != 0 && !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
				return errors.New("Archive KDF lock permits untrusted access")
			}
		default:
			return errors.New("Unsupported archive KDF lock DACL")
		}
	}
	return nil
}

// tryArchiveKDFProcessLock holds an anchored directory chain and a persistent
// lock-file handle without FILE_SHARE_DELETE. Cooperating processes must use
// the same trusted root. The file is never removed while the application runs.
func tryArchiveKDFProcessLock() (release func(), busy bool, resultErr error) {
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if resultErr != nil || busy {
			_ = guard.Close()
		}
	}()
	root, err := stagingRoot(FILEFOLDER)
	if err != nil {
		return nil, false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, false, errors.New("Archive KDF service identity unavailable")
	}
	// An explicit protected DACL prevents a new lock file inheriting broad
	// read rights, which would otherwise permit another user to lock it.
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, false, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	path := filepath.Join(root, archiveKDFProcessLockName)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes, windows.OPEN_ALWAYS,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(handle), path)
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return nil, false, errors.New("Untrusted archive KDF lock file")
	}
	if err := trustedArchiveKDFLock(handle, user.User.Sid); err != nil {
		return nil, false, err
	}
	locked, err := quotaTryLock(file)
	if err != nil {
		return nil, false, err
	}
	if !locked {
		return nil, true, nil
	}
	opened, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		_ = quotaUnlock(file)
		return nil, false, errors.New("Archive KDF lock path changed")
	}
	keep = true
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = quotaUnlock(file)
			_ = file.Close()
			_ = guard.Close()
		})
	}, false, nil
}
