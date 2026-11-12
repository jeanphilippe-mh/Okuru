//go:build windows

package utils

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OpenStorageArchive opens the final object without following a reparse point.
// Callers that perform additional path operations must retain their own guard.
func OpenStorageArchive(path string) (*os.File, error) {
	guard, err := AcquireStoragePathGuard(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer guard.Close()
	base := filepath.Base(path)
	if !safeWindowsPathComponent(base) || strings.ContainsAny(base, `:\/`) {
		return nil, errors.New("Invalid archive name")
	}
	name, err := windows.NewNTUnicodeString(base)
	if err != nil {
		return nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		RootDirectory: guard.handles[len(guard.handles)-1],
		ObjectName:    name,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var status windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, windows.GENERIC_READ|windows.SYNCHRONIZE, &attributes, &status,
		nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	kind, kindErr := windows.GetFileType(h)
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || kindErr != nil || kind != windows.FILE_TYPE_DISK ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(h)
		return nil, errors.New("Archive is not a regular non-reparse file")
	}
	return os.NewFile(uintptr(h), path), nil
}
