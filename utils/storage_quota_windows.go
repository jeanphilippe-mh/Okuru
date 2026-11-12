//go:build windows

package utils

import (
	"math"

	"golang.org/x/sys/windows"
)

// GetDiskFreeSpaceEx reports free bytes available to this service account,
// accounting for Windows per-user disk quotas. The volume serial identifies
// aliases of the same volume; collisions only make reservations stricter.
func storageFilesystemCapacityOS(path string) (filesystemCapacity, error) {
	guard, err := AcquireStoragePathGuard(path)
	if err != nil {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	defer guard.Close()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(name, &available, nil, nil); err != nil {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	h, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	free := int64(math.MaxInt64)
	if available <= math.MaxInt64 {
		free = int64(available)
	}
	return filesystemCapacity{device: uint64(info.VolumeSerialNumber), available: free}, nil
}
