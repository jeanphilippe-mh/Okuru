//go:build windows

package utils

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var uploadClusterGeometry = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDiskFreeSpaceW")

func checkUploadPartVolume(root string, entries int64) error {
	volume, err := windows.UTF16PtrFromString(filepath.VolumeName(root) + "\\")
	if err != nil {
		return ErrStorageCapacity
	}
	var sectors, bytes, free, total uint32
	ok, _, _ := uploadClusterGeometry.Call(uintptr(unsafe.Pointer(volume)), uintptr(unsafe.Pointer(&sectors)), uintptr(unsafe.Pointer(&bytes)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)))
	unit := uint64(sectors) * uint64(bytes)
	if ok == 0 || unit == 0 || unit > 64<<10 || uint64(free) < uint64(entries) {
		return ErrStorageCapacity
	}
	return nil
}
