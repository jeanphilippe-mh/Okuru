//go:build linux || darwin

package utils

import (
	"math"
	"syscall"
)

func storageFilesystemCapacityOS(path string) (filesystemCapacity, error) {
	var disk syscall.Statfs_t
	if err := syscall.Statfs(path, &disk); err != nil || int64(disk.Bsize) <= 0 {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	var file syscall.Stat_t
	if err := syscall.Stat(path, &file); err != nil {
		return filesystemCapacity{}, ErrStorageCapacity
	}
	block := uint64(disk.Bsize)
	available := int64(math.MaxInt64)
	if uint64(disk.Bavail) <= uint64(math.MaxInt64)/block {
		available = int64(uint64(disk.Bavail) * block)
	}
	return filesystemCapacity{device: uint64(file.Dev), available: available}, nil
}
