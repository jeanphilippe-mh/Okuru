//go:build !linux && !darwin && !windows

package utils

// Until a platform-specific free-space check is provided, fail closed rather
// than accepting uploads on an unverifiable filesystem.
func storageFilesystemCapacityOS(string) (filesystemCapacity, error) {
	return filesystemCapacity{}, ErrStorageCapacity
}
