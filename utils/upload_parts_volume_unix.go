//go:build darwin || linux

package utils

import "golang.org/x/sys/unix"

func checkUploadPartVolume(root string, entries int64) error {
	var stat unix.Statfs_t
	if unix.Statfs(root, &stat) != nil || stat.Bsize <= 0 || stat.Bsize > 64<<10 ||
		(stat.Files != 0 && uint64(stat.Ffree) < uint64(entries)) {
		return ErrStorageCapacity
	}
	return nil
}
