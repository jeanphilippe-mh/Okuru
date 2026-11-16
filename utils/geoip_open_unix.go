//go:build unix

package utils

import (
	"os"

	"golang.org/x/sys/unix"
)

// Opening a swapped FIFO must not block service startup. Only regular files
// are accepted after opening; O_NONBLOCK has no effect on ordinary files.
func openGeoIPSnapshot(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
