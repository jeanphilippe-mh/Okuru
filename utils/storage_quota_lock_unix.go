//go:build darwin || linux

package utils

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// quotaTryLock uses a separate open file description for each reservation.
func quotaTryLock(file *os.File) (bool, error) {
	return tryFileLock(file, unix.LOCK_EX)
}

func trySharedOwnerLock(file *os.File) (bool, error) {
	return tryFileLock(file, unix.LOCK_SH)
}

func tryFileLock(file *os.File, mode int) (bool, error) {
	err := unix.Flock(int(file.Fd()), mode|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return err == nil, err
}

func quotaUnlock(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
