//go:build !linux && !darwin && !windows

package utils

import "errors"

const archiveKDFProcessLockName = ".okuru-archive-kdf.lock"

func tryArchiveKDFProcessLock() (func(), bool, error) {
	return nil, false, errors.New("Interprocess archive KDF locking is unsupported on this platform")
}
