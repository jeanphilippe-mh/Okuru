//go:build !darwin && !linux && !windows

package utils

import "errors"

type LockedStagingDir struct{ Path string }

func stagingRoot(string) (string, error) {
	return "", errors.New("interprocess staging locks are unsupported on this platform")
}

func CreateLockedStagingDir(root, prefix string) (*LockedStagingDir, error) {
	return nil, errors.New("interprocess staging locks are unsupported on this platform")
}
func (d *LockedStagingDir) Close() error { return nil }
func CleanupStaleStagingDirs(root string) error {
	return errors.New("interprocess staging locks are unsupported on this platform")
}
