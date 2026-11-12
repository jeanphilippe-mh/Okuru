//go:build !linux && !darwin && !windows

package utils

import (
	"errors"
	"os"
)

func quotaTryLock(*os.File) (bool, error) {
	return false, errors.New("Interprocess quota locks are unsupported on this platform")
}

func quotaUnlock(*os.File) error {
	return errors.New("Interprocess quota locks are unsupported on this platform")
}
