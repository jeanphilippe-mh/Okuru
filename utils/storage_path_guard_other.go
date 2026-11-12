//go:build !windows

package utils

// StoragePathGuard is a Windows path-identity guard. Existing Unix checks and
// filesystem locking remain unchanged.
type StoragePathGuard struct{}

func AcquireStoragePathGuard(string) (*StoragePathGuard, error) { return &StoragePathGuard{}, nil }
func (g *StoragePathGuard) Close() error                        { return nil }
