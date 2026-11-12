//go:build darwin || linux

package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const stagingLockName = ".okuru-staging-lock-v1"
const stagingLockContents = "okuru-staging-lock-v1\n"

// LockedStagingDir holds an exclusive interprocess lock for a private staging
// directory. The Path remains owned by this instance until Close completes.
type LockedStagingDir struct {
	Path   string
	lock   *os.File
	mu     sync.Mutex
	closed bool
	err    error
}

func validStagingPrefix(prefix string) bool {
	return prefix == ".okuru-upload-" || prefix == ".okuru-multipart-"
}

func validStagingName(name string) bool {
	for _, prefix := range []string{".okuru-upload-", ".okuru-multipart-"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if len(suffix) == 0 || len(suffix) > 20 {
			return false
		}
		for _, c := range suffix {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// stagingRoot rejects writable shared roots. Locking prevents interference by
// cooperating instances, but cannot secure a directory controlled by an
// unrelated local user who can rename its contents.
func stagingRoot(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return "", errors.New("staging root is not a trusted directory")
	}
	return root, nil
}

func CreateLockedStagingDir(root, prefix string) (_ *LockedStagingDir, resultErr error) {
	if !validStagingPrefix(prefix) {
		return nil, errors.New("invalid staging prefix")
	}
	root, err := stagingRoot(root)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(root, prefix)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			resultErr = errors.Join(resultErr, os.RemoveAll(dir))
		}
	}()
	marker, err := os.CreateTemp(dir, ".okuru-lock-init-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = marker.Close()
		}
	}()
	if err = unix.Flock(int(marker.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	if _, err = io.WriteString(marker, stagingLockContents); err != nil {
		return nil, err
	}
	// A scanner only recognizes the marker after it has been locked.
	if err = os.Rename(marker.Name(), filepath.Join(dir, stagingLockName)); err != nil {
		return nil, err
	}
	ok = true
	return &LockedStagingDir{Path: dir, lock: marker}, nil
}

// removeStagingContents retains the marker until all other children are gone,
// permitting a later reconciliation if any removal fails.
func removeStagingContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var all error
	for _, e := range entries {
		if e.Name() == stagingLockName {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			all = errors.Join(all, err)
		}
	}
	if all != nil {
		return all
	}
	if err := os.Remove(filepath.Join(dir, stagingLockName)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (d *LockedStagingDir) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.err
	}
	d.closed = true
	d.err = errors.Join(removeStagingContents(d.Path), d.lock.Close())
	return d.err
}

// CleanupStaleStagingDirs removes only directories bearing our published marker
// whose lock can be acquired immediately. Existing unmarked directories are
// deliberately left intact, as are directories owned by active processes.
func CleanupStaleStagingDirs(root string) error {
	root, err := stagingRoot(root)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var all error
	for _, e := range entries {
		if !e.IsDir() || !validStagingName(e.Name()) {
			continue
		}
		if err := cleanupStaleStagingDir(filepath.Join(root, e.Name())); err != nil {
			all = errors.Join(all, err)
		}
	}
	return all
}

func cleanupStaleStagingDir(dir string) error {
	dirInfo, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || dirStat.Uid != uint32(os.Geteuid()) || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0700 {
		return nil
	}
	markerPath := filepath.Join(dir, stagingLockName)
	fd, err := unix.Open(markerPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
			return nil
		}
		return err
	}
	marker := os.NewFile(uintptr(fd), markerPath)
	defer marker.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return nil
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil
		}
		return err
	}
	var buf [len(stagingLockContents) + 1]byte
	n, readErr := marker.ReadAt(buf[:], 0)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if string(buf[:n]) != stagingLockContents {
		return nil
	}
	// Refuse a replaced directory or marker, rather than acting on a different
	// inode from the one whose lock we hold.
	currentDir, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	currentMarker, err := os.Lstat(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	openedMarker, err := marker.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(dirInfo, currentDir) || !os.SameFile(openedMarker, currentMarker) {
		return nil
	}
	if err := removeStagingContents(dir); err != nil {
		return fmt.Errorf("remove stale staging directory: %w", err)
	}
	return nil
}
