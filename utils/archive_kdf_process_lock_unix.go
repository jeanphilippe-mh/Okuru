//go:build darwin || linux

package utils

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const archiveKDFProcessLockName = ".okuru-archive-kdf.lock"

// trustedArchiveKDFPath rejects ancestor directories that an unrelated local
// user could use to substitute the shared root. A trusted sticky directory
// such as /tmp is allowed: untrusted users cannot rename a trusted child.
func trustedArchiveKDFPath(root string) error {
	for current := root; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Untrusted archive KDF storage path")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("Untrusted archive KDF storage path owner")
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("Archive KDF storage path permits untrusted mutation")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

// tryArchiveKDFProcessLock serializes memory-heavy scrypt operations across
// cooperating processes sharing the same trusted local filesystem root. The
// fixed lock file is deliberately never unlinked: removing it would allow two
// processes to lock different inodes. OS close/crash releases the lock.
func tryArchiveKDFProcessLock() (release func(), busy bool, resultErr error) {
	root, err := stagingRoot(FILEFOLDER)
	if err != nil {
		return nil, false, err
	}
	if err := trustedArchiveKDFPath(root); err != nil {
		return nil, false, err
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, err
	}
	rootFile := os.NewFile(uintptr(rootFD), root)
	defer func() {
		if resultErr != nil || busy {
			_ = rootFile.Close()
		}
	}()
	openedRoot, err := rootFile.Stat()
	currentRoot, pathErr := os.Lstat(root)
	if err != nil || pathErr != nil || !openedRoot.IsDir() || !os.SameFile(openedRoot, currentRoot) {
		return nil, false, errors.New("Archive KDF storage root changed")
	}
	lockFD, err := unix.Openat(rootFD, archiveKDFProcessLockName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(lockFD), filepath.Join(root, archiveKDFProcessLockName))
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
		}
	}()
	var info unix.Stat_t
	if err := unix.Fstat(lockFD, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Nlink != 1 || info.Uid != uint32(os.Geteuid()) || info.Mode&0077 != 0 {
		return nil, false, errors.New("Untrusted archive KDF lock file")
	}
	locked, err := quotaTryLock(file)
	if err != nil {
		return nil, false, err
	}
	if !locked {
		return nil, true, nil
	}
	opened, err := file.Stat()
	current, pathErr := os.Lstat(filepath.Join(root, archiveKDFProcessLockName))
	rootNow, rootErr := os.Lstat(root)
	if err != nil || pathErr != nil || rootErr != nil || !os.SameFile(opened, current) || !os.SameFile(openedRoot, rootNow) {
		_ = quotaUnlock(file)
		return nil, false, errors.New("Archive KDF lock path changed")
	}
	keep = true
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = quotaUnlock(file)
			_ = file.Close()
			_ = rootFile.Close()
		})
	}, false, nil
}
