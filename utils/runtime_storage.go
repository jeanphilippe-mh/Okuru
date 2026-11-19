package utils

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	storageProbeInterval    = 10 * time.Second
	storageFreshness        = 30 * time.Second
	storageAdmissionTimeout = 2 * time.Second
)

type archiveDiskState uint8

const (
	archiveUnavailable archiveDiskState = iota
	archiveReadable
	archiveWritable
)

// The disk-only retention worker can be the first to open the configured
// directory, even while Redis is down. All workers share this identity.
var runtimeArchive = struct {
	sync.Mutex
	enabled bool
	pin     *os.Root
	info    os.FileInfo
}{}

// StartArchiveDirectoryTracking performs no I/O on the startup/listener path.
// The caller stops all workers before releasing the process's directory pin.
func StartArchiveDirectoryTracking() func() {
	runtimeArchive.Lock()
	runtimeArchive.enabled = true
	runtimeArchive.Unlock()
	return func() {
		runtimeArchive.Lock()
		defer runtimeArchive.Unlock()
		if runtimeArchive.pin != nil {
			_ = runtimeArchive.pin.Close()
		}
		runtimeArchive.enabled, runtimeArchive.pin, runtimeArchive.info = false, nil, nil
	}
}

// InitializeArchiveDirectory creates a new installation's storage directory.
// Once a directory has been observed, a lost mount must never be recreated.
func InitializeArchiveDirectory(path string) error {
	runtimeArchive.Lock()
	defer runtimeArchive.Unlock()
	if runtimeArchive.pin != nil {
		info, err := os.Stat(path)
		if err != nil || !os.SameFile(info, runtimeArchive.info) {
			return ErrStorageCapacity
		}
		return nil
	}
	return os.MkdirAll(path, 0700)
}

func openRuntimeArchiveRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	runtimeArchive.Lock()
	defer runtimeArchive.Unlock()
	if !runtimeArchive.enabled {
		return root, nil
	}
	info, err := root.Stat(".")
	if err == nil && runtimeArchive.pin == nil {
		// Validate the configured pathname and verify the actual descriptor
		// before retaining it as the reference used by future sweeps.
		var trusted string
		trusted, err = stagingRoot(path)
		if err == nil {
			var verified os.FileInfo
			verified, err = os.Stat(trusted)
			if err == nil && !os.SameFile(info, verified) {
				err = ErrStorageCapacity
			}
		}
		if err == nil {
			runtimeArchive.pin, err = root.OpenRoot(".")
			if err == nil {
				runtimeArchive.info = info
			}
		}
	} else if err == nil && !os.SameFile(info, runtimeArchive.info) {
		err = ErrStorageCapacity
	}
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// Keep the recovered directory referenced even if its pathname temporarily
// resolves to another volume. A replacement directory is never adopted.
type ArchiveStorageMonitor struct {
	configured string
	anchor     *os.Root
	original   os.FileInfo
	canary     string
	ownCanary  os.FileInfo
	identityMu sync.Mutex
	check      *storageIdentityCheck
}

type storageIdentityCheck struct {
	done    chan struct{}
	matches bool
}

// One pathname lookup at most may be blocked by the filesystem, regardless
// of the number of incoming uploads. Each caller waits at most two seconds.
func (m *ArchiveStorageMonitor) acceptsArchiveWrite() bool {
	m.identityMu.Lock()
	check := m.check
	if check == nil {
		check = &storageIdentityCheck{done: make(chan struct{})}
		m.check = check
		go func() {
			info, err := os.Stat(m.configured)
			check.matches = err == nil && os.SameFile(info, m.original)
			m.identityMu.Lock()
			m.check = nil
			close(check.done)
			m.identityMu.Unlock()
		}()
	}
	m.identityMu.Unlock()
	timer := time.NewTimer(storageAdmissionTimeout)
	defer timer.Stop()
	select {
	case <-check.done:
		return check.matches
	case <-timer.C:
		return false
	}
}

func OpenArchiveStorageMonitor(folder string) (*ArchiveStorageMonitor, error) {
	root, err := stagingRoot(folder)
	if err != nil {
		return nil, err
	}
	anchor, err := openRuntimeArchiveRoot(root)
	if err != nil {
		return nil, err
	}
	original, err := anchor.Stat(".")
	if err != nil {
		_ = anchor.Close()
		return nil, err
	}
	return &ArchiveStorageMonitor{configured: folder, anchor: anchor, original: original, canary: ".okuru-health-" + rand.Text()}, nil
}

func (m *ArchiveStorageMonitor) Close() error {
	_ = m.removeCanary()
	return m.anchor.Close()
}

func (m *ArchiveStorageMonitor) removeCanary() error {
	if m.ownCanary == nil {
		return nil
	}
	current, err := m.anchor.Lstat(m.canary)
	if os.IsNotExist(err) {
		m.ownCanary = nil
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(current, m.ownCanary) {
		return ErrStorageCapacity
	}
	if err := m.anchor.Remove(m.canary); err != nil {
		return err
	}
	m.ownCanary = nil
	return nil
}

func (m *ArchiveStorageMonitor) sample() archiveDiskState {
	root, err := stagingRoot(m.configured)
	if err != nil {
		return archiveUnavailable
	}
	guard, err := AcquireStoragePathGuard(root)
	if err != nil {
		return archiveUnavailable
	}
	defer guard.Close()
	current, err := os.Stat(root)
	if err != nil || !os.SameFile(m.original, current) {
		return archiveUnavailable
	}
	dir, err := m.anchor.Open(".")
	if err != nil {
		return archiveUnavailable
	}
	// Read at most one directory entry. Never inventory the files from a probe.
	_, readErr := dir.ReadDir(1)
	closeErr := dir.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return archiveUnavailable
	}
	if err := m.removeCanary(); err != nil {
		return archiveReadable
	}
	capacity, err := storageFilesystemCapacity(root)
	limits, limitsErr := readStorageLimits()
	if err != nil || limitsErr != nil || capacity.available <= limits.minFreeBytes {
		return archiveReadable
	}
	f, err := m.anchor.OpenFile(m.canary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return archiveReadable
	}
	m.ownCanary, err = f.Stat()
	if err != nil {
		_ = f.Close()
		_ = m.anchor.Remove(m.canary)
		return archiveReadable
	}
	_, writeErr := f.Write([]byte{1})
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr = f.Close()
	unlinkErr := m.removeCanary()
	if writeErr != nil || closeErr != nil || unlinkErr != nil {
		return archiveReadable
	}
	return archiveWritable
}

func (h *RuntimeHealth) recordStorage(state archiveDiskState, at time.Time, monitor *ArchiveStorageMonitor) {
	h.mu.Lock()
	h.diskState, h.diskChecked, h.monitor = state, at, monitor
	h.mu.Unlock()
}

// RunStorage samples serially. A blocked filesystem operation cannot spawn
// additional probes; its cached result ages out independently in HTTP handlers.
func (h *RuntimeHealth) RunStorage(ctx context.Context, monitor *ArchiveStorageMonitor) {
	ticker := time.NewTicker(storageProbeInterval)
	defer ticker.Stop()
	defer h.recordStorage(archiveUnavailable, time.Time{}, nil)
	var observed bool
	var previous archiveDiskState
	for ctx.Err() == nil {
		state := monitor.sample()
		if ctx.Err() != nil {
			return
		}
		h.recordStorage(state, time.Now(), monitor)
		if !observed || state != previous {
			entry := log.WithField("event", "health.storage_changed")
			switch state {
			case archiveWritable:
				entry.Info("Archive storage accepts uploads")
			case archiveReadable:
				entry.Warn("Archive storage cannot accept uploads")
			default:
				entry.Warn("The recovered archive directory is unavailable")
			}
			previous, observed = state, true
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
