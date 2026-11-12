package utils

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Cooperating processes using the same storage root share reservations.
// This remains an application admission budget, not a filesystem quota.
var (
	ErrStorageQuotaConfiguration = errors.New("Invalid storage quota configuration")
	ErrStorageCapacity           = errors.New("Insufficient storage capacity")
)

const (
	defaultStorageQuotaBytes = int64(8 << 30)
	defaultMinimumFreeBytes  = int64(1 << 30)
	defaultMaxArchives       = int64(1000)
	maxQuotaScanEntries      = 10000
)

type storageLimits struct {
	maxBytes, minFreeBytes, maxArchives int64
}

type filesystemCapacity struct {
	device    uint64
	available int64
}

// A replaceable function allows tests to exercise capacity without filling a
// real disk. Platform-specific implementations fail closed where unsupported.
var storageFilesystemCapacity = storageFilesystemCapacityOS

var storageQuotaState = struct {
	sync.Mutex
	roots   map[string]storageRootReservation
	devices map[uint64]int64
	local   map[string]bool
}{roots: make(map[string]storageRootReservation), devices: make(map[uint64]int64), local: make(map[string]bool)}

type storageRootReservation struct {
	bytes    int64
	archives int64
}

// StorageReservation must be released exactly when the upload is finished,
// after its temporary and staged files have been cleaned up. Release is safe
// to call more than once.
type StorageReservation struct {
	once        sync.Once
	root        string
	rootBytes   int64
	deviceBytes map[uint64]int64
	record      *os.File
	recordPath  string
	pathGuards  []*StoragePathGuard
}

func quotaPositiveEnv(name string, fallback int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, ErrStorageQuotaConfiguration
	}
	return parsed, nil
}

func readStorageLimits() (storageLimits, error) {
	var limits storageLimits
	var err error
	if limits.maxBytes, err = quotaPositiveEnv("OKURU_STORAGE_QUOTA_BYTES", defaultStorageQuotaBytes); err != nil {
		return limits, err
	}
	if limits.minFreeBytes, err = quotaPositiveEnv("OKURU_STORAGE_MIN_FREE_BYTES", defaultMinimumFreeBytes); err != nil {
		return limits, err
	}
	if limits.maxArchives, err = quotaPositiveEnv("OKURU_STORAGE_MAX_ARCHIVES", defaultMaxArchives); err != nil {
		return limits, err
	}
	return limits, nil
}

func quotaAdd(values ...int64) (int64, error) {
	var total int64
	for _, value := range values {
		if value < 0 || total > math.MaxInt64-value {
			return 0, ErrStorageQuotaConfiguration
		}
		total += value
	}
	return total, nil
}

func quotaDirectory(path string) (string, error) {
	if path == "" {
		return "", ErrStorageCapacity
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrStorageCapacity
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", ErrStorageCapacity
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", ErrStorageCapacity
	}
	return resolved, nil
}

// storageUsage counts regular files, including unfinished staging files. It
// does not follow links: an unexpected symlink causes a fail-closed denial.
func storageUsage(root string) (int64, int64, error) {
	var bytes, archives int64
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return ErrStorageCapacity
		}
		entries++
		if entries > maxQuotaScanEntries || entry.Type()&os.ModeSymlink != 0 {
			return ErrStorageCapacity
		}
		if entry.IsDir() {
			if path == filepath.Join(root, quotaRegistryName) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrStorageCapacity
		}
		bytes, err = quotaAdd(bytes, info.Size())
		if err != nil {
			return ErrStorageCapacity
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
			archives++
		}
		return nil
	})
	if err != nil {
		return 0, 0, ErrStorageCapacity
	}
	return bytes, archives, nil
}

// ReserveUploadStorage reserves space before multipart parsing begins.
// maxBodyBytes must be the complete bounded request body size; for unknown
// Content-Length the caller must pass the configured maximum body size.
// maxFiles must be the maximum actually enforced by the upload controller.
// The reservation estimates staging + ZIP + ZIP overhead on storageDir and a
// complete multipart spill on tempDir. On a shared volume these are added before
// checking free space. The ZIP allowance is conservative for this repository's
// standard store/deflate writer and its <=255-byte filenames; it must be
// revisited if the archive implementation or filename constraints change.
//
// Actual files are re-counted on each admission and reservations are added to
// that count, so partially written uploads can be counted twice. This can deny
// an otherwise possible upload but does not grant additional capacity.
func ReserveUploadStorage(storageDir, tempDir string, maxBodyBytes int64, maxFiles int) (*StorageReservation, error) {
	if tempDir == "" {
		return nil, ErrStorageCapacity
	}
	return reserveUploadStorage(storageDir, tempDir, maxBodyBytes, maxFiles)
}

// ReserveEncryptedUploadStorage is only for the streaming multipart path
// whose staging files and final archive are both written under storageDir.
// Unlike ReserveUploadStorage, it must not be used by a parser that spills to
// the system temporary directory. Two copies and archive overhead remain
// reserved on the storage filesystem.
func ReserveEncryptedUploadStorage(storageDir string, maxBodyBytes int64, maxFiles int) (*StorageReservation, error) {
	return reserveUploadStorage(storageDir, "", maxBodyBytes, maxFiles)
}

func reserveUploadStorage(storageDir, tempDir string, maxBodyBytes int64, maxFiles int) (*StorageReservation, error) {
	if maxBodyBytes < 0 || maxFiles <= 0 || maxFiles > 1000 {
		return nil, ErrStorageQuotaConfiguration
	}
	limits, err := readStorageLimits()
	if err != nil {
		return nil, err
	}
	guard, err := AcquireStoragePathGuard(storageDir)
	if err != nil {
		return nil, ErrStorageCapacity
	}
	guards := []*StoragePathGuard{guard}
	retained := false
	defer func() {
		if !retained {
			for i := len(guards) - 1; i >= 0; i-- {
				_ = guards[i].Close()
			}
		}
	}()
	if tempDir != "" {
		tempGuard, err := AcquireStoragePathGuard(tempDir)
		if err != nil {
			return nil, ErrStorageCapacity
		}
		guards = append(guards, tempGuard)
	}
	root, err := quotaDirectory(storageDir)
	if err != nil {
		return nil, err
	}
	var temp string
	if tempDir != "" {
		temp, err = quotaDirectory(tempDir)
		if err != nil {
			return nil, err
		}
	}
	// Two storage copies plus one percent compression allowance, a generous
	// per-entry ZIP envelope, and a fixed final-directory allowance.
	storageBytes, err := quotaAdd(maxBodyBytes, maxBodyBytes, maxBodyBytes/100, int64(maxFiles)*1024, 1<<20)
	if err != nil {
		return nil, err
	}
	rootBytes := storageBytes
	var tempBytes int64
	if temp != "" {
		tempBytes, err = quotaAdd(maxBodyBytes, 1<<20)
		if err != nil {
			return nil, err
		}
		// Traditional parsers may spill inside the quota directory.
		relativeTemp, err := filepath.Rel(root, temp)
		if err != nil {
			return nil, ErrStorageCapacity
		}
		if relativeTemp == "." || (relativeTemp != ".." && !strings.HasPrefix(relativeTemp, ".."+string(filepath.Separator))) {
			rootBytes, err = quotaAdd(rootBytes, tempBytes)
			if err != nil {
				return nil, err
			}
		}
	}

	storageQuotaState.Lock()
	defer storageQuotaState.Unlock()
	registry, err := acquireQuotaRegistry(root)
	if err != nil {
		return nil, err
	}
	defer registry.close()
	other, err := registry.activeReservations(storageQuotaState.local)
	if err != nil {
		return nil, err
	}
	used, archives, err := storageUsage(root)
	if err != nil {
		return nil, err
	}
	rootReserved := storageQuotaState.roots[root]
	needed, err := quotaAdd(used, rootReserved.bytes, other.rootBytes, rootBytes)
	activeArchives, countErr := quotaAdd(archives, rootReserved.archives, other.archives, 1)
	if err != nil || countErr != nil || needed > limits.maxBytes || activeArchives > limits.maxArchives {
		return nil, ErrStorageCapacity
	}

	storageDisk, err := storageFilesystemCapacity(root)
	if err != nil {
		return nil, ErrStorageCapacity
	}
	deviceBytes := map[uint64]int64{storageDisk.device: storageBytes}
	deviceAvailable := map[uint64]int64{storageDisk.device: storageDisk.available}
	if temp != "" {
		tempDisk, err := storageFilesystemCapacity(temp)
		if err != nil {
			return nil, ErrStorageCapacity
		}
		if previous, same := deviceBytes[tempDisk.device]; same {
			deviceBytes[tempDisk.device], err = quotaAdd(previous, tempBytes)
			if err != nil {
				return nil, err
			}
			if tempDisk.available < deviceAvailable[tempDisk.device] {
				deviceAvailable[tempDisk.device] = tempDisk.available
			}
		} else {
			deviceBytes[tempDisk.device] = tempBytes
			deviceAvailable[tempDisk.device] = tempDisk.available
		}
	}
	for device, reservation := range deviceBytes {
		total, err := quotaAdd(limits.minFreeBytes, storageQuotaState.devices[device], other.devices[device], reservation)
		if err != nil || total > deviceAvailable[device] {
			return nil, ErrStorageCapacity
		}
	}
	// Keep the registry directory itself anchored while its reservation file
	// exists, not just while the admission lock is held.
	registryGuard, err := AcquireStoragePathGuard(registry.dir)
	if err != nil {
		return nil, ErrStorageCapacity
	}
	guards = append(guards, registryGuard)
	record, recordPath, err := registry.createReservation(rootBytes, deviceBytes)
	if err != nil {
		return nil, err
	}
	rootReserved.bytes += rootBytes
	rootReserved.archives++
	storageQuotaState.roots[root] = rootReserved
	for device, reservation := range deviceBytes {
		storageQuotaState.devices[device] += reservation
	}
	storageQuotaState.local[recordPath] = true
	retained = true
	return &StorageReservation{root: root, rootBytes: rootBytes, deviceBytes: deviceBytes, record: record, recordPath: recordPath, pathGuards: guards}, nil
}

func (reservation *StorageReservation) Release() {
	if reservation == nil {
		return
	}
	reservation.once.Do(func() {
		defer func() {
			for i := len(reservation.pathGuards) - 1; i >= 0; i-- {
				_ = reservation.pathGuards[i].Close()
			}
		}()
		storageQuotaState.Lock()
		defer storageQuotaState.Unlock()
		// Once the request is finished its reservation may be released even if
		// admission is busy. An unlocked leftover record is reaped later.
		registry, err := acquireQuotaRegistry(reservation.root)
		if err == nil {
			defer registry.close()
		}
		_ = quotaUnlock(reservation.record)
		_ = reservation.record.Close()
		if registry != nil {
			_ = os.Remove(reservation.recordPath)
		}
		delete(storageQuotaState.local, reservation.recordPath)
		root := storageQuotaState.roots[reservation.root]
		root.bytes -= reservation.rootBytes
		root.archives--
		if root.archives == 0 {
			delete(storageQuotaState.roots, reservation.root)
		} else {
			storageQuotaState.roots[reservation.root] = root
		}
		for device, bytes := range reservation.deviceBytes {
			storageQuotaState.devices[device] -= bytes
			if storageQuotaState.devices[device] == 0 {
				delete(storageQuotaState.devices, device)
			}
		}
	})
}
