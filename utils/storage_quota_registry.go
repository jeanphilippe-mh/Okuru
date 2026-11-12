package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const quotaRegistryName = ".okuru-quota"
const quotaAdmissionName = "admission.lock"

// Every cooperating process must use the same private storage root. The
// registry files contain no file names, user data or secrets: the reservation
// amounts are encoded in their names so Windows byte-range locks never prevent
// another process from inspecting the accounting record.
type quotaRegistry struct {
	dir   string
	lock  *os.File
	guard *StoragePathGuard
}

type quotaRegistryUsage struct {
	rootBytes int64
	archives  int64
	devices   map[uint64]int64
}

func acquireQuotaRegistry(root string) (_ *quotaRegistry, resultErr error) {
	trusted, err := stagingRoot(root)
	if err != nil || trusted != root {
		return nil, ErrStorageCapacity
	}
	dir := filepath.Join(root, quotaRegistryName)
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrStorageCapacity
	}
	guard, err := AcquireStoragePathGuard(dir)
	if err != nil {
		return nil, ErrStorageCapacity
	}
	retained := false
	defer func() {
		if !retained {
			_ = guard.Close()
		}
	}()
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrStorageCapacity
	}
	trustedDir, err := stagingRoot(dir)
	if err != nil || trustedDir != dir {
		return nil, ErrStorageCapacity
	}
	path := filepath.Join(dir, quotaAdmissionName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, ErrStorageCapacity
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrStorageCapacity
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrStorageCapacity
	}
	opened, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, current) {
		_ = file.Close()
		return nil, ErrStorageCapacity
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		locked, err := quotaTryLock(file)
		if err != nil {
			_ = file.Close()
			return nil, ErrStorageCapacity
		}
		if locked {
			retained = true
			return &quotaRegistry{dir: dir, lock: file, guard: guard}, nil
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, ErrStorageCapacity
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *quotaRegistry) close() {
	_ = quotaUnlock(r.lock)
	_ = r.lock.Close()
	_ = r.guard.Close()
}

// Names are deliberately fixed in structure and bounded so malformed records
// fail closed instead of causing an underestimated reservation.
func quotaRecordName(rootBytes int64, devices map[uint64]int64) (string, error) {
	if rootBytes < 0 || len(devices) < 1 || len(devices) > 2 {
		return "", ErrStorageQuotaConfiguration
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("r-%s-%x", hex.EncodeToString(nonce[:]), rootBytes)
	for device, bytes := range devices {
		if bytes < 0 {
			return "", ErrStorageQuotaConfiguration
		}
		name += fmt.Sprintf("-%x-%x", device, bytes)
	}
	return name, nil
}

func parseQuotaRecord(name string) (int64, map[uint64]int64, error) {
	parts := strings.Split(name, "-")
	if (len(parts) != 5 && len(parts) != 7) || parts[0] != "r" || len(parts[1]) != 32 {
		return 0, nil, ErrStorageCapacity
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return 0, nil, ErrStorageCapacity
	}
	value, err := strconv.ParseUint(parts[2], 16, 63)
	if err != nil || value > math.MaxInt64 {
		return 0, nil, ErrStorageCapacity
	}
	devices := make(map[uint64]int64, (len(parts)-3)/2)
	for i := 3; i < len(parts); i += 2 {
		device, err1 := strconv.ParseUint(parts[i], 16, 64)
		amount, err2 := strconv.ParseUint(parts[i+1], 16, 63)
		if _, exists := devices[device]; err1 != nil || err2 != nil || exists {
			return 0, nil, ErrStorageCapacity
		}
		devices[device] = int64(amount)
	}
	return int64(value), devices, nil
}

// The caller holds both the process mutex and the registry admission lock.
func (r *quotaRegistry) activeReservations(local map[string]bool) (quotaRegistryUsage, error) {
	usage := quotaRegistryUsage{devices: make(map[uint64]int64)}
	entries, err := os.ReadDir(r.dir)
	if err != nil || len(entries) > maxQuotaScanEntries {
		return usage, ErrStorageCapacity
	}
	for _, entry := range entries {
		if entry.Name() == quotaAdmissionName {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return usage, ErrStorageCapacity
		}
		rootBytes, devices, err := parseQuotaRecord(entry.Name())
		if err != nil {
			return usage, err
		}
		path := filepath.Join(r.dir, entry.Name())
		if local[path] {
			continue
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return usage, ErrStorageCapacity
		}
		opened, err := file.Stat()
		current, pathErr := os.Lstat(path)
		if err != nil || pathErr != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, current) {
			_ = file.Close()
			return usage, ErrStorageCapacity
		}
		locked, lockErr := quotaTryLock(file)
		if lockErr != nil {
			_ = file.Close()
			return usage, ErrStorageCapacity
		}
		if locked {
			// The owner has exited. The admission lock prevents a new owner
			// from reusing this name between unlock, close and removal.
			unlockErr := quotaUnlock(file)
			closeErr := file.Close()
			removeErr := os.Remove(path)
			if unlockErr != nil || closeErr != nil || (removeErr != nil && !errors.Is(removeErr, os.ErrNotExist)) {
				return usage, ErrStorageCapacity
			}
			continue
		}
		_ = file.Close()
		usage.rootBytes, err = quotaAdd(usage.rootBytes, rootBytes)
		if err != nil {
			return usage, ErrStorageCapacity
		}
		usage.archives++
		for device, amount := range devices {
			usage.devices[device], err = quotaAdd(usage.devices[device], amount)
			if err != nil {
				return usage, ErrStorageCapacity
			}
		}
	}
	return usage, nil
}

func (r *quotaRegistry) createReservation(rootBytes int64, devices map[uint64]int64) (*os.File, string, error) {
	name, err := quotaRecordName(rootBytes, devices)
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(r.dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, "", ErrStorageCapacity
	}
	locked, err := quotaTryLock(file)
	if err != nil || !locked {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, "", ErrStorageCapacity
	}
	return file, path, nil
}
