package utils

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func prepareQuotaTest(t *testing.T) (string, string) {
	t.Helper()
	root, err := quotaDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	temp, err := quotaDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldCapacity := storageFilesystemCapacity
	storageQuotaState.Lock()
	storageQuotaState.roots = make(map[string]storageRootReservation)
	storageQuotaState.devices = make(map[uint64]int64)
	storageQuotaState.Unlock()
	storageFilesystemCapacity = func(string) (filesystemCapacity, error) {
		return filesystemCapacity{device: 1, available: 1 << 30}, nil
	}
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(100<<20))
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_MAX_ARCHIVES", "1000")
	t.Cleanup(func() {
		storageQuotaState.Lock()
		defer storageQuotaState.Unlock()
		if len(storageQuotaState.roots) != 0 || len(storageQuotaState.devices) != 0 {
			t.Errorf("test leaked reservations: roots=%v devices=%v", storageQuotaState.roots, storageQuotaState.devices)
		}
		storageFilesystemCapacity = oldCapacity
	})
	return root, temp
}

func TestStorageQuotaCountsExistingFilesAndReleases(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	if err := os.WriteFile(filepath.Join(root, "existing.zip"), make([]byte, 16), 0600); err != nil {
		t.Fatal(err)
	}
	perUpload := int64((1 << 20) + 1024)
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(perUpload+16))
	r, err := ReserveUploadStorage(root, temp, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveUploadStorage(root, temp, 0, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("second reservation exceeded quota: %v", err)
	}
	r.Release()
	r.Release()
	r, err = ReserveUploadStorage(root, temp, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
}

func TestStorageQuotaAccountsExistingArchiveCount(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	if err := os.WriteFile(filepath.Join(root, "one.zip"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKURU_STORAGE_MAX_ARCHIVES", "1")
	if _, err := ReserveUploadStorage(root, temp, 0, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("archive count was not enforced: %v", err)
	}
}

func TestStorageQuotaAddsReservationsOnSameFilesystem(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	// Body=0 and one allowed file: 1 MiB + 1 KiB on storage, 1 MiB on temp.
	available := int64((2 << 20) + 1024)
	storageFilesystemCapacity = func(string) (filesystemCapacity, error) {
		return filesystemCapacity{device: 1, available: available}, nil
	}
	if _, err := ReserveUploadStorage(root, temp, 0, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("minimum free space was not retained: %v", err)
	}
	available++
	r, err := ReserveUploadStorage(root, temp, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
}

func TestStorageQuotaChecksSeparateFilesystems(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	tempAvailable := int64(1 << 20)
	storageFilesystemCapacity = func(path string) (filesystemCapacity, error) {
		if path == root {
			return filesystemCapacity{device: 1, available: 20 << 20}, nil
		}
		if path == temp {
			return filesystemCapacity{device: 2, available: tempAvailable}, nil
		}
		return filesystemCapacity{}, ErrStorageCapacity
	}
	if _, err := ReserveUploadStorage(root, temp, 0, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("temporary volume reserve was not checked: %v", err)
	}
	tempAvailable++
	r, err := ReserveUploadStorage(root, temp, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	r.Release()
}

func TestStorageQuotaCountsMultipartInsideStorageRoot(t *testing.T) {
	root, _ := prepareQuotaTest(t)
	temp := filepath.Join(root, "temporary")
	if err := os.Mkdir(temp, 0700); err != nil {
		t.Fatal(err)
	}
	// Enough for staging and ZIP, but not for multipart spill in the same root.
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint((1<<20)+1024))
	if _, err := ReserveUploadStorage(root, temp, 0, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("multipart spill was omitted from the storage quota: %v", err)
	}
}

func TestEncryptedUploadQuotaIgnoresSystemTemporaryVolume(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	t.Setenv("TMPDIR", filepath.Join(temp, "missing"))
	storageFilesystemCapacity = func(path string) (filesystemCapacity, error) {
		if path != root {
			return filesystemCapacity{}, errors.New("unexpected temporary-volume check")
		}
		return filesystemCapacity{device: 1, available: 100 << 20}, nil
	}
	r, err := ReserveEncryptedUploadStorage(root, 1<<20, 100)
	if err != nil {
		t.Fatalf("encrypted multipart incorrectly depends on system temporary storage: %v", err)
	}
	r.Release()
	if _, err := ReserveUploadStorage(root, filepath.Join(temp, "missing"), 1<<20, 100); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("traditional multipart lost its temporary-volume check: %v", err)
	}
}

func TestEncryptedUploadQuotaReservesBothCopies(t *testing.T) {
	root, _ := prepareQuotaTest(t)
	body := int64(4 << 20)
	// staging ciphertext + final archive, plus the existing overhead reserve.
	needed := 2*body + body/100 + 100*1024 + 1<<20
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(needed-1))
	if _, err := ReserveEncryptedUploadStorage(root, body, 100); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("quota accepted less than two copies: %v", err)
	}
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(needed))
	available := needed
	storageFilesystemCapacity = func(path string) (filesystemCapacity, error) {
		if path != root {
			return filesystemCapacity{}, errors.New("unexpected filesystem")
		}
		return filesystemCapacity{device: 1, available: available}, nil
	}
	if _, err := ReserveEncryptedUploadStorage(root, body, 100); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("free-space threshold was not retained: %v", err)
	}
	available++ // The test configuration retains one byte of free space.
	r, err := ReserveEncryptedUploadStorage(root, body, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveEncryptedUploadStorage(root, body, 100); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("concurrent reservation bypassed the quota: %v", err)
	}
	r.Release()
}

func TestStorageQuotaConcurrentAdmissionIsBounded(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	perUpload := int64((1 << 20) + 1024)
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(2*perUpload))
	results := make(chan *StorageReservation, 20)
	var wg sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := ReserveUploadStorage(root, temp, 0, 1)
			if err == nil {
				results <- r
				return
			}
			if !errors.Is(err, ErrStorageCapacity) {
				t.Errorf("unexpected error: %v", err)
			}
			results <- nil
		}()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for r := range results {
		if r != nil {
			accepted++
			r.Release()
		}
	}
	if accepted != 2 {
		t.Fatalf("got %d accepted uploads, want 2", accepted)
	}
}

func TestStorageQuotaFailsClosed(t *testing.T) {
	root, temp := prepareQuotaTest(t)
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "0")
	if _, err := ReserveUploadStorage(root, temp, 1, 1); !errors.Is(err, ErrStorageQuotaConfiguration) {
		t.Fatalf("invalid config: %v", err)
	}
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(100<<20))
	if _, err := ReserveUploadStorage(root, temp, math.MaxInt64, 1); !errors.Is(err, ErrStorageQuotaConfiguration) {
		t.Fatalf("overflow: %v", err)
	}
	if _, err := ReserveUploadStorage(root, filepath.Join(temp, "absent"), 1, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("missing temp dir: %v", err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveUploadStorage(root, temp, 1, 1); !errors.Is(err, ErrStorageCapacity) {
		t.Fatalf("unexpected symlink accepted: %v", err)
	}
}
