package utils

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"filippo.io/age"
)

const uploadPartPrefix = ".okuru-parts-"
const maxUploadParts = 2048

func UploadPatchLimit() int64 {
	const ceiling int64 = 90_000_000
	raw := os.Getenv("OKURU_UPLOAD_MAX_PATCH_BYTES")
	if raw == "" {
		return ceiling
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 || n > ceiling {
		return 0
	}
	return n
}

type uploadPart struct {
	index      int
	start, end int64
	path       string
}
type uploadPartSet struct {
	guard       *StoragePathGuard
	entryBudget int64
	dir         string
	generation  string
	identity    *age.X25519Identity
	quota       *StorageReservation
	marker      *os.File
	files       [][]uploadPart
	count       int
	pending     *uploadPart
}

var uploadParts = struct {
	sync.Mutex
	sets map[string]*uploadPartSet
}{sets: make(map[string]*uploadPartSet)}

func init() {
	SetUploadSessionPartsCleanup(ReleaseUploadParts)
	SetUploadSessionPartsPrepare(PrepareUploadParts)
}

func localPartSet(id string) *uploadPartSet {
	uploadParts.Lock()
	defer uploadParts.Unlock()
	return uploadParts.sets[id]
}

// Serialize first-time reservations and account for the worst-case future
// entry count, including blocks not yet present in the directory walk.
var partAdmission sync.Mutex

func checkUploadPartEntries(root string, needed int64) error {
	remaining := int64(maxQuotaScanEntries) - needed
	active := make(map[string]bool)
	uploadParts.Lock()
	for _, set := range uploadParts.sets {
		if filepath.Dir(set.dir) == root {
			active[set.dir] = true
			remaining -= set.entryBudget
		}
	}
	uploadParts.Unlock()
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || remaining < 1 {
			return ErrStorageCapacity
		}
		if active[path] {
			return filepath.SkipDir
		}
		remaining--
		if entry.IsDir() && path == filepath.Join(root, quotaRegistryName) {
			return filepath.SkipDir
		}
		return nil
	})
}

func PrepareUploadParts(s *UploadSession) error {
	if s == nil || !validUploadID(s.ID) || s.Mode != "blocks" || s.Metadata == nil {
		return uploadSessionError("invalid_manifest")
	}
	partAdmission.Lock()
	defer partAdmission.Unlock()
	if set := localPartSet(s.ID); set != nil && set.generation == sessionGeneration() {
		return nil
	}
	unlock, err := LockUploadSession(s.ID)
	if err != nil {
		return err
	}
	defer unlock()
	if set := localPartSet(s.ID); set != nil && set.generation == sessionGeneration() {
		return nil
	}
	ok, err := UploadSessionOwnsParts(context.Background(), s.ID)
	if err != nil {
		return err
	}
	if !ok {
		return uploadSessionError("not_ready")
	}
	root, err := stagingRoot(FILEFOLDER)
	if err != nil {
		return ErrStorageCapacity
	}
	possible := min(int64(maxUploadParts), s.Total)
	if s.Total < 0 || checkUploadPartVolume(root, possible+8) != nil || checkUploadPartEntries(root, possible+8) != nil {
		return ErrStorageCapacity
	}
	// The existing reservation budgets two copies. Padding each with one
	// allocation unit per possible age record covers its metadata and rounding.
	budget, err := quotaAdd(s.Total, (possible+1)*(64<<10))
	if err != nil {
		return err
	}
	quota, err := ReserveEncryptedUploadStorage(root, budget, len(s.Metadata.Files))
	if err != nil {
		return err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			quota.Release()
		}
	}()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	dir := filepath.Join(root, uploadPartPrefix+s.ID)
	if err := os.Mkdir(dir, 0700); err != nil {
		return ErrStorageCapacity
	}
	defer func() {
		if !handedOff {
			_ = os.RemoveAll(dir)
		}
	}()
	guard, err := AcquireStoragePathGuard(dir)
	if err != nil {
		return ErrStorageCapacity
	}
	defer func() {
		if !handedOff {
			_ = guard.Close()
		}
	}()
	marker, err := os.OpenFile(filepath.Join(dir, "owner"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrStorageCapacity
	}
	locked, err := quotaTryLock(marker)
	if err != nil || !locked {
		_ = marker.Close()
		return ErrStorageCapacity
	}
	set := &uploadPartSet{dir: dir, guard: guard, entryBudget: possible + 8, generation: sessionGeneration(), identity: identity, quota: quota, marker: marker, files: make([][]uploadPart, len(s.Metadata.Files))}
	uploadParts.Lock()
	uploadParts.sets[s.ID] = set
	uploadParts.Unlock()
	handedOff = true
	return nil
}

// Caller owns the session lock. Directory names are canonical UUIDs in the
// private storage root. Redis ownership is checked by the caller for recovery.
func ReleaseUploadParts(id string) error {
	if !validUploadID(id) {
		return uploadSessionError("invalid_id")
	}
	root, err := stagingRoot(FILEFOLDER)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, uploadPartPrefix+id)
	set := localPartSet(id)
	info, err := os.Lstat(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if info != nil {
		if !info.IsDir() {
			return ErrStorageCapacity
		}
		if set == nil {
			marker, e := os.OpenFile(filepath.Join(dir, "owner"), os.O_RDWR, 0)
			if e != nil && !os.IsNotExist(e) {
				return ErrStorageCapacity
			}
			if marker != nil {
				locked, e := quotaTryLock(marker)
				_ = marker.Close()
				if e != nil || !locked {
					return uploadSessionError("busy")
				}
			}
		} else if set.marker != nil {
			_ = quotaUnlock(set.marker)
			_ = set.marker.Close()
			set.marker = nil
		}
		if set != nil && set.guard != nil {
			_ = set.guard.Close()
			set.guard = nil
		}
		if err := os.RemoveAll(dir); err != nil {
			return ErrStorageCapacity
		}
	}
	if set != nil {
		if set.marker != nil {
			_ = set.marker.Close()
		}
		if set.guard != nil {
			_ = set.guard.Close()
		}
		set.quota.Release()
		uploadParts.Lock()
		delete(uploadParts.sets, id)
		uploadParts.Unlock()
	}
	return nil
}

func SweepUploadParts(ctx context.Context) error {
	if sessionGeneration() == "" {
		return uploadSessionError("unavailable")
	}
	root, err := stagingRoot(FILEFOLDER)
	if err != nil {
		return err
	}
	d, err := os.Open(root)
	if err != nil {
		return err
	}
	defer d.Close()
	for {
		entries, err := d.ReadDir(128)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), uploadPartPrefix) {
				continue
			}
			id := strings.TrimPrefix(entry.Name(), uploadPartPrefix)
			if !validUploadID(id) {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			unlock, e := LockUploadSession(id)
			if e != nil {
				if _, code := UploadSessionHTTPError(e); code == "busy" {
					continue
				}
				return e
			}
			owns, e := UploadSessionOwnsParts(ctx, id)
			if e == nil && !owns {
				e = ReleaseUploadParts(id)
			}
			unlock()
			if e != nil {
				return e
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Recognize both the router's transport limit and a manifest size mismatch.
func uploadReadError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return uploadSessionError("too_large")
	}
	return uploadSessionError("invalid_request")
}

// CloseUploadPartOwners drops volatile identities after the HTTP server has
// drained. The next owner reconciles Redis before reclaiming these directories.
func CloseUploadPartOwners() {
	partAdmission.Lock()
	defer partAdmission.Unlock()
	uploadParts.Lock()
	sets := uploadParts.sets
	uploadParts.sets = make(map[string]*uploadPartSet)
	uploadParts.Unlock()
	for _, set := range sets {
		if set.marker != nil {
			_ = quotaUnlock(set.marker)
			_ = set.marker.Close()
		}
		if set.guard != nil {
			_ = set.guard.Close()
		}
		set.quota.Release()
	}
}
