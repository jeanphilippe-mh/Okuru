package utils

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

var uploadSessionOwner struct {
	sync.RWMutex
	generation string
	locks      map[string]struct{}
}

var uploadPartsCleanup struct {
	sync.RWMutex
	run func(string) error
	prepare func(*UploadSession) error
	pending map[string]*uploadSessionPreparation
}

type uploadSessionPreparation struct {
	done chan struct{}
	err  error
}

func SetUploadSessionPartsPrepare(f func(*UploadSession) error) {
	uploadPartsCleanup.Lock()
	defer uploadPartsCleanup.Unlock()
	uploadPartsCleanup.prepare = f
}

func ReserveUploadSessionParts(ctx context.Context, s *UploadSession, bearer string) error {
	if s.Mode != "blocks" || s.State != "open" {
		return nil
	}
	uploadPartsCleanup.Lock()
	f := uploadPartsCleanup.prepare
	if f == nil {
		uploadPartsCleanup.Unlock()
		return nil
	}
	if active := uploadPartsCleanup.pending[s.ID]; active != nil {
		uploadPartsCleanup.Unlock()
		select {
		case <-active.done:
			return active.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if uploadPartsCleanup.pending == nil {
		uploadPartsCleanup.pending = make(map[string]*uploadSessionPreparation)
	}
	task := &uploadSessionPreparation{done: make(chan struct{}), err: uploadSessionError("unavailable")}
	uploadPartsCleanup.pending[s.ID] = task
	uploadPartsCleanup.Unlock()
	// Serialize the reservation and its compensation for duplicate prepares.
	// A late rejection must not abort a successfully reserved retry.
	defer func() {
		uploadPartsCleanup.Lock()
		defer uploadPartsCleanup.Unlock()
		delete(uploadPartsCleanup.pending, s.ID)
		close(task.done)
	}()
	task.err = f(s)
	if errors.Is(task.err, ErrStorageCapacity) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := RejectUploadReservation(cleanup, s.ID, bearer); err != nil {
			task.err = err
		}
	}
	return task.err
}

// SetUploadSessionPartsCleanup connects the disk owner to durable cancellation.
// The callback runs under the transfer exclusion lock and must be idempotent.
func SetUploadSessionPartsCleanup(f func(string) error) {
	uploadPartsCleanup.Lock()
	defer uploadPartsCleanup.Unlock()
	uploadPartsCleanup.run = f
}

func CleanupUploadSessionParts(id string) error {
	uploadPartsCleanup.RLock()
	f := uploadPartsCleanup.run
	uploadPartsCleanup.RUnlock()
	if f == nil {
		return nil
	}
	return f(id)
}

// AcquireUploadSessionOwner holds a stable, private lock file until all v2
// work has stopped. Never unlink a live lock: another process could lock a
// different inode at the same path.
func AcquireUploadSessionOwner(storageDir string) (func(), error) {
	uploadSessionOwner.Lock()
	defer uploadSessionOwner.Unlock()
	if uploadSessionOwner.generation != "" {
		return nil, uploadSessionError("unavailable")
	}
	root, err := stagingRoot(storageDir)
	if err != nil {
		return nil, err
	}
	guard, err := AcquireStoragePathGuard(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, ".okuru-upload-v2-owner")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		_ = guard.Close()
		return nil, err
	}
	invalid := func() (func(), error) {
		_ = f.Close()
		_ = guard.Close()
		return nil, uploadSessionError("unavailable")
	}
	marker, err := os.Lstat(path)
	if err != nil || !marker.Mode().IsRegular() {
		return invalid()
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(marker, info) {
		return invalid()
	}
	locked, err := quotaTryLock(f)
	if err != nil || !locked {
		return invalid()
	}
	uploadSessionOwner.generation = uuid.NewString()
	uploadSessionOwner.locks = make(map[string]struct{})
	var once sync.Once
	return func() {
		once.Do(func() {
			uploadSessionOwner.Lock()
			defer uploadSessionOwner.Unlock()
			uploadSessionOwner.generation = ""
			uploadSessionOwner.locks = nil
			_ = errors.Join(quotaUnlock(f), f.Close(), guard.Close())
		})
	}, nil
}
func sessionGeneration() string {
	uploadSessionOwner.RLock()
	defer uploadSessionOwner.RUnlock()
	return uploadSessionOwner.generation
}

// LockUploadSession excludes competing file transfers, cancellation and publication.
// Invalid or invented IDs cannot grow the lock map beyond active operations.
func LockUploadSession(id string) (func(), error) {
	if !validUploadID(id) {
		return nil, uploadSessionError("not_found")
	}
	uploadSessionOwner.Lock()
	defer uploadSessionOwner.Unlock()
	if uploadSessionOwner.generation == "" {
		return nil, uploadSessionError("unavailable")
	}
	if _, ok := uploadSessionOwner.locks[id]; ok {
		return nil, uploadSessionError("busy")
	}
	if len(uploadSessionOwner.locks) >= 256 {
		return nil, uploadSessionError("capacity")
	}
	uploadSessionOwner.locks[id] = struct{}{}
	gen := uploadSessionOwner.generation
	var once sync.Once
	return func() {
		once.Do(func() {
			uploadSessionOwner.Lock()
			defer uploadSessionOwner.Unlock()
			if uploadSessionOwner.generation == gen {
				delete(uploadSessionOwner.locks, id)
			}
		})
	}, nil
}
