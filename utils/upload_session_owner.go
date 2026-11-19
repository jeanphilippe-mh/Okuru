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

var errUploadOwnerBusy = errors.New("another process owns prepared uploads")
var retentionOwnerLifetime sync.RWMutex

const uploadOwnerMarker = ".okuru-upload-v2-owner"

var uploadSessionOwner struct {
	sync.RWMutex
	generation string
	locks      map[string]struct{}
}

var uploadPartsCleanup struct {
	sync.RWMutex
	run     func(string) error
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
	path := filepath.Join(root, uploadOwnerMarker)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		_ = guard.Close()
		return nil, err
	}
	reject := func(reason error) (func(), error) {
		_ = f.Close()
		_ = guard.Close()
		return nil, reason
	}
	marker, err := os.Lstat(path)
	if err != nil || !marker.Mode().IsRegular() {
		return reject(uploadSessionError("unavailable"))
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(marker, info) {
		return reject(uploadSessionError("unavailable"))
	}
	locked, err := quotaTryLock(f)
	if err != nil {
		return reject(uploadSessionError("unavailable"))
	}
	if !locked {
		// Offline journal retirement takes a short shared lock. Storage startup
		// must retry instead of mistaking that reader for a permanent publisher.
		shared, e := trySharedOwnerLock(f)
		if e != nil || shared {
			return reject(uploadSessionError("unavailable"))
		}
		return reject(errUploadOwnerBusy)
	}
	uploadSessionOwner.generation = uuid.NewString()
	uploadSessionOwner.locks = make(map[string]struct{})
	var once sync.Once
	return func() {
		once.Do(func() {
			retentionOwnerLifetime.Lock()
			defer retentionOwnerLifetime.Unlock()
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

// The normal owner excludes all other publishers and locks individual sessions.
// Without a local owner (including cold startup with Redis offline), a shared
// lock on its stable marker proves that no publisher can run during retirement.
func lockJournalForRetention(root *os.Root, id, session string) (func(), error) {
	retentionOwnerLifetime.RLock()
	if sessionGeneration() != "" {
		if session == "" {
			unlock, ok := lockPublicationJournal(id)
			if ok {
				return func() { unlock(); retentionOwnerLifetime.RUnlock() }, nil
			}
			retentionOwnerLifetime.RUnlock()
			return nil, nil
		}
		unlock, err := LockUploadSession(session)
		if err == nil {
			return func() { unlock(); retentionOwnerLifetime.RUnlock() }, nil
		}
		retentionOwnerLifetime.RUnlock()
		if err == uploadSessionError("busy") || err == uploadSessionError("capacity") || err == uploadSessionError("unavailable") {
			return nil, nil
		}
		return unlock, err
	}
	retentionOwnerLifetime.RUnlock()
	info, err := root.Lstat(uploadOwnerMarker)
	if os.IsNotExist(err) {
		// Restored storage may omit the stable lock file. Publish an empty
		// one exclusively, exactly where the upload owner also takes its lock.
		f, createErr := root.OpenFile(uploadOwnerMarker, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if createErr != nil && !os.IsExist(createErr) {
			return nil, createErr
		}
		if f != nil {
			if err := f.Close(); err != nil {
				return nil, err
			}
		}
		info, err = root.Lstat(uploadOwnerMarker)
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, err
	}
	f, err := root.OpenFile(uploadOwnerMarker, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, err
	}
	held, err := trySharedOwnerLock(f)
	if err != nil || !held {
		f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
