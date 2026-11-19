package utils

import (
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"time"
)

// Run recovery before the ordinary expiry cleaner can inspect public names.
// An additional reader process can still serve existing shares without owning uploads.
func StartPreparedUploads(parent context.Context) (func(), error) {
	if !sessionFlag("OKURU_FILE_API") {
		return func() {}, nil
	}
	if err := os.MkdirAll(FILEFOLDER, 0700); err != nil {
		return nil, err
	}
	release, err := AcquireUploadSessionOwner(FILEFOLDER)
	if err != nil {
		return nil, err
	}
	root, err := publicationRoot()
	if err == nil {
		var entries []os.DirEntry
		entries, err = os.ReadDir(root)
		for _, entry := range entries {
			if !entry.IsDir() || !canonicalArchiveID(entry.Name()) {
				continue
			}
			dir := filepath.Join(root, entry.Name())
			_, e := os.Lstat(filepath.Join(dir, intentFileName))
			if os.IsNotExist(e) {
				err = errors.Join(err, os.RemoveAll(dir))
			} else if e != nil {
				err = errors.Join(err, e)
			}
		}
	}
	if err == nil {
		err = ReconcileUploadPublications(parent)
	}
	if err == nil {
		err = ReconcileUploadSessions(parent)
	}
	if err != nil {
		release()
		return nil, err
	}
	ctx, stop := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := ReconcileUploadPublications(ctx); err != nil {
					log.Warn("Pending upload publication needs reconciliation")
				}
			}
		}
	}()
	return func() { stop(); <-done; release() }, nil
}
