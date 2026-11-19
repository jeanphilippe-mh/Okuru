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
	if err := os.MkdirAll(FILEFOLDER, 0700); err != nil {
		return nil, err
	}
	release, err := AcquireUploadSessionOwner(FILEFOLDER)
	if errors.Is(err, errUploadOwnerBusy) {
		log.Info("Serving shares without ownership of prepared uploads")
		return func() {}, nil
	}
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
	if err = SweepUploadParts(parent); err != nil {
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
				if err := errors.Join(ReconcileUploadPublications(ctx), recoverUnboundFinalizations(ctx), SweepUploadParts(ctx)); err != nil {
					log.Warn("Pending upload publication needs reconciliation")
				}
			}
		}
	}()
	return func() {
		stop()
		<-done
		CloseUploadPartOwners()
		release()
	}, nil
}

// Recover a lost Redis acknowledgement or a failed rollback before a publication
// intent was bound. The same lock is held by every active finalizer.
func recoverUnboundFinalizations(ctx context.Context) error {
	candidates, err := uploadCommand(ctx, "", "unbound_publications", "", REDIS_PREFIX+"upload_v2_")
	if err != nil {
		return err
	}
	for _, id := range candidates[1:] {
		unlock, err := LockUploadSession(id)
		if err == uploadSessionError("busy") {
			continue
		}
		if err != nil {
			return err
		}
		_, err = uploadCommand(ctx, id, "recover_unbound", "")
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
