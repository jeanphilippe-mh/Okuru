package utils

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const maxArchiveRetention = 7 * 24 * time.Hour
const retiredPublicationPrefix = "retired-"

// LinkPublishedArchive starts the retention clock at publication. The source is
// a sealed file in private staging, or the private witness of a pending intent.
// No client-supplied file timestamp is used. The destination is never replaced.
func LinkPublishedArchive(source, destination string) error {
	now := time.Now()
	if err := os.Chtimes(source, now, now); err != nil {
		return err
	}
	return os.Link(source, destination)
}

// StartArchiveRetention starts before Redis initialization, so outages cannot
// stall the disk deadline. Scans never overlap. Stop joins the worker.
func StartArchiveRetention() func() { return startArchiveRetention(fileCleanupInterval) }

func startArchiveRetention(interval time.Duration) func() {
	ctx, cancel := context.WithCancel(context.Background())
	first, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		scan := func() {
			if err := enforceArchiveRetention(ctx, time.Now()); err != nil && ctx.Err() == nil {
				logCleanupFailure("archive.retention_failed", "Seven-day archive cleanup failed", err)
			}
		}
		scan()
		close(first)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scan()
			}
		}
	}()
	return func() {
		// A failed startup (for example Redis already offline) may exit
		// immediately. Give its first local scan time to run before cancelling.
		select {
		case <-first:
		case <-time.After(5 * time.Second):
		}
		cancel()
		<-done
	}
}

func enforceArchiveRetention(ctx context.Context, now time.Time) error {
	path, err := stagingRoot(FILEFOLDER)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Fresh installation; the first upload creates the directory.
	}
	if err != nil {
		return err
	}
	guard, err := AcquireStoragePathGuard(path)
	if err != nil {
		return err
	}
	defer guard.Close()
	root, err := openRuntimeArchiveRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	cutoff := now.Add(-maxArchiveRetention)
	dryRun := strings.EqualFold(os.Getenv("OKURU_CLEANUP_DRY_RUN"), "true")
	var firstErr error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Name() == journalDirName && entry.IsDir() {
				if err := retireOverduePublications(ctx, root, cutoff, dryRun); err != nil && firstErr == nil {
					firstErr = err
				}
				continue
			}
			if entry.IsDir() && strings.HasPrefix(entry.Name(), ".okuru-upload-") && validStagingName(entry.Name()) {
				staged, err := root.Lstat(filepath.Join(entry.Name(), "archive.tmp"))
				if err == nil && staged.Mode().IsRegular() && !staged.ModTime().After(cutoff) && !dryRun {
					// A crash may have left a third link in the uploader's stage.
					// Its authenticated marker and interprocess lock protect live work.
					err = cleanupStaleStagingDir(filepath.Join(root.Name(), entry.Name()))
				}
				if err != nil && !os.IsNotExist(err) && firstErr == nil {
					firstErr = err
				}
				continue
			}
			id, ok := strings.CutSuffix(entry.Name(), ".zip")
			if !ok || !entry.Type().IsRegular() || !canonicalArchiveID(id) {
				continue
			}
			if err := removeOverdueArchive(root, id, cutoff, dryRun); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
				firstErr = err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return firstErr
		}
		if readErr != nil {
			return errors.Join(readErr, firstErr)
		}
	}
}

func retireOverduePublications(ctx context.Context, root *os.Root, cutoff time.Time, dryRun bool) error {
	dir, err := root.Open(journalDirName)
	if err != nil {
		return err
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return err
	}
	var firstErr error
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			id, _ := strings.CutPrefix(entry.Name(), retiredPublicationPrefix)
			if !entry.IsDir() || !canonicalArchiveID(id) {
				continue
			}
			err := retirePublication(root, entry.Name(), id, cutoff, dryRun)
			if err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return firstErr
		}
		if readErr != nil {
			return errors.Join(firstErr, readErr)
		}
	}
}

func retirePublication(root *os.Root, name, id string, cutoff time.Time, dryRun bool) error {
	dir := filepath.Join(journalDirName, name)
	private, err := root.Lstat(dir)
	if err != nil || !private.IsDir() || private.Mode().Perm()&0077 != 0 {
		return err
	}
	retired := name != id
	witness := filepath.Join(dir, witnessName)
	initial, err := root.Lstat(witness)
	if err != nil && !(retired && os.IsNotExist(err)) {
		return err
	}
	if initial != nil && (!initial.Mode().IsRegular() || initial.ModTime().After(cutoff)) {
		return nil
	}
	intent := filepath.Join(dir, intentFileName)
	info, err := root.Lstat(intent)
	if retired && initial == nil && os.IsNotExist(err) && !dryRun {
		return root.Remove(dir) // Only remove an already-empty retired directory.
	}
	incomplete := os.IsNotExist(err)
	var p UploadPublication
	if !incomplete {
		if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
			return err
		}
		f, err := root.Open(intent)
		if err != nil {
			return err
		}
		err = errors.Join(json.NewDecoder(io.LimitReader(f, 256<<10)).Decode(&p), f.Close())
		if err != nil || p.FileID != id || !canonicalArchiveID(p.Session) {
			return errors.New("invalid archive retention journal")
		}
	}
	release, err := lockJournalForRetention(root, id, p.Session)
	if err != nil || release == nil {
		return err
	}
	defer release()
	current, err := root.Lstat(dir)
	if err != nil || !os.SameFile(private, current) {
		return err
	}
	if incomplete {
		if _, err := root.Lstat(intent); !os.IsNotExist(err) {
			return err
		}
	}
	_, markerErr := root.Lstat(filepath.Join(journalDirName, "collision-"+id))
	if markerErr != nil && !os.IsNotExist(markerErr) {
		return markerErr
	}
	public := id + ".zip"
	archive, err := root.Lstat(public)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if initial != nil {
		current, err := root.Lstat(witness)
		if err != nil || !os.SameFile(initial, current) || current.ModTime().After(cutoff) {
			return err
		}
	}
	if dryRun {
		log.WithField("archive", public).Warn("Cleanup dry-run: overdue publication would be retired")
		return nil
	}
	if archive != nil && (incomplete || markerErr == nil || initial == nil || !archive.Mode().IsRegular() || !os.SameFile(initial, archive)) {
		// Preserve the unfamiliar public inode beyond the lifetime of this
		// private journal, including if an ordinary cleanup scans it later.
		if markerErr != nil {
			if err := markPublicationCollision(id); err != nil {
				return err
			}
		}
		archive = nil
	}
	if !retired {
		target := filepath.Join(journalDirName, retiredPublicationPrefix+id)
		if _, err := root.Lstat(target); !os.IsNotExist(err) {
			return err
		}
		if err := root.Rename(dir, target); err != nil {
			return err
		}
		dir = target
	}
	// Recovery enumerates canonical UUID directories only. Persist the rename
	// before deleting either link; a subsequent disk pass resumes this state.
	if err := syncPublicationDir(filepath.Join(root.Name(), journalDirName)); err != nil {
		return err
	}
	if archive != nil {
		if err := root.Remove(public); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := syncPublicationDir(root.Name()); err != nil {
		return err
	}
	for _, file := range []string{"intent.tmp", witnessName, intentFileName} {
		if err := root.Remove(filepath.Join(dir, file)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return root.Remove(dir)
}

func removeOverdueArchive(root *os.Root, id string, cutoff time.Time, dryRun bool) error {
	name := id + ".zip"
	seen, err := root.Lstat(name)
	if err != nil || !seen.Mode().IsRegular() || seen.ModTime().After(cutoff) {
		return err
	}
	protected, err := guardedUploadPublication(root, id)
	if err != nil || protected {
		return err
	}
	// Another cleaner or the operator's cron may have removed this entry.
	// Okuru publishers exclusively link new names and never replace a ZIP.
	current, err := root.Lstat(name)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(seen, current) || current.ModTime().After(cutoff) {
		return err
	}
	if dryRun {
		log.WithField("archive", name).Warn("Cleanup dry-run: seven-day archive would be removed")
		return nil
	}
	return root.Remove(name)
}
