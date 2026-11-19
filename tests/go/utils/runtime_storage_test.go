package utils

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRuntimeStorageCapacityAndMountRecovery(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "archive")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	probe, err := OpenArchiveStorageMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	oldCapacity := storageFilesystemCapacity
	t.Cleanup(func() { storageFilesystemCapacity = oldCapacity })
	var available int64 = 1001
	storageFilesystemCapacity = func(string) (filesystemCapacity, error) { return filesystemCapacity{available: available}, nil }
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1000")
	h := NewRuntimeHealth()
	h.SetStorageReady(true)
	now := time.Now()
	h.recordRedis(now)
	sample := func(want archiveDiskState) {
		t.Helper()
		state := probe.sample()
		if state != want {
			t.Fatalf("disk state=%d want=%d", state, want)
		}
		h.recordStorage(state, now, probe)
		if h.Ready() != (state == archiveWritable) || h.CanServe(true) != (state == archiveWritable) || h.CanServe(false) != (state != archiveUnavailable) {
			t.Fatalf("incorrect admission at state=%d", state)
		}
	}
	sample(archiveWritable)
	if files, err := os.ReadDir(dir); err != nil || len(files) != 0 {
		t.Fatal("probe left an artifact")
	}
	available = 1000
	sample(archiveReadable)
	available = 1001
	sample(archiveWritable)
	h.recordStorage(archiveWritable, now.Add(-storageFreshness), probe)
	if h.Ready() || h.CanServe(false) {
		t.Fatal("stale disk sample admitted traffic")
	}
	sample(archiveWritable)
	if err := os.WriteFile(filepath.Join(dir, probe.canary), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	sample(archiveReadable)
	if got, err := os.ReadFile(filepath.Join(dir, probe.canary)); err != nil || string(got) != "existing" {
		t.Fatal("probe altered a pre-existing file")
	}
	if err := os.Remove(filepath.Join(dir, probe.canary)); err != nil {
		t.Fatal(err)
	}
	sample(archiveWritable)
}

func TestRuntimeStorageRejectsReplacementDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows can prevent renaming an open directory")
	}
	parent := t.TempDir()
	original := filepath.Join(parent, "archive")
	away := filepath.Join(parent, "detached")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	probe, err := OpenArchiveStorageMonitor(original)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	h := NewRuntimeHealth()
	h.SetStorageReady(true)
	h.recordRedis(time.Now())
	h.recordStorage(probe.sample(), time.Now(), probe)
	if !h.CanServe(true) {
		t.Fatal("healthy directory refused")
	}
	if err := os.Rename(original, away); err != nil {
		t.Fatal(err)
	}
	// HTTP diagnostics only read the cached state. An admission check for
	// writing detects a mount change before the next periodic probe.
	if !h.Ready() {
		t.Fatal("readiness performed a synchronous path check")
	}
	if h.CanServe(true) || probe.sample() != archiveUnavailable {
		t.Fatal("missing original directory admitted")
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if h.CanServe(true) || probe.sample() != archiveUnavailable {
		t.Fatal("replacement directory admitted")
	}
	if entries, err := os.ReadDir(original); err != nil || len(entries) != 0 {
		t.Fatal("probe wrote to a replacement directory")
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(away, original); err != nil {
		t.Fatal(err)
	}
	if probe.sample() != archiveWritable || !h.CanServe(true) {
		t.Fatal("restored directory refused")
	}
}

func TestRuntimeStorageCleanupRejectsReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows can prevent renaming an open directory")
	}
	oldFolder := FILEFOLDER
	FILEFOLDER = filepath.Join(t.TempDir(), "archive")
	t.Cleanup(func() { FILEFOLDER = oldFolder })
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
	stop := StartArchiveDirectoryTracking()
	defer stop()
	if err := InitializeArchiveDirectory(FILEFOLDER); err != nil {
		t.Fatal(err)
	}
	// The disk-only sweep runs even before the Redis-dependent startup.
	if err := enforceArchiveRetention(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	const id = "c1aa6fab-dcc9-4d2d-925e-e4075aeb95d9"
	file := filepath.Join(FILEFOLDER, id+".zip")
	past := time.Now().Add(-8 * 24 * time.Hour)
	writeOld := func() {
		t.Helper()
		if err := os.WriteFile(file, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, past, past); err != nil {
			t.Fatal(err)
		}
	}
	writeOld()
	parent := filepath.Dir(FILEFOLDER)
	away := filepath.Join(parent, "detached")
	if err := os.Rename(FILEFOLDER, away); err != nil {
		t.Fatal(err)
	}
	if err := InitializeArchiveDirectory(FILEFOLDER); err == nil {
		t.Fatal("recreated missing original")
	}
	if err := os.Mkdir(FILEFOLDER, 0700); err != nil {
		t.Fatal(err)
	}
	writeOld()
	for name, f := range map[string]func() error{
		"recovery":  func() error { return InitializeArchiveDirectory(FILEFOLDER) },
		"retention": func() error { return enforceArchiveRetention(context.Background(), time.Now()) },
		"expiry":    func() error { return removeExpiredArchive(nil, id) },
		"delete":    func() error { return CleanFile(id) },
		"parts":     func() error { return ReleaseUploadParts(id) },
		"journal":   func() error { return removePublicationJournal(id) },
	} {
		if err := f(); err == nil {
			t.Fatalf("%s accepted a substitute directory", name)
		}
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("substitute archive was removed", err)
	}
	if err := os.Rename(FILEFOLDER, filepath.Join(parent, "substitute")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(away, FILEFOLDER); err != nil {
		t.Fatal(err)
	}
	if err := enforceArchiveRetention(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("restored archive retained: %v", err)
	}
}

func TestRuntimeStorageAdmissionWithStalledFilesystem(t *testing.T) {
	h := NewRuntimeHealth()
	h.SetStorageReady(true)
	now := time.Now()
	h.recordRedis(now)
	// Represent an outstanding lookup that never completes. Concurrent
	// admissions must join it, and diagnostics must never wait on it.
	pending := &storageIdentityCheck{done: make(chan struct{})}
	monitor := &ArchiveStorageMonitor{check: pending}
	h.recordStorage(archiveWritable, now, monitor)
	type result struct {
		accepted bool
		elapsed  time.Duration
	}
	results := make(chan result, 4)
	for i := 0; i < cap(results); i++ {
		go func() {
			start := time.Now()
			accepted := h.CanServe(true)
			results <- result{accepted, time.Since(start)}
		}()
	}
	if !h.Ready() || !h.CanServe(false) {
		t.Fatal("fresh cached health was unavailable during a blocked write-admission check")
	}
	deadline := time.NewTimer(storageAdmissionTimeout + 3*time.Second)
	defer deadline.Stop()
	for i := 0; i < cap(results); i++ {
		select {
		case r := <-results:
			if r.accepted || r.elapsed < storageAdmissionTimeout {
				t.Fatalf("unexpected admission result %+v", r)
			}
		case <-deadline.C:
			t.Fatal("write admission did not return on a stalled path")
		}
	}
	if monitor.check != pending {
		t.Fatal("additional path lookup started while the first was blocked")
	}
}
