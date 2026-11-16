//go:build unix

package utils

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenGeoIPSnapshotDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unexpected-fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		file, err := openGeoIPSnapshot(path)
		if err == nil {
			err = file.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO blocked instead of failing regular-file validation")
	}
}
