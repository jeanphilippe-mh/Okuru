//go:build darwin || linux || windows

package utils

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func useArchiveKDFTestRoot(t *testing.T) string {
	t.Helper()
	root := archiveKDFTestRoot(t)
	previous := FILEFOLDER
	FILEFOLDER = root
	t.Cleanup(func() { FILEFOLDER = previous })
	return root
}

func TestArchiveKDFProcessLockBusyReleaseAndPersistentFile(t *testing.T) {
	root := useArchiveKDFTestRoot(t)
	release, busy, err := tryArchiveKDFProcessLock()
	if err != nil || busy || release == nil {
		t.Fatalf("first reservation: busy=%v err=%v", busy, err)
	}
	t.Cleanup(release)
	if other, isBusy, err := tryArchiveKDFProcessLock(); err != nil || !isBusy || other != nil {
		if other != nil {
			other()
		}
		t.Fatalf("concurrent reservation: busy=%v err=%v", isBusy, err)
	}
	release()
	release()
	if info, err := os.Lstat(filepath.Join(root, archiveKDFProcessLockName)); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("persistent lock file missing or invalid: %v", err)
	}
	other, isBusy, err := tryArchiveKDFProcessLock()
	if err != nil || isBusy || other == nil {
		t.Fatalf("reservation after release: busy=%v err=%v", isBusy, err)
	}
	other()
}

func TestArchiveKDFProcessLockRefusesSymlinkAndHardlink(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			root := useArchiveKDFTestRoot(t)
			target := filepath.Join(t.TempDir(), "unrelated")
			if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, archiveKDFProcessLockName)
			var err error
			if kind == "symlink" {
				err = os.Symlink(target, path)
			} else {
				err = os.Link(target, path)
			}
			if err != nil {
				t.Skipf("%s unavailable on this filesystem: %v", kind, err)
			}
			release, busy, err := tryArchiveKDFProcessLock()
			if release != nil {
				release()
			}
			if err == nil || busy {
				t.Fatalf("%s accepted as lock: busy=%v err=%v", kind, busy, err)
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "keep" {
				t.Fatalf("unrelated target changed: %q %v", data, err)
			}
		})
	}
}

func TestArchiveKDFProcessLockAcrossProcessesAndCrash(t *testing.T) {
	if root := os.Getenv("OKURU_TEST_KDF_CHILD_ROOT"); root != "" {
		FILEFOLDER = root
		release, busy, err := tryArchiveKDFProcessLock()
		status := "acquired"
		if err != nil {
			status = "error"
		} else if busy {
			status = "busy"
		}
		if err := os.WriteFile(os.Getenv("OKURU_TEST_KDF_CHILD_STATUS"), []byte(status), 0600); err != nil {
			os.Exit(3)
		}
		if release != nil {
			_, _ = io.Copy(io.Discard, os.Stdin)
			release()
		}
		os.Exit(0)
	}
	root := useArchiveKDFTestRoot(t)
	statuses := t.TempDir()
	start := func(name string) (*exec.Cmd, io.WriteCloser, string) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestArchiveKDFProcessLockAcrossProcessesAndCrash$")
		status := filepath.Join(statuses, name)
		cmd.Env = append(os.Environ(), "OKURU_TEST_KDF_CHILD_ROOT="+root, "OKURU_TEST_KDF_CHILD_STATUS="+status)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = stdin.Close()
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		return cmd, stdin, status
	}
	waitStatus := func(path string) string {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
				return string(data)
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("child did not report its lock state")
		return ""
	}
	parentRelease, busy, err := tryArchiveKDFProcessLock()
	if err != nil || busy || parentRelease == nil {
		t.Fatalf("parent reservation: busy=%v err=%v", busy, err)
	}
	t.Cleanup(parentRelease)
	first, _, firstStatus := start("busy")
	if got := waitStatus(firstStatus); got != "busy" {
		t.Fatalf("child bypassed parent lock: %q", got)
	}
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	parentRelease()
	second, _, secondStatus := start("acquired")
	if got := waitStatus(secondStatus); got != "acquired" {
		t.Fatalf("child failed to acquire released lock: %q", got)
	}
	if release, busy, err := tryArchiveKDFProcessLock(); err != nil || !busy || release != nil {
		if release != nil {
			release()
		}
		t.Fatalf("parent bypassed child lock: busy=%v err=%v", busy, err)
	}
	if err := second.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = second.Wait()
	recovered, busy, err := tryArchiveKDFProcessLock()
	if err != nil || busy || recovered == nil {
		t.Fatalf("crashed child did not release lock: busy=%v err=%v", busy, err)
	}
	recovered()
}
