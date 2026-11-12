//go:build darwin || linux

package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStagingLockSubprocess(t *testing.T) {
	root := os.Getenv("OKURU_LOCK_TEST_CHILD_ROOT")
	if root == "" {
		return
	}
	stage, err := CreateLockedStagingDir(root, ".okuru-multipart-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage.Path, "ciphertext"), []byte("encrypted staging"), 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Println("STAGING=" + stage.Path)
	time.Sleep(30 * time.Second)
	_ = stage.Close()
}

func TestStagingCleanupHonorsLiveProcessAndCrash(t *testing.T) {
	root := t.TempDir()
	old, err := os.MkdirTemp(root, ".okuru-upload-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "legacy"), []byte("do not delete"), 0600); err != nil {
		t.Fatal(err)
	}
	unpublished, err := os.MkdirTemp(root, ".okuru-multipart-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unpublished, ".okuru-lock-init-0"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStagingLockSubprocess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OKURU_LOCK_TEST_CHILD_ROOT="+root)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			if strings.HasPrefix(s.Text(), "STAGING=") {
				line <- strings.TrimPrefix(s.Text(), "STAGING=")
				return
			}
		}
		line <- ""
	}()
	var active string
	select {
	case active = <-line:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not acquire staging lock")
	}
	if active == "" {
		t.Fatal("child did not report staging path")
	}
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(active, "ciphertext")); err != nil {
		t.Fatal("live staging was deleted")
	}
	// Publication can leave a second hard link in staging if a process dies
	// between publication and cleanup. Recovery must keep the published link.
	published := filepath.Join(root, "published.zip")
	if err := os.Link(filepath.Join(active, "ciphertext"), published); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(active); !os.IsNotExist(err) {
		t.Fatalf("crashed staging remained: %v", err)
	}
	if content, err := os.ReadFile(published); err != nil || string(content) != "encrypted staging" {
		t.Fatal("recovery removed or changed the published hard link")
	}
	for _, path := range []string{old, unpublished} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("unmarked directory was deleted")
		}
	}
}

func TestStagingCloseAndInvalidMarker(t *testing.T) {
	root := t.TempDir()
	stage, err := CreateLockedStagingDir(root, ".okuru-upload-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage.Path, "encrypted"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage.Path); err != nil {
		t.Fatal("active directory removed")
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage.Path); !os.IsNotExist(err) {
		t.Fatal("closed directory retained")
	}
	unknown, err := os.MkdirTemp(root, ".okuru-upload-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unknown, stagingLockName), []byte("not our marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("unrecognized marker removed")
	}
}

func TestStagingRejectsUntrustedRootAndSymlinkMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateLockedStagingDir(root, ".okuru-upload-"); err == nil {
		t.Fatal("staging accepted a group- and world-writable root")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	stage, err := os.MkdirTemp(root, ".okuru-upload-")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(stagingLockContents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(stage, stagingLockName)); err != nil {
		t.Fatal(err)
	}
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("staging with a symlink marker was deleted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("symlink target was deleted")
	}
}
