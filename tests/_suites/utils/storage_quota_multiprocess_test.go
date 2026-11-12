//go:build darwin || linux || windows

package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuotaMultiprocessAdmissionAndCrashRecovery(t *testing.T) {
	if root := os.Getenv("OKURU_QUOTA_CHILD_ROOT"); root != "" {
		result, err := ReserveEncryptedUploadStorage(root, 0, 1)
		status := "admitted"
		if errors.Is(err, ErrStorageCapacity) {
			status = "denied"
		} else if err != nil {
			status = "error:" + err.Error()
		}
		if err := os.WriteFile(os.Getenv("OKURU_QUOTA_CHILD_STATUS"), []byte(status), 0600); err != nil {
			os.Exit(3)
		}
		if result != nil {
			_, _ = io.Copy(io.Discard, os.Stdin)
			result.Release()
		}
		os.Exit(0)
	}
	root, statuses := t.TempDir(), t.TempDir()
	perUpload := int64((1 << 20) + 1024)
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", fmt.Sprint(2*perUpload))
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_MAX_ARCHIVES", "1000")
	type child struct {
		cmd    *exec.Cmd
		stdin  io.WriteCloser
		status string
	}
	children := make([]child, 8)
	for i := range children {
		cmd := exec.Command(os.Args[0], "-test.run=^TestQuotaMultiprocessAdmissionAndCrashRecovery$")
		status := filepath.Join(statuses, fmt.Sprint(i))
		cmd.Env = append(os.Environ(), "OKURU_QUOTA_CHILD_ROOT="+root, "OKURU_QUOTA_CHILD_STATUS="+status)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		children[i] = child{cmd: cmd, stdin: stdin, status: status}
	}
	t.Cleanup(func() {
		for _, c := range children {
			_ = c.stdin.Close()
			if c.cmd.ProcessState == nil {
				_ = c.cmd.Process.Kill()
				_ = c.cmd.Wait()
			}
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	var admitted []int
	for i, c := range children {
		var data []byte
		for time.Now().Before(deadline) {
			data, _ = os.ReadFile(c.status)
			if len(data) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		switch string(data) {
		case "admitted":
			admitted = append(admitted, i)
		case "denied":
		default:
			t.Fatalf("child %d did not return valid status: %q", i, data)
		}
	}
	if len(admitted) != 2 {
		t.Fatalf("admitted %d processes, want 2", len(admitted))
	}
	crashed := children[admitted[0]]
	if err := crashed.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = crashed.cmd.Wait()
	// Its released OS lock makes only the crashed reservation reclaimable.
	replacement, err := ReserveEncryptedUploadStorage(root, 0, 1)
	if err != nil {
		t.Fatalf("crashed reservation not reclaimed: %v", err)
	}
	defer replacement.Release()
	if excess, err := ReserveEncryptedUploadStorage(root, 0, 1); !errors.Is(err, ErrStorageCapacity) {
		if excess != nil {
			excess.Release()
		}
		t.Fatalf("live reservation lost or budget bypassed: %v", err)
	}
	// The remaining admitted process still holds its lock until instructed.
	if err := children[admitted[1]].stdin.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatal(err)
	}
	if err := children[admitted[1]].cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}
