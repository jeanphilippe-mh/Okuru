//go:build windows

package utils

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Child processes receive only paths created in the test-owned, private root.
// The helper always restores a successful rename before reporting success.
func TestWindowsGuardBlocksOtherProcessUntilClose(t *testing.T) {
	if root := os.Getenv("OKURU_GUARD_TEST_ROOT"); root != "" {
		marker, err := os.ReadFile(filepath.Join(root, ".okuru-guard-test-marker"))
		if err != nil || string(marker) != os.Getenv("OKURU_GUARD_TEST_MARKER") || len(marker) != 32 {
			os.Exit(2)
		}
		old := filepath.Join(root, "ancestor")
		moved := filepath.Join(root, "ancestor-moved")
		if _, err := os.Lstat(moved); !os.IsNotExist(err) {
			os.Exit(3)
		}
		err = os.Rename(old, moved)
		if err != nil {
			if os.Getenv("OKURU_GUARD_TEST_EXPECT_BLOCKED") == "1" {
				os.Exit(0)
			}
			os.Exit(4)
		}
		if err := os.Rename(moved, old); err != nil {
			os.Exit(5)
		}
		if os.Getenv("OKURU_GUARD_TEST_EXPECT_BLOCKED") == "1" {
			os.Exit(6)
		}
		os.Exit(0)
	}

	root := privateWindowsTestRoot(t)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	marker := hex.EncodeToString(nonce[:])
	if err := os.WriteFile(filepath.Join(root, ".okuru-guard-test-marker"), []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(root, "ancestor")
	storage := filepath.Join(ancestor, "storage")
	if err := os.MkdirAll(storage, 0700); err != nil {
		t.Fatal(err)
	}
	guard, err := AcquireStoragePathGuard(storage)
	if err != nil {
		t.Fatalf("anchor storage: %v", err)
	}
	defer guard.Close()
	tryRename := func(blocked bool) {
		t.Helper()
		value := "0"
		if blocked {
			value = "1"
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsGuardBlocksOtherProcessUntilClose$")
		cmd.Env = append(os.Environ(), "OKURU_GUARD_TEST_ROOT="+root, "OKURU_GUARD_TEST_MARKER="+marker, "OKURU_GUARD_TEST_EXPECT_BLOCKED="+value)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("second-process rename (blocked=%t): %v: %s", blocked, err, output)
		}
	}
	tryRename(true)
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	tryRename(false)
}

func TestWindowsGuardFailureReleasesOpenedAncestors(t *testing.T) {
	root := privateWindowsTestRoot(t)
	ancestor := filepath.Join(root, "ancestor")
	if err := os.Mkdir(ancestor, 0700); err != nil {
		t.Fatal(err)
	}
	control, err := AcquireStoragePathGuard(ancestor)
	if err != nil {
		t.Fatalf("cannot anchor existing ancestor before failure check: %v", err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	guard, err := AcquireStoragePathGuard(filepath.Join(ancestor, "missing"))
	if err == nil {
		_ = guard.Close()
		t.Fatal("guard accepted missing final directory")
	}
	moved := filepath.Join(root, "ancestor-moved")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatalf("ancestor remained locked after failed guard: %v", err)
	}
	if err := os.Rename(moved, ancestor); err != nil {
		t.Fatalf("restore test ancestor: %v", err)
	}
}
