//go:build windows

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

	"golang.org/x/sys/windows"
)

func privateWindowsTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestWindowsStorageCapacityAndLock(t *testing.T) {
	root := privateWindowsTestRoot(t)
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := storageFilesystemCapacityOS(root)
	if err != nil || a.available <= 0 {
		t.Fatalf("storage capacity unavailable: %v", err)
	}
	b, err := storageFilesystemCapacityOS(child)
	if err != nil || a.device != b.device {
		t.Fatalf("same volume reported inconsistently: %v", err)
	}
	lock := filepath.Join(root, "lock")
	one, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := os.OpenFile(lock, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	if ok, err := quotaTryLock(one); err != nil || !ok {
		t.Fatalf("first lock: %v", err)
	}
	if ok, err := quotaTryLock(two); err != nil || ok {
		t.Fatalf("second handle unexpectedly locked: %v", err)
	}
	if err := quotaUnlock(one); err != nil {
		t.Fatal(err)
	}
	if ok, err := quotaTryLock(two); err != nil || !ok {
		t.Fatalf("lock after release: %v", err)
	}
	if err := quotaUnlock(two); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsStagingLiveAndCrash(t *testing.T) {
	if root := os.Getenv("OKURU_WINDOWS_STAGE_CHILD"); root != "" {
		stage, err := CreateLockedStagingDir(root, ".okuru-upload-")
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(filepath.Join(stage.Path, "archive.tmp"), []byte("encrypted fixture"), 0600); err != nil {
			os.Exit(3)
		}
		fmt.Println("STAGE=" + stage.Path)
		time.Sleep(time.Hour)
		os.Exit(4)
	}
	root := privateWindowsTestRoot(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsStagingLiveAndCrash$")
	cmd.Env = append(os.Environ(), "OKURU_WINDOWS_STAGE_CHILD="+root)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "STAGE=") {
				lines <- strings.TrimPrefix(scanner.Text(), "STAGE=")
				return
			}
		}
		lines <- ""
	}()
	var path string
	select {
	case path = <-lines:
	case <-time.After(15 * time.Second):
		t.Fatal("child did not acquire staging lock")
	}
	if path == "" {
		t.Fatal("child failed before publishing staging")
	}
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active staging removed: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := CleanupStaleStagingDirs(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("abandoned staging remains: %v", err)
	}
}

func TestWindowsUntrustedDACLRejected(t *testing.T) {
	root := privateWindowsTestRoot(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FW;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := stagingRoot(root); err == nil {
		t.Fatal("world-writable staging root accepted")
	}
}

func TestWindowsUntrustedAncestorDACLRejected(t *testing.T) {
	root := privateWindowsTestRoot(t)
	child := filepath.Join(root, "storage")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	privateACL, _, err := private.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(child, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, privateACL, nil); err != nil {
		t.Fatal(err)
	}
	unsafeRoot, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FW;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	unsafeACL, _, err := unsafeRoot.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, unsafeACL, nil); err != nil {
		t.Fatal(err)
	}
	if err := trustedWindowsDirectory(child); err != nil {
		t.Fatalf("test child is not privately protected: %v", err)
	}
	if err := trustedWindowsPathChain(child); err == nil {
		t.Fatal("world-writable ancestor accepted")
	}
}

func TestWindowsAncestorMayPermitUnrelatedSubdirectories(t *testing.T) {
	root := privateWindowsTestRoot(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// FILE_ADD_SUBDIRECTORY alone does not grant delete-child or deletion of a
	// protected existing child, and is common on Windows volume roots.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;;0x00000004;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := trustedWindowsDirectoryAccess(root, true); err != nil {
		t.Fatalf("limited ancestor access rejected: %v", err)
	}
	if err := trustedWindowsDirectory(root); err == nil {
		t.Fatal("storage root allowing untrusted creation was accepted")
	}
}
