//go:build windows

package utils

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func archiveKDFTestRoot(t *testing.T) string {
	t.Helper()
	return privateWindowsTestRoot(t)
}

func TestArchiveKDFProcessLockRejectsUntrustedDACL(t *testing.T) {
	root := useArchiveKDFTestRoot(t)
	release, busy, err := tryArchiveKDFProcessLock()
	if err != nil || busy || release == nil {
		t.Fatalf("initial reservation: busy=%v err=%v", busy, err)
	}
	release()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("get service identity: %v", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;GR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(filepath.Join(root, archiveKDFProcessLockName), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	release, busy, err = tryArchiveKDFProcessLock()
	if release != nil {
		release()
	}
	if err == nil || busy {
		t.Fatalf("Lock granting access to Everyone accepted: busy=%v err=%v", busy, err)
	}
}
