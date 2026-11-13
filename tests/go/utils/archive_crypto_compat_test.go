package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestArchiveKDFAdmissionRejectsWaitersAndReleases(t *testing.T) {
	oldFileFolder := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = oldFileFolder })
	reserved, release, err := ReserveArchiveKDF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)

	const clients = 64
	results := make(chan error, clients)
	for i := 0; i < clients; i++ {
		go func() {
			results <- withArchiveKDF(context.Background(), func() error {
				return errors.New("unexpected second KDF")
			})
		}()
	}
	for i := 0; i < clients; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrArchiveKDFBusy) {
				t.Fatalf("waiter error = %v, want busy", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("KDF waiter blocked instead of being rejected")
		}
	}
	if err := withArchiveKDF(reserved, func() error { return nil }); err != nil {
		t.Fatalf("reserved KDF was rejected: %v", err)
	}
	started := make(chan struct{})
	finish := make(chan struct{})
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- withArchiveKDF(reserved, func() error {
			close(started)
			<-finish
			return nil
		})
	}()
	<-started
	if err := withArchiveKDF(reserved, func() error { return nil }); !errors.Is(err, ErrArchiveKDFBusy) {
		close(finish)
		t.Fatalf("shared reservation permitted concurrent KDF work: %v", err)
	}
	close(finish)
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
	release()
	release() // Release is safe even after an earlier explicit release.
	if err := withArchiveKDF(reserved, func() error { return nil }); !errors.Is(err, ErrArchiveKDFBusy) {
		t.Fatalf("released reservation allowed work: %v", err)
	}
	if err := withArchiveKDF(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("slot was not released: %v", err)
	}
}

func TestArchiveWorkFactorAndLegacyCompatibility(t *testing.T) {
	oldFileFolder := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = oldFileFolder })
	const password = "test-phrase-with-sufficient-entropy"
	const content = "synthetic legacy archive content"
	var current bytes.Buffer
	writer, err := EncryptArchive(context.Background(), &current, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	header := string(current.Bytes())
	if !strings.Contains(header, " 18\n") {
		t.Fatal("new age archive does not use the intended work factor")
	}
	reader, err := DecryptArchive(context.Background(), bytes.NewReader(current.Bytes()), password)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil || string(plain) != content {
		t.Fatalf("new archive failed round trip: %v", err)
	}

	legacyRecipient, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	legacyRecipient.SetWorkFactor(17)
	var legacy bytes.Buffer
	legacyWriter, err := age.Encrypt(&legacy, legacyRecipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(legacyWriter, content); err != nil {
		t.Fatal(err)
	}
	if err := legacyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy.Bytes()), " 17\n") {
		t.Fatal("legacy fixture does not use factor 17")
	}
	reader, err = DecryptArchive(context.Background(), bytes.NewReader(legacy.Bytes()), password)
	if err != nil {
		t.Fatalf("legacy factor-17 archive rejected: %v", err)
	}
	plain, err = io.ReadAll(reader)
	if err != nil || string(plain) != content {
		t.Fatalf("legacy archive failed round trip: %v", err)
	}

	// Changing just the public header gives an intentionally unauthentic file;
	// its unsupported factor must be rejected before an expensive derivation.
	tooExpensive := strings.Replace(header, " 18\n", " 19\n", 1)
	if _, err := DecryptArchive(context.Background(), strings.NewReader(tooExpensive), password); err == nil || !strings.Contains(err.Error(), "work factor too large") {
		t.Fatalf("unsupported work factor not rejected: %v", err)
	}
}
