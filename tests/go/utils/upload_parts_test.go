package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUploadPatchLimit(t *testing.T) {
	for _, tc := range []struct {
		setting string
		want    int64
	}{
		{"", 100_000_000}, {"100", 100_000_000}, {"37", 37_000_000}, {"1", 1_000_000},
		{"0", 0}, {"-1", 0}, {"101", 0}, {"100000000", 0}, {"1.5", 0}, {"invalid", 0},
		{"9223372036854775807", 0}, {"9223372036854775808", 0},
	} {
		t.Setenv("OKURU_UPLOAD_CHUNKS_SIZE", tc.setting)
		if got := UploadPatchLimit(); got != tc.want {
			t.Errorf("setting %q: got %d bytes, want %d", tc.setting, got, tc.want)
		}
	}
}

func TestUploadPartsEncryptedStorageAndCleanup(t *testing.T) {
	c, r, m := sessionTestSetup(t)
	prev := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = prev })
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	ctx := context.Background()
	m.Metadata.Files = []DirectFileSpec{{Name: "private.txt", Size: 17}, {Name: "empty", Size: 0}}
	id, bearer := uuid.NewString(), newUploadSecret()
	s, _, err := PrepareFileUploadSession(ctx, r, id, bearer, m)
	if err != nil {
		t.Fatal(err)
	}
	if err = PrepareUploadParts(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ReleaseUploadParts(id) })
	if err = PrepareUploadParts(s); err != nil {
		t.Fatal("duplicate reservation", err)
	}
	if _, err = AppendUploadPart(ctx, s, bearer, 0, 0, 16, 20, strings.NewReader("short")); err == nil {
		t.Fatal("accepted truncated PATCH")
	}
	if n, err := AppendUploadPart(ctx, s, bearer, 0, 0, -1, 20, strings.NewReader("private-plaintext")); err != nil || n != 17 {
		t.Fatal(n, err)
	}
	if offset, err := ConfirmedUploadOffset(ctx, id, bearer, 0); err != nil || offset != 17 {
		t.Fatal(offset, err)
	}
	set := localPartSet(id)
	files, err := os.ReadDir(set.dir)
	if err != nil || len(files) != 2 {
		t.Fatal("unexpected staging contents", len(files), err)
	}
	data, err := os.ReadFile(set.files[0][0].path)
	if err != nil || !bytes.HasPrefix(data, []byte("age-encryption.org/v1")) || bytes.Contains(data, []byte("private-plaintext")) {
		t.Fatal("plaintext or missing age envelope")
	}
	if err := CleanupStaleStagingDirs(FILEFOLDER); err != nil {
		t.Fatal(err)
	}
	sources, err := UploadPartSources(ctx, s, bearer)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"private-plaintext", ""} {
		in, err := sources[i].Open()
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(in)
		if closeErr := in.Close(); closeErr != nil || readErr != nil || string(got) != want {
			t.Fatal("incorrect stream", i, readErr, closeErr)
		}
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(set.files[0][0].path, data, 0600); err != nil {
		t.Fatal(err)
	}
	in, err := sources[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, in)
	_ = in.Close()
	if err == nil {
		t.Fatal("accepted damaged ciphertext")
	}
	key, _ := UploadSessionRedisKeys(id)
	if _, err = c.Do("HSET", key, "until", time.Now().Add(-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err = SweepUploadParts(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(set.dir); !errors.Is(err, os.ErrNotExist) || localPartSet(id) != nil {
		t.Fatal("expired storage or reservation retained")
	}
	if err = ReleaseUploadParts(id); err != nil {
		t.Fatal("duplicate cleanup", err)
	}
}

func TestUploadPartsReservationFailure(t *testing.T) {
	_, r, m := sessionTestSetup(t)
	prev := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = prev })
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "1048576")
	id, bearer := uuid.NewString(), newUploadSecret()
	s, _, err := PrepareFileUploadSession(t.Context(), r, id, bearer, m)
	if err != nil {
		t.Fatal(err)
	}
	if err = PrepareUploadParts(s); !errors.Is(err, ErrStorageCapacity) {
		t.Fatal("expected an admission refusal", err)
	}
	if _, err = os.Stat(filepath.Join(FILEFOLDER, uploadPartPrefix+id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreserved staging directory exists")
	}
}
