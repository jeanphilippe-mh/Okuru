package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"filippo.io/age"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
)

func TestFileMetadataSecretSeparatesPasswordOnlyForNewProvidedFormat(t *testing.T) {
	const password = "example user-selected password"
	for _, format := range []string{"", ArchiveFormatAge} {
		for _, provided := range []bool{false, true} {
			secret, err := fileMetadataSecret(password, provided, format)
			if err != nil || secret != password {
				t.Fatalf("legacy format %q changed its secret: %v", format, err)
			}
		}
	}
	first, err := fileMetadataSecret(password, true, ArchiveFormatAgeUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fileMetadataSecret(password, true, ArchiveFormatAgeUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	if first == password || second == password || first == second || len(first) != 50 || len(second) != 50 {
		t.Fatal("new file metadata did not use an independent fresh random secret")
	}
	for _, input := range []struct {
		password string
		provided bool
	}{{password, false}, {"", true}} {
		if _, err := fileMetadataSecret(input.password, input.provided, ArchiveFormatAgeUserPassword); !errors.Is(err, errArchivePasswordRequired) {
			t.Fatalf("invalid v2 input accepted: %v", err)
		}
	}
	if _, err := SetFile(password, 60, 1, false, true, "not-an-id", ArchiveFormatAgeUserPassword); err == nil || err.Code != http.StatusBadRequest {
		t.Fatalf("invalid password-link identifier accepted: %v", err)
	}
	if _, err := SetFile(password, 60, 1, false, false, uuid.NewString(), ArchiveFormatAgeUserPassword); err == nil || err.Code != http.StatusBadRequest {
		t.Fatalf("unprotected file accepted with protected format: %v", err)
	}
}

func TestArchivePasswordErrorClassification(t *testing.T) {
	oldFileFolder := FILEFOLDER
	FILEFOLDER = t.TempDir()
	t.Cleanup(func() { FILEFOLDER = oldFileFolder })
	// Use a small work factor only in this isolated test fixture.
	r, err := age.NewScryptRecipient("correct fixture password")
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(10)
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "private fixture data"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = DecryptArchive(context.Background(), bytes.NewReader(encrypted.Bytes()), "wrong fixture password")
	if !IsArchivePasswordError(err) {
		t.Fatalf("incorrect passphrase was not identified: %v", err)
	}
	_, err = DecryptArchive(context.Background(), bytes.NewReader([]byte("invalid archive")), "correct fixture password")
	if err == nil || IsArchivePasswordError(err) {
		t.Fatalf("corrupt archive was mistaken for an incorrect passphrase: %v", err)
	}
}

func TestFileMetadataSecretForX25519RequiresValidUnprotectedIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := fileMetadataSecret(identity.String(), false, ArchiveFormatAgeX25519)
	if err != nil || secret != identity.String() {
		t.Fatalf("valid unprotected identity rejected: %v", err)
	}
	if _, err := SetFile(identity.String(), 60, 1, false, false, uuid.NewString(), ArchiveFormatAgeX25519); err == nil || err.Code != http.StatusBadRequest {
		t.Fatalf("unexpected associated password key accepted: %v", err)
	}
	for _, input := range []struct {
		identity string
		provided bool
	}{{"", false}, {"invalid identity", false}, {identity.String(), true}} {
		if _, err := fileMetadataSecret(input.identity, input.provided, ArchiveFormatAgeX25519); !errors.Is(err, errArchiveIdentityRequired) {
			t.Fatalf("invalid identity or provided flag accepted: %v", err)
		}
		if _, err := SetFile(input.identity, 60, 1, false, input.provided, "", ArchiveFormatAgeX25519); err == nil || err.Code != http.StatusBadRequest {
			t.Fatalf("invalid identity or provided flag reached storage: %v", err)
		}
	}
}

func TestFileMetadataPasswordIsolationAndLegacyRedis(t *testing.T) {
	c := cleanupTest(t)
	const password = "test user's separate archive password"
	passwordLink, httpErr := SetPassword(password, 60, 2, false)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	passwordID, passwordKey, err := ParseToken(passwordLink)
	if err != nil {
		t.Fatal(err)
	}
	newLink, httpErr := SetFile(password, 60, 2, false, true, passwordID, ArchiveFormatAgeUserPassword)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	fileID, fileKey, err := ParseToken(newLink)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := redis.Bytes(c.Do("HGET", REDIS_PREFIX+"file_"+fileID, "token"))
	if err != nil {
		t.Fatal(err)
	}
	fileSecret, err := Decrypt(raw, fileKey, 0)
	if err != nil || fileSecret == password || len(fileSecret) != 50 {
		t.Fatal("file-link metadata decrypts to the archive password")
	}
	f := &models.File{FileKey: newLink}
	if err := GetFile(f); err != nil || f.ArchiveFormat != ArchiveFormatAgeUserPassword || f.Password != fileSecret {
		t.Fatalf("new file-link authentication failed: %v", err)
	}
	raw, err = redis.Bytes(c.Do("HGET", REDIS_PREFIX+passwordID, "token"))
	if err != nil {
		t.Fatal(err)
	}
	separatePassword, err := Decrypt(raw, passwordKey, 0)
	if err != nil || separatePassword != password {
		t.Fatal("separate password link no longer recovers the password")
	}
	for _, format := range []string{"", ArchiveFormatAge} {
		var link string
		if format == "" {
			link, httpErr = SetFile(password, 60, 2, false, false, "")
		} else {
			link, httpErr = SetFile(password, 60, 2, false, false, "", format)
		}
		if httpErr != nil {
			t.Fatal(httpErr)
		}
		legacy := &models.File{FileKey: link}
		if err := GetFile(legacy); err != nil || legacy.Password != password || legacy.ArchiveFormat != format {
			t.Fatalf("legacy or generated-password link changed: format=%q err=%v", format, err)
		}
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyLink, httpErr := SetFile(identity.String(), 60, 2, false, false, "", ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	keyFile := &models.File{FileKey: keyLink}
	if err := GetFile(keyFile); err != nil || keyFile.Password != identity.String() || keyFile.ArchiveFormat != ArchiveFormatAgeX25519 {
		t.Fatalf("unprotected identity link changed: %v", err)
	}
}
