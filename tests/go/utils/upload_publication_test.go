package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
)

func TestPreparedPublicationRollsBackOnRedisWriteFailure(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		key           int
	}{
		{"file expiration", "pexpireat", 2},
		{"password expiration", "pexpireat", 3},
		{"session expiration", "pexpireat", 0},
		{"session index", "zadd", 1},
		{"session ready state", "hset", 0},
		{"rollback permission", "del", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin := admissionTestRedis(t)
			id, fileID, passwordID := uuid.NewString(), uuid.NewString(), uuid.NewString()
			session, index := UploadSessionRedisKeys(id)
			keys := []string{session, index, REDIS_PREFIX + "file_" + fileID, REDIS_PREFIX + passwordID}
			t.Cleanup(func() { _, _ = admin.Do("DEL", redis.Args{}.AddFlat(keys)...) })
			previousDeadline := time.Now().Add(2 * time.Hour).UnixMilli()
			const previousScore = 1234
			if _, err := admin.Do("HSET", session, "state", "finalizing", "publication_id", fileID, "until", previousScore); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Do("PEXPIREAT", session, previousDeadline); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Do("ZADD", index, previousScore, id); err != nil {
				t.Fatal(err)
			}

			// Limit only the selected command on one of the four test keys.
			user := "publication_" + id
			password := newUploadSecret()
			selector := []string{"+" + tc.command}
			for i, key := range keys {
				if i != tc.key {
					selector = append(selector, "~"+key)
				}
			}
			if _, err := admin.Do("ACL", "SETUSER", user, "on", ">"+password, "~*", "+@all", "-"+tc.command, "("+strings.Join(selector, " ")+")"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = admin.Do("ACL", "DELUSER", user) })
			restricted, err := redis.Dial("tcp", os.Getenv("OKURU_TEST_REDIS_ADDR"), redis.DialUsername(user), redis.DialPassword(password))
			if err != nil {
				t.Fatal(err)
			}
			defer restricted.Close()
			args := redis.Args{}.AddFlat(keys).Add(id, fileID, 60, 1, "0", ArchiveFormatAgeUserPassword, "sealed-file", passwordID, "sealed-password", "sealed-result", "digest", 100000)
			if _, err := commitUploadPublication.Do(restricted, args...); err == nil {
				t.Fatal("publication accepted a denied Redis command")
			}
			if n, err := redis.Int(admin.Do("EXISTS", keys[2], keys[3])); err != nil || n != 0 {
				t.Fatalf("failed publication left new metadata: %d, %v", n, err)
			}
			if state, err := redis.String(admin.Do("HGET", session, "state")); err != nil || state != "finalizing" {
				t.Fatalf("failed publication changed session state: %q, %v", state, err)
			}
			if expiry, err := redis.Int64(admin.Do("PEXPIRETIME", session)); err != nil || expiry != previousDeadline {
				t.Fatalf("failed publication changed session deadline: %d, %v", expiry, err)
			}
			if score, err := redis.Int(admin.Do("ZSCORE", index, id)); err != nil || score != previousScore {
				t.Fatalf("failed publication changed session index: %d, %v", score, err)
			}

			if status, err := redis.Int(commitUploadPublication.Do(admin, args...)); err != nil || status != 1 {
				t.Fatalf("publication could not retry: %d, %v", status, err)
			}
			archiveExpiry, err := redis.Int64(admin.Do("PEXPIRETIME", keys[2]))
			if err != nil || archiveExpiry <= time.Now().UnixMilli() {
				t.Fatalf("missing archive expiration: %d, %v", archiveExpiry, err)
			}
			if expiry, err := redis.Int64(admin.Do("PEXPIRETIME", keys[3])); err != nil || expiry != archiveExpiry {
				t.Fatalf("password expiration differs from archive: %d, %v", expiry, err)
			}
			if status, err := redis.Int(commitUploadPublication.Do(admin, args...)); err != nil || status != 2 {
				t.Fatalf("committed publication could not replay: %d, %v", status, err)
			}
		})
	}
}

func TestPreparedPublicationRecoversWithoutCreatorKey(t *testing.T) {
	for _, collision := range []bool{false, true} {
		name := "response lost"
		if collision {
			name = "foreign archive"
		}
		t.Run(name, func(t *testing.T) {
			conn, r, m := sessionTestSetup(t)
			ctx := context.Background()
			old := FILEFOLDER
			FILEFOLDER = t.TempDir()
			t.Cleanup(func() { FILEFOLDER = old })
			m.Mode = "multipart"
			id, bearer := uuid.NewString(), newUploadSecret()
			if _, _, err := PrepareFileUploadSession(ctx, r, id, bearer, m); err != nil {
				t.Fatal(err)
			}
			if err := BeginMultipartAttempt(ctx, id, bearer, 7); err != nil {
				t.Fatal(err)
			}
			if err := BeginUploadPublication(ctx, id, bearer); err != nil {
				t.Fatal(err)
			}
			p, link, _, err := PrepareUploadRecords(id, &m.Metadata, m.Metadata.Password, ArchiveFormatAgeUserPassword)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(map[string]string{"link": "/file/" + link})
			if err != nil {
				t.Fatal(err)
			}
			p.Result, err = SealUploadResult(id, bearer, raw)
			if err != nil {
				t.Fatal(err)
			}
			root, err := publicationRoot()
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, p.FileID)
			if err = os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, witnessName), []byte("encrypted archive fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			j, err := json.Marshal(p)
			if err != nil || bytes.Contains(j, []byte(link)) || bytes.Contains(j, []byte(bearer)) || bytes.Contains(j, []byte(m.Metadata.Password)) {
				t.Fatal("journal contains private material")
			}
			if err = os.WriteFile(filepath.Join(dir, intentFileName), j, 0600); err != nil {
				t.Fatal(err)
			}
			if err = BindUploadPublication(ctx, id, bearer, p.FileID); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(FILEFOLDER, p.FileID+".zip")
			if collision {
				if err = os.WriteFile(final, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.Link(filepath.Join(dir, witnessName), final); err != nil {
					t.Fatal(err)
				}
				// Lose the commit after linking. Each subsequent retry must
				// preserve the original deadline of this same ciphertext.
				published := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
				stampRetentionTestFile(t, final, published)
				t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "invalid")
				for range 2 {
					if err := ReconcileUploadPublications(ctx); err == nil {
						t.Fatal("expected the pre-commit failure")
					}
					fi, err := os.Stat(final)
					if err != nil || !fi.ModTime().Equal(published) {
						t.Fatal("a publication retry renewed the archive deadline", err)
					}
				}
				t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "100000")
			}
			err = ReconcileUploadPublications(ctx)
			defer conn.Do("DEL", REDIS_PREFIX+"file_"+p.FileID, REDIS_PREFIX+p.PasswordID)
			for range 2 {
				if e := removeExpiredArchive(conn, p.FileID); e != nil {
					t.Fatal(e)
				}
			}
			data, e := os.ReadFile(final)
			if e != nil {
				t.Fatal(e)
			}
			if collision {
				if string(data) != "foreign" || err != nil {
					t.Fatal("collision was not isolated")
				}
				return
			}
			if err != nil || string(data) != "encrypted archive fixture" {
				t.Fatalf("reconcile: %v", err)
			}
			result, err := ReadUploadResult(ctx, id, bearer)
			if err != nil || !bytes.Contains(result, []byte(link)) {
				t.Fatal("receipt lost")
			}
			a, _ := redis.Int64(conn.Do("PEXPIRETIME", REDIS_PREFIX+"file_"+p.FileID))
			b, _ := redis.Int64(conn.Do("PEXPIRETIME", REDIS_PREFIX+p.PasswordID))
			if a != b || a < time.Now().UnixMilli() {
				t.Fatal("unequal share expirations")
			}
			// Simulate death after Redis commit but before removing its journal,
			// followed by receipt expiry while the longer-lived share is still valid.
			if err = os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.Link(final, filepath.Join(dir, witnessName)); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, intentFileName), j, 0600); err != nil {
				t.Fatal(err)
			}
			sessionKey, _ := UploadSessionRedisKeys(id)
			if _, err = conn.Do("DEL", sessionKey); err != nil {
				t.Fatal(err)
			}
			if err = ReconcileUploadPublications(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(final); err != nil {
				t.Fatal("live share lost after receipt expiry", err)
			}
		})
	}
}

func TestArchiveRetentionRetiresOwnedJournalsOffline(t *testing.T) {
	for _, mode := range []string{"published", "private only", "another inode", "retirement interrupted", "active session", "foreign owner", "before intent", "temporary intent"} {
		t.Run(mode, func(t *testing.T) {
			retentionTestFolder(t)
			db := REDIS_DB
			REDIS_DB = "unavailable"
			t.Cleanup(func() { REDIS_DB = db })
			owner, err := AcquireUploadSessionOwner(FILEFOLDER)
			if err != nil {
				t.Fatal(err)
			}
			defer owner()
			p := UploadPublication{FileID: uuid.NewString(), Session: uuid.NewString()}
			root, err := publicationRoot()
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, p.FileID)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			intent, _ := json.Marshal(p)
			switch mode {
			case "before intent":
			case "temporary intent":
				if err := os.WriteFile(filepath.Join(dir, "intent.tmp"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filepath.Join(dir, intentFileName), intent, 0600); err != nil {
					t.Fatal(err)
				}
			}
			witness := filepath.Join(dir, witnessName)
			if err := os.WriteFile(witness, []byte("private ciphertext"), 0600); err != nil {
				t.Fatal(err)
			}
			stale := time.Now().Add(-maxArchiveRetention - time.Hour)
			stampRetentionTestFile(t, witness, stale)
			public := filepath.Join(FILEFOLDER, p.FileID+".zip")
			switch mode {
			case "private only", "before intent", "temporary intent":
			case "another inode":
				if err := os.WriteFile(public, []byte("unrelated file"), 0600); err != nil {
					t.Fatal(err)
				}
				stampRetentionTestFile(t, public, stale)
			default:
				if err := os.Link(witness, public); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.finish(t.Context(), dir); err != errPublicationOverdue {
				t.Fatalf("recovery accepted an expired witness: %v", err)
			}
			if mode == "retirement interrupted" {
				target := filepath.Join(root, retiredPublicationPrefix+p.FileID)
				if err := os.Rename(dir, target); err != nil {
					t.Fatal(err)
				}
				dir = target
				if err := os.Remove(public); err != nil {
					t.Fatal(err)
				}
			}
			sweep := func() {
				t.Helper()
				if err := enforceArchiveRetention(t.Context(), time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "active session" || mode == "before intent" || mode == "temporary intent" {
				var done func()
				if mode == "active session" {
					done, err = LockUploadSession(p.Session)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					var ok bool
					done, ok = lockPublicationJournal(p.FileID)
					if !ok {
						t.Fatal("could not simulate active journal creation")
					}
				}
				sweep()
				done()
				if _, err := os.Stat(witness); err != nil {
					t.Fatal("active session affected", err)
				}
			}
			if mode == "temporary intent" {
				// An unrelated, continuously active upload cannot retain this orphan.
				done, err := LockUploadSession(uuid.NewString())
				if err != nil {
					t.Fatal(err)
				}
				defer done()
			} else {
				owner() // The service can be offline before ordinary recovery has an owner.
			}
			if mode == "foreign owner" {
				file, err := os.OpenFile(filepath.Join(FILEFOLDER, uploadOwnerMarker), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if ok, err := quotaTryLock(file); err != nil || !ok {
					t.Fatal("cannot lock", err)
				}
				sweep()
				if _, err := os.Stat(witness); err != nil {
					t.Fatal("foreign owner was disturbed", err)
				}
				if err := quotaUnlock(file); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("OKURU_CLEANUP_DRY_RUN", "true")
			sweep()
			if _, err := os.Stat(filepath.Join(dir, witnessName)); err != nil {
				t.Fatal("dry run removed the private ciphertext", err)
			}
			t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
			sweep()
			if err := ReconcileUploadPublications(t.Context()); err != nil {
				t.Fatal(err)
			}
			sweep()
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				t.Fatal("journal survives", err)
			}
			if _, err := os.Lstat(filepath.Join(root, retiredPublicationPrefix+p.FileID)); !os.IsNotExist(err) {
				t.Fatal("retired witness survives", err)
			}
			if mode == "another inode" {
				if b, err := os.ReadFile(public); err != nil || string(b) != "unrelated file" {
					t.Fatal("foreign archive lost", err)
				}
			} else if _, err := os.Lstat(public); !os.IsNotExist(err) {
				t.Fatal("expired archive was resurrected", err)
			}
		})
	}
}

func TestArchiveRetentionStagingAndOwnerShutdown(t *testing.T) {
	retentionTestFolder(t)
	active, err := CreateLockedStagingDir(FILEFOLDER, ".okuru-upload-")
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	archive := filepath.Join(active.Path, "archive.tmp")
	if err := os.WriteFile(archive, []byte("sealed"), 0600); err != nil {
		t.Fatal(err)
	}
	stampRetentionTestFile(t, archive, time.Now().Add(-maxArchiveRetention-time.Hour))
	// Reconstruct the surviving hard link and unlocked marker left by a crash.
	orphan := filepath.Join(FILEFOLDER, ".okuru-upload-123")
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(archive, filepath.Join(orphan, "archive.tmp")); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(active.Path, ".okuru-staging-lock-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, ".okuru-staging-lock-v1"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "true")
	if err := enforceArchiveRetention(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(orphan, "archive.tmp")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKURU_CLEANUP_DRY_RUN", "false")
	if err := enforceArchiveRetention(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatal("inactive ciphertext remains", err)
	}
	if _, err := os.Lstat(archive); err != nil {
		t.Fatal("active stage was collected", err)
	}

	release, err := AcquireUploadSessionOwner(FILEFOLDER)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	store, err := os.OpenRoot(FILEFOLDER)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	unlock, err := lockJournalForRetention(store, uuid.NewString(), uuid.NewString())
	if err != nil || unlock == nil {
		t.Fatal("failed to acquire journal retirement lock", err)
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	go func() { close(started); release(); close(stopped) }()
	<-started
	select {
	case <-stopped:
		t.Fatal("the owner released its file lock while retirement was active")
	case <-time.After(20 * time.Millisecond):
	}
	unlock()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the retiring journal prevented a clean owner shutdown")
	}
}

func TestFinalizationLostBeforeBindingCanRetry(t *testing.T) {
	_, r, m := sessionTestSetup(t)
	m.Mode = "multipart"
	ctx := t.Context()
	id, bearer := uuid.NewString(), newUploadSecret()
	if _, _, err := PrepareFileUploadSession(ctx, r, id, bearer, m); err != nil {
		t.Fatal(err)
	}
	if err := BeginMultipartAttempt(ctx, id, bearer, 7); err != nil {
		t.Fatal(err)
	}
	if err := BeginUploadPublication(ctx, id, bearer); err != nil {
		t.Fatal(err)
	}
	state := func(want string) {
		t.Helper()
		s, err := AuthorizeUploadSession(ctx, id, bearer, false)
		if err != nil || s.State != want {
			t.Fatalf("want %s, got %v, err %v", want, s, err)
		}
	}
	unlock, err := LockUploadSession(id)
	if err != nil {
		t.Fatal(err)
	}
	err = recoverUnboundFinalizations(ctx)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	state("finalizing")
	if err := recoverUnboundFinalizations(ctx); err != nil {
		t.Fatal(err)
	}
	state("open")
	if err := BeginMultipartAttempt(ctx, id, bearer, 7); err != nil {
		t.Fatal(err)
	}
	if err := BeginUploadPublication(ctx, id, bearer); err != nil {
		t.Fatal(err)
	}
	if err := BindUploadPublication(ctx, id, bearer, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if err := recoverUnboundFinalizations(ctx); err != nil {
		t.Fatal(err)
	}
	state("finalizing")
}
