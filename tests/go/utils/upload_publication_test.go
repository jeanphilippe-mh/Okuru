package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
				if string(data) != "foreign" || err == nil {
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
			if err = ReconcileUploadPublications(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
