package controllers

import (
	"github.com/gomodule/redigo/redis"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"net/http"
	"testing"
)

func TestDownloadRejectsUnsupportedMetadataBeforeReservingView(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, _ := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _, _ := u.ParseToken(token)
	key := u.REDIS_PREFIX + "file_" + id
	for _, format := range []string{"", "age-v1", "unknown-v99"} {
		if _, err := conn.Do("HSET", key, "archive_format", format); err != nil {
			t.Fatal(err)
		}
		rec, err := downloadCompatibilityFile(t, e, token, "")
		if err != nil || rec.Code != http.StatusNotFound {
			t.Fatalf("unsupported format %q: %d %v", format, rec.Code, err)
		}
		if used, err := redis.Int(conn.Do("HGET", key, "views_count")); err != nil || used != 0 {
			t.Fatal("unsupported archive consumed a view")
		}
	}
}
