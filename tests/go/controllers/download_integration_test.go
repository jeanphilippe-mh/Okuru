package controllers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gomodule/redigo/redis"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
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

func TestArchiveCapacityPreservesViewsAndContinuation(t *testing.T) {
	conn := configureCompatibilityRedis(t)
	e, token, _, plain := resumeFixture(t, conn, u.ArchiveFormatAgeX25519, false)
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	capacityRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	capacityRequest.RemoteAddr = "127.0.0.1:1234"
	archiveName, err := archiveNameFromToken(token)
	if err != nil {
		t.Fatal(err)
	}
	reserveArchive := func() func() {
		t.Helper()
		var releases []func()
		for range maxDownloadsPerArchive {
			release := archiveDownloads.TryAcquire(capacityRequest, archiveName)
			if release == nil {
				t.Fatal("could not reserve download capacity")
			}
			releases = append(releases, release)
		}
		return func() {
			for _, release := range releases {
				release()
			}
		}
	}

	release := reserveArchive()
	post, postErr := postDownload(t, e, token, "")
	release()
	if fault, found := errors.AsType[*echo.HTTPError](postErr); !found || fault.Code != http.StatusServiceUnavailable || post.Header().Get("Retry-After") != "1" {
		t.Fatalf("download authorization at capacity: %v %v", postErr, post.Header())
	}
	fileKey := u.REDIS_PREFIX + "file_" + id
	if views, err := redis.Int(conn.Do("HGET", fileKey, "views_count")); err != nil || views != 0 {
		t.Fatalf("rejected authorization recorded a view: %d %v", views, err)
	}

	cookie, _, etag := interruptedSession(t, conn, e, token, 5)
	release = reserveArchive()
	refused, _ := getResume(e, token, cookie, "bytes=5-", etag)
	release()
	if refused.Code != http.StatusServiceUnavailable || refused.Header().Get("Retry-After") != "1" {
		t.Fatalf("continuation at capacity: %d %v", refused.Code, refused.Header())
	}
	sessionKey := u.REDIS_PREFIX + "download_session_" + id + "_" + downloadSessionDigest(cookie.Value)
	if requests, err := redis.Int(conn.Do("HGET", sessionKey, "requests")); err != nil || requests != 0 {
		t.Fatalf("rejected continuation consumed a request: %d %v", requests, err)
	}
	resumed, err := getResume(e, token, cookie, "bytes=5-", etag)
	if err != nil || resumed.Code != http.StatusPartialContent || !bytes.Equal(resumed.Body.Bytes(), plain[5:]) {
		t.Fatalf("continuation after capacity returned: %d %v", resumed.Code, err)
	}
}
