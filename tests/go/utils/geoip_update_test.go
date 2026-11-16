package utils

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type geoIPRoundTrip func(*http.Request) (*http.Response, error)

func (f geoIPRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeDBIP(t *testing.T, built time.Time) []byte {
	t.Helper()
	data, err := os.ReadFile(geoIPFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	old := append([]byte{0x4e}, []byte("GeoIP2-Country")...)
	replacement := append([]byte{0x51}, []byte("DBIP-Country-Lite")...)
	if !bytes.Contains(data, old) {
		t.Fatal("fixture type absent")
	}
	data = bytes.Replace(data, old, replacement, 1)
	old = append([]byte{0x49}, []byte("languages")...)
	old = append(old, 0x01, 0x04, 0x20, 0x78)
	replacement = append([]byte{0x49}, []byte("languages")...)
	replacement = append(replacement, 0x01, 0x04, 0x42, 'e', 'n')
	if !bytes.Contains(data, old) {
		t.Fatal("fixture language absent")
	}
	data = bytes.Replace(data, old, replacement, 1)
	i := bytes.LastIndex(data, []byte("build_epoch"))
	if i < 0 {
		t.Fatal("fixture epoch absent")
	}
	i += len("build_epoch")
	if data[i] != 0x04 || data[i+1] != 0x02 {
		t.Fatal("unexpected fixture epoch encoding")
	}
	binary.BigEndian.PutUint32(data[i+2:i+6], uint32(built.Unix()))
	return data
}
func gzipDBIP(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func updaterTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func testUpdater(t *testing.T, now time.Time, handler geoIPRoundTrip) *geoIPAutoUpdater {
	t.Helper()
	_ = CloseGeoIPCountry()
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	u := newGeoIPAutoUpdater(filepath.Join(updaterTestRoot(t), geoIPDatabaseFile))
	u.now = func() time.Time { return now }
	// Existing updater scenarios provide a fake archive response. Also serve
	// matching vendor metadata so these tests exercise the same candidate data
	// after the independent checksum gate has accepted it.
	var archiveURL string
	var archive []byte
	u.client = &http.Client{Transport: geoIPRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == geoIPChecksumsSource {
			z, err := gzip.NewReader(bytes.NewReader(archive))
			if err != nil {
				t.Fatalf("checksum fixture: %v", err)
			}
			data, err := io.ReadAll(z)
			if err != nil {
				t.Fatalf("checksum fixture: %v", err)
			}
			if err := z.Close(); err != nil {
				t.Fatalf("checksum fixture: %v", err)
			}
			monthText := strings.TrimSuffix(strings.TrimPrefix(archiveURL, geoIPUpdateSource), ".mmdb.gz")
			month, err := time.Parse("2006-01", monthText)
			if err != nil {
				t.Fatalf("checksum fixture month: %v", err)
			}
			page := fmt.Sprintf(`<div class="card"><dl><dt>Format</dt><dd>MMDB</dd><dt>Release</dt><dd>%s</dd><dt>MD5SUM</dt><dd>%x</dd><dt>SHA1SUM</dt><dd>%x</dd></dl><a href="%s">Download</a></div>`, month.Format("January 2006"), md5.Sum(data), sha1.Sum(data), archiveURL)
			return geoIPResponse(http.StatusOK, []byte(page)), nil
		}
		resp, err := handler(r)
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			archiveURL = r.URL.String()
			archive, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(archive))
		}
		return resp, err
	})}
	return u
}
func geoIPResponse(code int, data []byte) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Header: make(http.Header)}
}

func TestGeoIPUpdaterMonthlyCacheAndNoIPNetwork(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	// Build is deliberately from the previous month: freshness follows the URL, not build time.
	data := fakeDBIP(t, time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC))
	zipped := gzipDBIP(t, data)
	downloadRequests := 0
	u := testUpdater(t, now, func(r *http.Request) (*http.Response, error) {
		downloadRequests++
		if r.URL.String() != geoIPUpdateSource+"2026-11.mmdb.gz" {
			t.Fatalf("unexpected URL %s", r.URL)
		}
		return geoIPResponse(200, zipped), nil
	})
	result, err := u.updateOnce(context.Background())
	if err != nil || !result.changed || result.pending {
		t.Fatalf("install: %+v %v", result, err)
	}
	if code, _, status := LookupGeoIPCountry("81.2.69.160"); code != "GB" || status != GeoIPFound {
		t.Fatalf("lookup %q %q", code, status)
	}
	if _, err := u.updateOnce(context.Background()); err != nil || downloadRequests != 1 {
		t.Fatalf("fresh month re-downloaded: %d %v", downloadRequests, err)
	}
	_ = CloseGeoIPCountry()
	if _, err := u.updateOnce(context.Background()); err != nil || downloadRequests != 1 {
		t.Fatalf("reload after restart: %d %v", downloadRequests, err)
	}
	if code, _, _ := LookupGeoIPCountry("81.2.69.160"); code != "GB" {
		t.Fatal("cache was not reloaded")
	}
}

func TestGeoIPUpdaterFallbackRetryAndRestartThrottle(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	data := fakeDBIP(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	zipped := gzipDBIP(t, data)
	downloadRequests := 0
	u := testUpdater(t, now, func(r *http.Request) (*http.Response, error) {
		downloadRequests++
		if strings.Contains(r.URL.Path, "2026-11") {
			return geoIPResponse(404, nil), nil
		}
		return geoIPResponse(200, zipped), nil
	})
	result, err := u.updateOnce(context.Background())
	if err != nil || !result.changed || !result.pending || downloadRequests != 2 {
		t.Fatalf("fallback: %+v %v downloads=%d", result, err, downloadRequests)
	}
	_, err = u.updateOnce(context.Background())
	if !errors.Is(err, errGeoIPUpdateRecent) || downloadRequests != 2 {
		t.Fatalf("throttle: %v %d", err, downloadRequests)
	}
	u.now = func() time.Time { return now.Add(16 * time.Minute) }
	result, err = u.updateOnce(context.Background())
	if err != nil || !result.pending || downloadRequests != 3 {
		t.Fatalf("retry: %+v %v downloads=%d", result, err, downloadRequests)
	}
}

func TestGeoIPUpdaterRejectsBadCandidateAndRollback(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	valid := fakeDBIP(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	older := fakeDBIP(t, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	future := fakeDBIP(t, now.Add(48*time.Hour))
	compressed := gzipDBIP(t, valid)
	corruptChecksum := bytes.Clone(compressed)
	corruptChecksum[len(corruptChecksum)-8] ^= 0xff
	for _, tc := range []struct {
		name     string
		payload  []byte
		expected error
	}{{"invalid gzip", []byte("garbage"), errGeoIPUpdateCompressed},
		{"truncated gzip", compressed[:len(compressed)-4], errGeoIPUpdateCompressed},
		{"invalid gzip checksum", corruptChecksum, errGeoIPUpdateCompressed},
		{"truncated database", gzipDBIP(t, valid[:len(valid)-10]), errGeoIPUpdateInvalid},
		{"future database", gzipDBIP(t, future), errGeoIPUpdateInvalid},
		{"rollback", gzipDBIP(t, older), errGeoIPUpdateRollback}, {"wrong type", gzipDBIP(t, func() []byte {
			d, e := os.ReadFile(geoIPFixture(t))
			if e != nil {
				t.Fatal(e)
			}
			return d
		}()), errGeoIPUpdateInvalid}} {
		t.Run(tc.name, func(t *testing.T) {
			u := testUpdater(t, now, func(*http.Request) (*http.Response, error) { return geoIPResponse(200, tc.payload), nil })
			if err := os.WriteFile(u.path, valid, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := activateDBIPSnapshot(valid, now); err != nil {
				t.Fatal(err)
			}
			_, err := u.updateOnce(context.Background())
			if !errors.Is(err, tc.expected) {
				t.Fatalf("got %v", err)
			}
			after, err := os.ReadFile(u.path)
			if err != nil || !bytes.Equal(after, valid) {
				t.Fatalf("cache changed: %v", err)
			}
			if code, _, _ := LookupGeoIPCountry("81.2.69.160"); code != "GB" {
				t.Fatal("old reader lost")
			}
		})
	}
}

func TestGeoIPUpdaterLockAndCancellation(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	u := testUpdater(t, now, func(r *http.Request) (*http.Response, error) {
		calls++
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	root, err := secureGeoIPCacheRoot(filepath.Dir(u.path))
	if err != nil {
		t.Fatal(err)
	}
	release, err := lockGeoIPUpdater(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.updateOnce(context.Background())
	if !errors.Is(err, errGeoIPUpdateBusy) || calls != 0 {
		t.Fatalf("lock: %v calls=%d", err, calls)
	}
	release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updater did not stop")
	}
}

func TestGeoIPUpdaterReloadsChangedSnapshotWithSameBuild(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	built := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	old := fakeDBIP(t, built)
	updated := bytes.Replace(old, []byte("Royaume-Uni"), []byte("Royaume-Unx"), 1)
	if bytes.Equal(old, updated) {
		t.Fatal("test string not found")
	}
	requests := 0
	u := testUpdater(t, now, func(*http.Request) (*http.Response, error) { requests++; return geoIPResponse(500, nil), nil })
	if _, err := activateDBIPSnapshot(old, now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.path, updated, 0600); err != nil {
		t.Fatal(err)
	}
	if err := recordGeoIPPublication(filepath.Dir(u.path), updated, now); err != nil {
		t.Fatal(err)
	}
	if _, err := u.updateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, name, status := LookupGeoIPCountry("81.2.69.160")
	if status != GeoIPFound || name != "Royaume-Unx" || requests != 0 {
		t.Fatalf("name=%q status=%q requests=%d", name, status, requests)
	}
}
