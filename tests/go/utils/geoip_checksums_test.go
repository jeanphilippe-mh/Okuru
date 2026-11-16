package utils

import (
	"bytes"
	"context"
	"crypto/md5"  // DB-IP publishes this legacy digest for compatibility, not authentication.
	"crypto/sha1" // DB-IP publishes this legacy digest for compatibility, not authentication.
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func checksumTestCard(format, release, url, md5sum, sha1sum string) string {
	return fmt.Sprintf(`<div class="card"><dl class="card-body"><dt>Format</dt><dd>%s</dd><dt>Release</dt><dd>%s</dd><dt>MD5SUM</dt><dd>%s</dd><dt>SHA1SUM</dt><dd>%s</dd></dl><div><a href="%s">Download</a></div></div>`, format, release, md5sum, sha1sum, url)
}

func checksumTestPage(format, release, url string, data []byte) []byte {
	return []byte("<html><body>" + checksumTestCard(format, release, url, fmt.Sprintf("%x", md5.Sum(data)), fmt.Sprintf("%x", sha1.Sum(data))) + "</body></html>")
}

// Exercise the updater against the supplied responses, without the other
// updater tests' helper automatically synthesizing matching vendor checksums.
func checksumTestUpdater(t *testing.T, now time.Time, handler geoIPRoundTrip) *geoIPAutoUpdater {
	t.Helper()
	u := testUpdater(t, now, handler)
	u.client = &http.Client{Transport: handler}
	return u
}

func TestDBIPChecksumParsesObservedVendorHTML(t *testing.T) {
	// Frozen fragment of the DB-IP Country Lite MMDB card observed on
	// 2026-11-16. The digest values are examples for that publication only.
	const card = `<div class="card"><dl class="card-body"><dt>Format</dt><dd>MMDB</dd><dt>Release</dt><dd>November 2026</dd><dt>Supported language(s)</dt><dd>English, French, German, Spanish, Portuguese, Chinese, Japanese, Russian, Persian, Korean</dd><dt>Number of records</dt><dd>732,796</dd><dt>File size</dt><dd>8.1 MB</dd><dt>MD5SUM</dt><dd class="small">5974b336a7409ec854f67eacd52c2061</dd><dt>SHA1SUM</dt><dd class="small">09eea8433fe3eed71984fd6aac9d8ab3d9ca51f0</dd></dl><div class="px-1 mb-1"><a href="https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz" class="btn btn-block icon-txt download free_download_link">Download IP to Country Lite MMDB</a></div></div>`
	checksums, err := parseGeoIPChecksums([]byte(card), geoIPUpdateSource+"2026-11.mmdb.gz")
	if err != nil {
		t.Fatalf("parse the observed DB-IP card: %v", err)
	}
	if got := fmt.Sprintf("%x", checksums.md5); got != "5974b336a7409ec854f67eacd52c2061" {
		t.Fatalf("incorrect MD5: %s", got)
	}
	if got := fmt.Sprintf("%x", checksums.sha1); got != "09eea8433fe3eed71984fd6aac9d8ab3d9ca51f0" {
		t.Fatalf("incorrect SHA-1: %s", got)
	}
}

func TestDBIPChecksumParserSelectsExpectedMMDB(t *testing.T) {
	data := []byte("database contents")
	url := geoIPUpdateSource + "2026-11.mmdb.gz"
	page := []byte(`<html><body>` + checksumTestCard("CSV", "November 2026", geoIPUpdateSource+"2026-11.csv.gz", strings.Repeat("a", 32), strings.Repeat("b", 40)) + checksumTestCard("MMDB", "November 2026", url, fmt.Sprintf("%x", md5.Sum(data)), fmt.Sprintf("%x", sha1.Sum(data))) + `</body></html>`)
	checksums, err := parseGeoIPChecksums(page, url)
	if err != nil {
		t.Fatalf("parse valid MMDB card: %v", err)
	}
	if !verifyGeoIPChecksums(data, checksums) {
		t.Fatal("matching MMDB checksums rejected")
	}
	if verifyGeoIPChecksums([]byte("different contents"), checksums) {
		t.Fatal("different bytes accepted")
	}
}

func TestDBIPChecksumParserRejectsMissingOrAmbiguousData(t *testing.T) {
	url := geoIPUpdateSource + "2026-11.mmdb.gz"
	good := checksumTestCard("MMDB", "November 2026", url, strings.Repeat("a", 32), strings.Repeat("b", 40))
	for _, tc := range []struct {
		name string
		page string
	}{
		{"missing MD5", strings.Replace(good, "<dt>MD5SUM</dt>", "<dt>other</dt>", 1)},
		{"missing SHA-1", strings.Replace(good, "<dt>SHA1SUM</dt>", "<dt>other</dt>", 1)},
		{"invalid digest", strings.Replace(good, strings.Repeat("a", 32), strings.Repeat("z", 32), 1)},
		{"duplicate matching cards", good + good},
		{"duplicate field", strings.Replace(good, "<dt>MD5SUM</dt>", "<dt>MD5SUM</dt><dd>"+strings.Repeat("a", 32)+"</dd><dt>MD5SUM</dt>", 1)},
		{"CSV only", checksumTestCard("CSV", "November 2026", geoIPUpdateSource+"2026-11.csv.gz", strings.Repeat("a", 32), strings.Repeat("b", 40))},
		{"CSV claiming MMDB URL", checksumTestCard("CSV", "November 2026", url, strings.Repeat("a", 32), strings.Repeat("b", 40))},
		{"different month", checksumTestCard("MMDB", "October 2026", geoIPUpdateSource+"2026-10.mmdb.gz", strings.Repeat("a", 32), strings.Repeat("b", 40))},
		{"release does not match URL", checksumTestCard("MMDB", "October 2026", url, strings.Repeat("a", 32), strings.Repeat("b", 40))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseGeoIPChecksums([]byte("<html><body>"+tc.page+"</body></html>"), url); err == nil {
				t.Fatal("ambiguous or invalid metadata accepted")
			}
		})
	}
}

func TestDBIPChecksumUpdaterAcceptsMatchingSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	previous := fakeDBIP(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	candidateTime := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	candidate := fakeDBIP(t, candidateTime)
	url := geoIPUpdateSource + "2026-11.mmdb.gz"
	u := checksumTestUpdater(t, now, func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case url:
			return geoIPResponse(http.StatusOK, gzipDBIP(t, candidate)), nil
		case geoIPChecksumsSource:
			return geoIPResponse(http.StatusOK, checksumTestPage("MMDB", "November 2026", url, candidate)), nil
		default:
			t.Fatalf("unexpected request to %q", r.URL)
			return nil, nil
		}
	})
	if err := os.WriteFile(u.path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := activateDBIPSnapshot(previous, now); err != nil {
		t.Fatal(err)
	}
	result, err := u.updateOnce(context.Background())
	if err != nil || !result.changed {
		t.Fatalf("matching update rejected: %+v %v", result, err)
	}
	actual, err := os.ReadFile(u.path)
	if err != nil || !bytes.Equal(actual, candidate) {
		t.Fatalf("candidate not installed on disk: %v", err)
	}
	if built, ok := GeoIPCountryBuildTime(); !ok || !built.Equal(candidateTime) {
		t.Fatalf("candidate not activated in memory: %v %v", built, ok)
	}
}

func TestDBIPChecksumUpdaterRejectsAndRetainsSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	previous := fakeDBIP(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	candidate := fakeDBIP(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	url := geoIPUpdateSource + "2026-11.mmdb.gz"
	md5sum := fmt.Sprintf("%x", md5.Sum(candidate))
	sha1sum := fmt.Sprintf("%x", sha1.Sum(candidate))
	goodPage := checksumTestCard("MMDB", "November 2026", url, md5sum, sha1sum)
	for _, tc := range []struct {
		name string
		page string
	}{
		{"MD5 mismatch", strings.Replace(goodPage, md5sum, strings.Repeat("0", 32), 1)},
		{"SHA-1 mismatch", strings.Replace(goodPage, sha1sum, strings.Repeat("0", 40), 1)},
		{"missing checksum", strings.Replace(goodPage, "<dt>SHA1SUM</dt>", "<dt>other</dt>", 1)},
		{"wrong month", checksumTestCard("MMDB", "October 2026", geoIPUpdateSource+"2026-10.mmdb.gz", md5sum, sha1sum)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := checksumTestUpdater(t, now, func(r *http.Request) (*http.Response, error) {
				switch r.URL.String() {
				case url:
					return geoIPResponse(http.StatusOK, gzipDBIP(t, candidate)), nil
				case geoIPChecksumsSource:
					return geoIPResponse(http.StatusOK, []byte("<html><body>"+tc.page+"</body></html>")), nil
				default:
					t.Fatalf("unexpected request to %q", r.URL)
					return nil, nil
				}
			})
			if err := os.WriteFile(u.path, previous, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := activateDBIPSnapshot(previous, now); err != nil {
				t.Fatal(err)
			}
			if _, err := u.updateOnce(context.Background()); err == nil {
				t.Fatal("update with invalid checksum metadata succeeded")
			}
			actual, err := os.ReadFile(u.path)
			if err != nil || !bytes.Equal(actual, previous) {
				t.Fatalf("previous disk database not retained: %v", err)
			}
			if code, _, status := LookupGeoIPCountry("81.2.69.160"); code != "GB" || status != GeoIPFound {
				t.Fatalf("previous in-memory snapshot lost: %q %q", code, status)
			}
		})
	}
}
