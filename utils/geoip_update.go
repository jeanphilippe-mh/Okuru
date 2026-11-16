package utils

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	log "github.com/sirupsen/logrus"
)

const (
	// DB-IP Country Lite is licensed under CC BY 4.0; see https://db-ip.com.
	geoIPUpdateSource    = "https://download.db-ip.com/free/dbip-country-lite-"
	geoIPDatabaseFile    = "dbip-country-lite.mmdb"
	geoIPLockFile        = ".dbip-country-lite.lock"
	geoIPPublicationFile = ".dbip-country-lite.publication"
	geoIPAttemptFile     = ".dbip-country-lite.last-attempt"
	geoIPDatabaseType    = "DBIP-Country-Lite"
	maxGeoIPGzipBytes    = 32 << 20
	GeoIPLoading         = "loading"
)

var (
	errGeoIPUpdateNetwork    = errors.New("network")
	errGeoIPUpdateHTTP       = errors.New("http_status")
	errGeoIPUpdateCompressed = errors.New("invalid_compressed_data")
	errGeoIPUpdateInvalid    = errors.New("invalid_database")
	errGeoIPUpdateFilesystem = errors.New("filesystem")
	errGeoIPUpdateRollback   = errors.New("older_database")
	errGeoIPUpdateBusy       = errors.New("update_busy")
	errGeoIPUpdateRecent     = errors.New("recent_attempt")
)

// GeoIPAutoDatabasePath returns the fixed local cache path. No project-specific
// environment variable or systemd configuration is needed. Cache root discovery
// follows os.UserCacheDir; if unavailable, the caller can continue without GeoIP.
func GeoIPAutoDatabasePath() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil || root == "" || !filepath.IsAbs(root) {
		return "", errGeoIPUpdateFilesystem
	}
	return filepath.Join(root, "okuru", "geoip", geoIPDatabaseFile), nil
}

type geoIPUpdateResult struct {
	changed bool
	pending bool
	build   time.Time
}

type geoIPAutoUpdater struct {
	path            string
	client          *http.Client
	now             func() time.Time
	refreshInterval time.Duration
	retryInitial    time.Duration
	retryMaximum    time.Duration
	mu              sync.Mutex
}

func newGeoIPAutoUpdater(path string) *geoIPAutoUpdater {
	transport := &http.Transport{
		Proxy:                 nil, // never forward visitor-related traffic via an environment proxy
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableCompression:    true,
	}
	return &geoIPAutoUpdater{
		path: path,
		client: &http.Client{
			Transport: transport,
			Timeout:   45 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now, refreshInterval: 24 * time.Hour,
		retryInitial: 15 * time.Minute, retryMaximum: 6 * time.Hour,
	}
}

// StartGeoIPCountryUpdater loads the latest verified cache and updates it in a
// goroutine; startup and request handling do not wait for a network operation.
// Cancel ctx and wait for the returned channel before closing country lookups.
// This performs fixed-source database downloads only, never one lookup per IP.
func StartGeoIPCountryUpdater(ctx context.Context, path string) <-chan struct{} {
	done := make(chan struct{})
	geoIPCountry.Lock()
	if geoIPCountry.reader == nil {
		geoIPCountry.status = GeoIPLoading
	}
	geoIPCountry.Unlock()
	updater := newGeoIPAutoUpdater(path)
	go func() {
		defer close(done)
		defer updater.client.CloseIdleConnections()
		updater.run(ctx)
	}()
	return done
}

func (u *geoIPAutoUpdater) run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	root, rootErr := secureGeoIPCacheRoot(filepath.Dir(u.path))
	if rootErr == nil && filepath.Base(u.path) == geoIPDatabaseFile {
		data, err := readCachedDBIP(filepath.Join(root, geoIPDatabaseFile))
		if err == nil {
			if built, activateErr := activateDBIPSnapshot(data, u.now().UTC()); activateErr == nil {
				geoIPUpdateEntry("geoip.database_loaded").WithField("database_built_at", built.Format(time.RFC3339)).Info("Local DB-IP country database loaded")
			} else {
				markGeoIPLoading()
			}
		} else {
			markGeoIPLoading()
		}
	} else {
		markGeoIPLoading()
	}
	backoff := u.retryInitial
	warned := false
	for ctx.Err() == nil {
		result, err := u.updateOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		delay := u.refreshInterval
		if err != nil {
			MarkGeoIPDatabaseUnavailable()
			if !warned && !errors.Is(err, errGeoIPUpdateBusy) && !errors.Is(err, errGeoIPUpdateRecent) {
				message := "DB-IP country database unavailable"
				if _, available := GeoIPCountryBuildTime(); available {
					message = "DB-IP country database update failed; last valid data retained"
				}
				geoIPUpdateEntry("geoip.update_failed").WithField("reason_class", geoIPUpdateErrorClass(err)).Warn(message)
				warned = true
			}
			delay = backoff
			backoff = min(backoff*2, u.retryMaximum)
		} else {
			if result.changed {
				geoIPUpdateEntry("geoip.database_updated").WithField("database_built_at", result.build.UTC().Format(time.RFC3339)).Info("DB-IP country database updated")
			} else if warned {
				geoIPUpdateEntry("geoip.update_recovered").Info("DB-IP country database update recovered")
			}
			warned = false
			if result.pending {
				delay = backoff
				backoff = min(backoff*2, u.retryMaximum)
			} else {
				backoff = u.retryInitial
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func geoIPUpdateEntry(event string) *log.Entry {
	return log.WithFields(log.Fields{
		"event": event, "source": "DB-IP Country Lite", "license": "CC BY 4.0", "attribution": "https://db-ip.com",
	})
}

func markGeoIPLoading() {
	geoIPCountry.Lock()
	if geoIPCountry.reader == nil {
		geoIPCountry.status = GeoIPLoading
	}
	geoIPCountry.Unlock()
}

// updateOnce is serialized both per process and across cooperating workers. A
// bad response never replaces a valid on-disk or in-memory snapshot.
func (u *geoIPAutoUpdater) updateOnce(ctx context.Context) (geoIPUpdateResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if filepath.Base(u.path) != geoIPDatabaseFile || ctx.Err() != nil {
		return geoIPUpdateResult{}, errGeoIPUpdateFilesystem
	}
	root, err := secureGeoIPCacheRoot(filepath.Dir(u.path))
	if err != nil {
		return geoIPUpdateResult{}, errGeoIPUpdateFilesystem
	}
	path := filepath.Join(root, geoIPDatabaseFile)
	unlock, err := lockGeoIPUpdater(root)
	if err != nil {
		return geoIPUpdateResult{}, err
	}
	defer unlock()

	now := u.now().UTC()
	diskBuild, _, currentValid := existingGeoIPVersion(path, now)
	currentBuild := diskBuild
	inMemory, memoryValid := GeoIPCountryBuildTime()
	if memoryValid && inMemory.After(currentBuild) {
		currentBuild = inMemory
	}
	// Another process may have installed a newer cache since this worker
	// loaded its snapshot. Reload it before checking the source again.
	if currentValid && (!memoryValid || !inMemory.After(diskBuild)) {
		data, readErr := readCachedDBIP(path)
		if readErr != nil {
			return geoIPUpdateResult{}, errGeoIPUpdateFilesystem
		}
		reloaded, activateErr := activateDBIPSnapshot(data, now)
		if activateErr != nil || !reloaded.Equal(diskBuild) {
			return geoIPUpdateResult{}, errGeoIPUpdateInvalid
		}
	}
	cacheMatchesLatest := currentValid && diskBuild.Equal(currentBuild)
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	// Only the publication month recorded at download establishes freshness;
	// the database build timestamp may fall in the preceding month.
	if cacheMatchesLatest && publicationMatches(root, path, month) {
		return geoIPUpdateResult{build: currentBuild}, nil
	}
	if recentlyAttempted(root, now, u.retryInitial) {
		return geoIPUpdateResult{}, errGeoIPUpdateRecent
	}
	if err := recordGeoIPAttempt(root, now); err != nil {
		return geoIPUpdateResult{}, err
	}
	var data []byte
	var build time.Time
	var publication time.Time
	for attempt := 0; attempt < 2; attempt++ {
		candidateMonth := month.AddDate(0, -attempt, 0)
		data, build, err = u.fetch(ctx, candidateMonth, now)
		publication = candidateMonth
		if !errors.Is(err, os.ErrNotExist) {
			break
		}
		// If the new month is not published and the old cache is verified,
		// keep it rather than downloading the same old database again.
		if attempt == 0 && cacheMatchesLatest {
			return geoIPUpdateResult{build: currentBuild, pending: true}, nil
		}
	}
	if err != nil {
		return geoIPUpdateResult{}, err
	}
	if !currentBuild.IsZero() && build.Before(currentBuild) {
		return geoIPUpdateResult{}, errGeoIPUpdateRollback
	}

	if ctx.Err() != nil {
		return geoIPUpdateResult{}, ctx.Err()
	}
	// Prepare the replacement reader before changing the on-disk snapshot, so
	// validation cannot fail after a successful rename.
	reader, _, err := openVerifiedDBIP(data, now)
	if err != nil {
		return geoIPUpdateResult{}, errGeoIPUpdateInvalid
	}
	defer func() {
		if reader != nil {
			_ = reader.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return geoIPUpdateResult{}, err
	}
	if err := replaceGeoIPSnapshot(root, path, data); err != nil {
		return geoIPUpdateResult{}, err
	}
	activateDBIPReader(reader)
	reader = nil // ownership transferred to geoIPCountry
	if err := recordGeoIPPublication(root, data, publication); err != nil {
		return geoIPUpdateResult{}, err
	}
	return geoIPUpdateResult{changed: true, pending: publication.Before(month), build: build}, nil
}

func (u *geoIPAutoUpdater) fetch(ctx context.Context, month, now time.Time) ([]byte, time.Time, error) {
	url := geoIPUpdateSource + month.Format("2006-01") + ".mmdb.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, errGeoIPUpdateNetwork
	}
	req.Header.Set("User-Agent", "Okuru-GeoIP-Update/1.0")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, time.Time{}, errGeoIPUpdateNetwork
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, time.Time{}, os.ErrNotExist
	case http.StatusOK:
	default:
		return nil, time.Time{}, errGeoIPUpdateHTTP
	}
	if resp.ContentLength > maxGeoIPGzipBytes {
		return nil, time.Time{}, errGeoIPUpdateCompressed
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxGeoIPGzipBytes + 1}
	z, err := gzip.NewReader(limited)
	if err != nil {
		return nil, time.Time{}, errGeoIPUpdateCompressed
	}
	data, readErr := io.ReadAll(io.LimitReader(z, maxGeoIPDatabaseBytes+1))
	closeErr := z.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxGeoIPDatabaseBytes || limited.N <= 0 {
		return nil, time.Time{}, errGeoIPUpdateCompressed
	}
	build, err := verifiedDBIPBuild(data, now)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, build, nil
}

func openVerifiedDBIP(data []byte, now time.Time) (*maxminddb.Reader, time.Time, error) {
	reader, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, time.Time{}, errGeoIPUpdateInvalid
	}
	if reader.Verify() != nil || reader.Metadata.DatabaseType != geoIPDatabaseType || reader.Metadata.IPVersion != 6 {
		_ = reader.Close()
		return nil, time.Time{}, errGeoIPUpdateInvalid
	}
	build := reader.Metadata.BuildTime().UTC()
	if build.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) || build.After(now.Add(24*time.Hour)) {
		_ = reader.Close()
		return nil, time.Time{}, errGeoIPUpdateInvalid
	}
	return reader, build, nil
}

func verifiedDBIPBuild(data []byte, now time.Time) (time.Time, error) {
	reader, build, err := openVerifiedDBIP(data, now)
	if err != nil {
		return time.Time{}, err
	}
	_ = reader.Close()
	return build, nil
}

// activateDBIPSnapshot owns data's immutable bytes and atomically swaps the
// reader only after independent type, structure and timestamp validation.
func activateDBIPSnapshot(data []byte, now time.Time) (time.Time, error) {
	reader, build, err := openVerifiedDBIP(data, now)
	if err != nil {
		return time.Time{}, err
	}
	activateDBIPReader(reader)
	return build, nil
}

// activateDBIPReader takes ownership of a reader that has already been verified.
func activateDBIPReader(reader *maxminddb.Reader) {
	geoIPCountry.Lock()
	old := geoIPCountry.reader
	geoIPCountry.reader = reader
	geoIPCountry.status = GeoIPFound
	if old != nil {
		_ = old.Close()
	}
	geoIPCountry.Unlock()
}

func readCachedDBIP(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errGeoIPUpdateFilesystem
	}
	return readGeoIPDatabase(path)
}

func existingGeoIPVersion(path string, now time.Time) (build, modified time.Time, valid bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return time.Time{}, time.Time{}, false
	}
	data, err := readCachedDBIP(path)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	build, err = verifiedDBIPBuild(data, now)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	return build, info.ModTime().UTC(), true
}

func lockGeoIPUpdater(root string) (func(), error) {
	path := filepath.Join(root, geoIPLockFile)
	before, err := os.Lstat(path)
	if err == nil && (!before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0) {
		return nil, errGeoIPUpdateFilesystem
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, errGeoIPUpdateFilesystem
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errGeoIPUpdateFilesystem
	}
	info, statErr := file.Stat()
	after, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, after) {
		_ = file.Close()
		return nil, errGeoIPUpdateFilesystem
	}
	locked, err := quotaTryLock(file)
	if err != nil || !locked {
		_ = file.Close()
		if err != nil {
			return nil, errGeoIPUpdateFilesystem
		}
		return nil, errGeoIPUpdateBusy
	}
	return func() { _ = quotaUnlock(file); _ = file.Close() }, nil
}

func replaceGeoIPSnapshot(root, path string, data []byte) error {
	info, err := os.Lstat(path)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errGeoIPUpdateFilesystem
	}
	if err != nil && !os.IsNotExist(err) {
		return errGeoIPUpdateFilesystem
	}
	file, err := os.CreateTemp(root, ".dbip-country-*.tmp")
	if err != nil {
		return errGeoIPUpdateFilesystem
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err = io.Copy(file, bytes.NewReader(data)); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errGeoIPUpdateFilesystem
	}
	if err = os.Rename(temp, path); err != nil {
		return errGeoIPUpdateFilesystem
	}
	return nil
}

// The fixed-source publication month is bound to the exact validated bytes.
// A missing, stale or modified marker merely triggers another download.
func publicationMatches(root, path string, month time.Time) bool {
	info, err := os.Lstat(filepath.Join(root, geoIPPublicationFile))
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128 {
		return false
	}
	marker, err := os.ReadFile(filepath.Join(root, geoIPPublicationFile))
	if err != nil {
		return false
	}
	data, err := readCachedDBIP(path)
	if err != nil {
		return false
	}
	return string(marker) == fmt.Sprintf("%s %x\n", month.Format("2006-01"), sha256.Sum256(data))
}

func recordGeoIPPublication(root string, data []byte, month time.Time) error {
	path := filepath.Join(root, geoIPPublicationFile)
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return errGeoIPUpdateFilesystem
	}
	if err != nil && !os.IsNotExist(err) {
		return errGeoIPUpdateFilesystem
	}
	file, err := os.CreateTemp(root, ".dbip-publication-*.tmp")
	if err != nil {
		return errGeoIPUpdateFilesystem
	}
	name := file.Name()
	defer os.Remove(name)
	_, err = fmt.Fprintf(file, "%s %x\n", month.Format("2006-01"), sha256.Sum256(data))
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil || os.Rename(name, path) != nil {
		return errGeoIPUpdateFilesystem
	}
	return nil
}

// recentlyAttempted prevents repeated application restarts from generating a
// burst of downloads. Corrupt or future timestamps are ignored; no waiting is
// performed on the request path.
func recentlyAttempted(root string, now time.Time, interval time.Duration) bool {
	path := filepath.Join(root, geoIPAttemptFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 64 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	last, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	return err == nil && !last.After(now) && now.Sub(last) < interval
}

func recordGeoIPAttempt(root string, now time.Time) error {
	path := filepath.Join(root, geoIPAttemptFile)
	info, err := os.Lstat(path)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errGeoIPUpdateFilesystem
	}
	if err != nil && !os.IsNotExist(err) {
		return errGeoIPUpdateFilesystem
	}
	file, err := os.CreateTemp(root, ".dbip-attempt-*.tmp")
	if err != nil {
		return errGeoIPUpdateFilesystem
	}
	name := file.Name()
	defer os.Remove(name)
	_, err = io.WriteString(file, now.UTC().Format(time.RFC3339Nano)+"\n")
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil || os.Rename(name, path) != nil {
		return errGeoIPUpdateFilesystem
	}
	return nil
}

func geoIPUpdateErrorClass(err error) string {
	for _, e := range []error{errGeoIPUpdateNetwork, errGeoIPUpdateHTTP, errGeoIPUpdateCompressed, errGeoIPUpdateInvalid, errGeoIPUpdateFilesystem, errGeoIPUpdateRollback, errGeoIPUpdateBusy, errGeoIPUpdateRecent} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return "not_found"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	return "other"
}
