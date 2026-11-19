package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

func downloadSessionCookiePrefix(token string) (string, error) {
	id, _, err := ParseToken(token)
	if err != nil {
		return "", errors.New("Invalid file link")
	}
	return "__Secure-okuru-dl-" + id + "-", nil
}

func downloadSessionDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func downloadSessionCookie(token, value string) (string, error) {
	prefix, err := downloadSessionCookiePrefix(token)
	if err != nil {
		return "", err
	}
	return prefix + downloadSessionDigest(value), nil
}

func sessionETag(base, value string) string {
	return strings.TrimSuffix(base, `"`) + "-" + downloadSessionDigest(value) + `"`
}

// The dedicated URL selects one session. On the older URL, the browser can
// disambiguate concurrent sessions using the If-Range validator.
func chooseDownloadCookie(c *echo.Context, token string) (*http.Cookie, error) {
	prefix, err := downloadSessionCookiePrefix(token)
	if err != nil {
		return nil, err
	}
	if id := c.Param("session_id"); id != "" {
		cookie, err := c.Cookie(prefix + id)
		if err != nil || downloadSessionDigest(cookie.Value) != id {
			return nil, errors.New("Download session is missing")
		}
		return cookie, nil
	}
	candidates := make(map[string]*http.Cookie)
	for _, cookie := range c.Request().Cookies() {
		if cookie.Name == prefix+downloadSessionDigest(cookie.Value) {
			candidates[downloadSessionDigest(cookie.Value)] = cookie
		}
	}
	validator := c.Request().Header.Get("If-Range")
	if strings.HasPrefix(validator, `"`) && strings.HasSuffix(validator, `"`) {
		bare := strings.TrimSuffix(validator, `"`)
		if len(bare) >= 65 && bare[len(bare)-65] == '-' {
			if cookie := candidates[bare[len(bare)-64:]]; cookie != nil {
				return cookie, nil
			}
		}
	}
	if len(candidates) == 1 {
		for _, cookie := range candidates {
			return cookie, nil
		}
	}
	return nil, errors.New("Download session is missing or ambiguous")
}

// downloadArchive reads the stored file directly without staging plaintext.
// age authenticates each requested chunk and the final chunk.
type downloadArchive struct {
	file   *os.File
	reader io.ReaderAt
	size   int64
	etag   string
	info   os.FileInfo
}

func openDownloadArchive(c *echo.Context, f *File, secret, name string) (*downloadArchive, error) {
	if !ValidFileArchiveFormat(f.ArchiveFormat, f.PasswordProvided) {
		return nil, errors.New("Invalid archive metadata")
	}
	file, err := OpenStorageArchive(filepath.Join(FILEFOLDER, name))
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*downloadArchive, error) { _ = file.Close(); return nil, err }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return closeOnError(errors.New("Invalid archive"))
	}
	var reader io.ReaderAt
	var size int64
	switch f.ArchiveFormat {
	case ArchiveFormatAgeUserPassword:
		reader, size, err = DecryptArchiveReaderAt(c.Request().Context(), file, info.Size(), secret)
	case ArchiveFormatAgeX25519:
		reader, size, err = DecryptArchiveIdentityReaderAt(c.Request().Context(), file, info.Size(), secret)
	default:
		return closeOnError(errors.New("Unsupported archive format"))
	}
	if err != nil {
		return closeOnError(err)
	}
	etag, err := encryptedArchiveETag(file, info.Size())
	if err != nil {
		return closeOnError(err)
	}
	archive := &downloadArchive{file: file, reader: reader, size: size, etag: etag, info: info}
	if err := archive.verifyUnchanged(); err != nil {
		return closeOnError(err)
	}
	return archive, nil
}

func (a *downloadArchive) verifyUnchanged() error {
	if a.file == nil || a.info == nil {
		return nil
	}
	current, err := a.file.Stat()
	if err != nil || !os.SameFile(a.info, current) || current.Size() != a.info.Size() || !current.ModTime().Equal(a.info.ModTime()) {
		return errors.New("Archive changed during download")
	}
	return nil
}

// age uses an independent random file key and nonce for each archive. Bind the
// validator to both ends and the total size of the ciphertext so a resumed
// transfer does not silently join two separately encrypted versions.
func encryptedArchiveETag(file *os.File, size int64) (string, error) {
	if size < 0 {
		return "", errors.New("Invalid archive size")
	}
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "%d:", size); err != nil {
		return "", err
	}
	first := min(size, int64(4096))
	if _, err := io.CopyN(h, io.NewSectionReader(file, 0, first), first); err != nil {
		return "", err
	}
	tail := min(size, int64(65552))
	if _, err := io.CopyN(h, io.NewSectionReader(file, size-tail, tail), tail); err != nil {
		return "", err
	}
	return `"` + hex.EncodeToString(h.Sum(nil)) + `"`, nil
}

// parseSingleByteRange accepts one bounded or open-ended RFC byte range. It
// rejects multiple ranges to bound work and amplification per continuation.
func parseSingleByteRange(value string, size int64) (start, length int64, err error) {
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") || size <= 0 {
		return 0, 0, errors.New("Invalid range")
	}
	left, right, ok := strings.Cut(strings.TrimPrefix(value, "bytes="), "-")
	if !ok || (left == "" && right == "") || strings.Contains(right, "-") {
		return 0, 0, errors.New("Invalid range")
	}
	for _, part := range []string{left, right} {
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return 0, 0, errors.New("Invalid range")
			}
		}
	}
	if left == "" {
		n, e := strconv.ParseInt(right, 10, 64)
		if e != nil || n <= 0 {
			return 0, 0, errors.New("Invalid range")
		}
		if n > size {
			n = size
		}
		return size - n, n, nil
	}
	start, err = strconv.ParseInt(left, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, errors.New("Invalid range")
	}
	end := size - 1
	if right != "" {
		end, err = strconv.ParseInt(right, 10, 64)
		if err != nil || end < start {
			return 0, 0, errors.New("Invalid range")
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end - start + 1, nil
}

type downloadBudget struct {
	session  *DownloadSession
	reserved int64
	written  int64
}

// downloadProgress records only bytes handed to the response writer. It does
// not claim that an upstream proxy delivered those bytes to the browser.
type downloadProgress struct {
	session                 *DownloadSession
	start, written          int64
	integrityOK, responseOK bool
	representationOK        bool
	started                 bool
}

func (p *downloadProgress) finish() {
	if !p.started {
		if err := AbandonDownloadPreparation(p.session); err != nil {
			log.Error("Could not release download preparation")
		}
		return
	}
	if err := RecordDownloadProgress(p.session, p.start, p.written, p.integrityOK, p.responseOK); err != nil {
		log.Error("Could not finalize download progress")
	}
}

// Record a final write error even when a writer accepts the entire buffer.
type responseWriteTracker struct {
	http.ResponseWriter
	writeErr error
}

func (w *responseWriteTracker) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		w.writeErr = errors.Join(w.writeErr, err)
	} else if n != len(p) {
		w.writeErr = errors.Join(w.writeErr, io.ErrShortWrite)
	}
	return n, err
}

func (b *downloadBudget) finish() {
	if b == nil {
		return
	}
	if err := RefundDownloadBytes(b.session, b.reserved-b.written); err != nil {
		log.Error("Could not refund unused download reservation")
	}
}

func matchesDownloadIfRange(validator, etag string, lastModified time.Time) bool {
	if validator == "" || validator == etag {
		return true
	}
	date, err := http.ParseTime(validator)
	return err == nil && !lastModified.IsZero() && date.Equal(lastModified)
}

func writeDownloadArchive(c *echo.Context, a *downloadArchive, name string, budget *downloadBudget, progress *downloadProgress) error {
	// A dedicated session is pinned to one immutable ZIP representation.
	// Only such a resource can use its HTTP-second timestamp as a strong validator.
	var lastModified time.Time
	if c.Param("session_id") != "" && progress.representationOK && a.info != nil {
		mtime := a.info.ModTime().UTC().Truncate(time.Second)
		if !mtime.After(time.Now()) {
			lastModified = mtime
		}
	}
	start, length, status := int64(0), a.size, http.StatusOK
	if budget != nil {
		if a.size != budget.session.Size() {
			return echo.NewHTTPError(http.StatusPreconditionFailed, "Archive changed")
		}
		var err error
		start, length, err = parseSingleByteRange(c.Request().Header.Get("Range"), a.size)
		if err != nil {
			c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes */%d", a.size))
			return c.NoContent(http.StatusRequestedRangeNotSatisfiable)
		}
		if matchesDownloadIfRange(c.Request().Header.Get("If-Range"), a.etag, lastModified) {
			status = http.StatusPartialContent
		} else {
			start, length = 0, a.size
		}
		if length > budget.reserved {
			if httpErr := ReserveDownloadBytes(budget.session, length-budget.reserved); httpErr != nil {
				return httpErr
			}
			budget.reserved = length
		}
	}
	if err := progress.session.MarkDownloadStreaming(); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Download is unavailable")
	}
	h := c.Response().Header()
	if status == http.StatusPartialContent {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, a.size))
	}
	h.Set(echo.HeaderContentType, "application/zip")
	h.Set(echo.HeaderContentDisposition, mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	h.Set("Accept-Ranges", "bytes")
	h.Set("Cache-Control", "private, no-store, no-transform")
	h.Set("ETag", a.etag)
	if !lastModified.IsZero() {
		h.Set("Last-Modified", lastModified.Format(http.TimeFormat))
	}
	h.Set(echo.HeaderContentLength, strconv.FormatInt(length, 10))
	progress.started = true
	c.Response().WriteHeader(status)
	writer := &responseWriteTracker{ResponseWriter: c.Response()}
	written, err := io.CopyN(writer, io.NewSectionReader(a.reader, start, length), length)
	// CopyN may return nil after n bytes even if the final Write returned an
	// error together with those bytes; that is not a successful response.
	if err == nil && writer.writeErr != nil {
		err = writer.writeErr
	}
	if budget != nil {
		budget.written = written
	}
	integrityErr := a.verifyUnchanged()
	progress.start, progress.written = start, written
	progress.responseOK = progress.representationOK && err == nil && integrityErr == nil && c.Request().Context().Err() == nil
	progress.integrityOK = progress.representationOK && integrityErr == nil &&
		(progress.responseOK || (writer.writeErr != nil && written < length))
	if err != nil || integrityErr != nil {
		// A committed response must be interrupted when a chunk fails its
		// authentication or the transport cannot finish the bytes promised.
		panic(http.ErrAbortHandler)
	}
	return nil
}

// DownloadSessionFile serves the session's initial GET and its bounded continuations.
// ReadFile also delegates pre-upgrade Range requests here for the lifetime of their cookie.
func DownloadSessionFile(c *echo.Context) error {
	c.Response().Header().Set("Cache-Control", "private, no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	token := c.Param("file_key")
	name, err := archiveNameFromToken(token)
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
	defer guard.Close()
	value := c.Request().Header.Get("Range")
	dedicated := c.Param("session_id") != ""
	initial := dedicated && value == ""
	if !initial {
		// Reject unsupported forms before consuming one of the bounded retries.
		if _, _, err := parseSingleByteRange(value, int64(^uint64(0)>>1)); err != nil {
			return c.NoContent(http.StatusRequestedRangeNotSatisfiable)
		}
	}
	cookie, err := chooseDownloadCookie(c, token)
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}
	// Authenticate without incrementing the session request count. A busy KDF
	// or a rate-limit denial must not consume a continuation attempt or bytes.
	preview := &File{FileKey: token}
	if previewErr := PreviewDownloadSession(preview, cookie.Value); previewErr != nil {
		return c.NoContent(http.StatusNotFound)
	}
	var releaseKDF func()
	if !ValidFileArchiveFormat(preview.ArchiveFormat, preview.PasswordProvided) {
		return c.NoContent(http.StatusNotFound)
	}
	if preview.ArchiveFormat == ArchiveFormatAgeUserPassword {
		reserved, release, reserveErr := ReserveArchiveKDF(c.Request().Context())
		if reserveErr != nil {
			if errors.Is(reserveErr, ErrArchiveKDFBusy) {
				c.Response().Header().Set("Retry-After", "1")
			}
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Archive password processing is busy")
		}
		releaseKDF = release
		defer releaseKDF()
		c.SetRequest(c.Request().WithContext(reserved))
		shareID, _, _ := ParseToken(token) // archiveNameFromToken already validated it.
		if err := admitArchiveKDF(c, shareID, true); err != nil {
			return err
		}
	}
	f := &File{FileKey: token}
	begin := ResumeTrackedFileDownload
	switch {
	case initial:
		begin = StartTrackedFileDownload
	case dedicated:
		begin = ResumeStartedFileDownload
	}
	secret, session, httpErr := begin(f, cookie.Value)
	if httpErr != nil {
		return c.NoContent(http.StatusNotFound)
	}
	progress := &downloadProgress{session: session}
	defer progress.finish()
	// Keep a long response eligible for resumption until the request ends.
	// Stop renewing before its finalizer records the idle deadline in Redis.
	stopLease := KeepDownloadSessionAlive(c.Request().Context(), session)
	defer stopLease()
	if !bytes.Equal(preview.Token, f.Token) || preview.ArchiveFormat != f.ArchiveFormat || preview.PasswordProvided != f.PasswordProvided {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Download is unavailable")
	}
	var budget *downloadBudget
	if !initial {
		_, length, err := parseSingleByteRange(value, session.Size())
		if err != nil {
			c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes */%d", session.Size()))
			return c.NoContent(http.StatusRequestedRangeNotSatisfiable)
		}
		// Charge ranges before key derivation. The one-time initial GET has
		// its own atomic reservation and leaves this byte budget available.
		if httpErr := ReserveDownloadBytes(session, length); httpErr != nil {
			return httpErr
		}
		budget = &downloadBudget{session: session, reserved: length}
		defer budget.finish()
	}
	archive, err := openDownloadArchive(c, f, secret, name)
	if releaseKDF != nil {
		releaseKDF()
	}
	if err != nil {
		if errors.Is(err, ErrArchiveKDFBusy) {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Archive password processing is busy")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
	defer archive.file.Close()
	progress.representationOK, err = VerifyDownloadRepresentation(session, archive.etag)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
	}
	if dedicated && (!progress.representationOK || archive.size != session.Size()) {
		return echo.NewHTTPError(http.StatusPreconditionFailed, "Archive changed")
	}
	if initial {
		AuditStarted(c, "file.download_started", "File download started")
	}
	archive.etag = sessionETag(archive.etag, cookie.Value)
	return writeDownloadArchive(c, archive, name, budget, progress)
}
