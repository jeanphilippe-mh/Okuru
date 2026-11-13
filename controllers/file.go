package controllers

import (
	"archive/zip"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

func IndexFile(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	csrfToken := context.Get("csrf")
	dataContext["maxFileSize"] = MaxFileSize
	dataContext["maxFileSizeText"] = GetMaxFileSizeText()
	dataContext["csrfToken"] = csrfToken

	return context.Render(http.StatusOK, "index_file.html", dataContext)
}

func Error400File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusBadRequest, "400.html", dataContext)
}

func Error401File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusUnauthorized, "401.html", dataContext)
}

func Error403File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusForbidden, "403.html", dataContext)
}

func Error404File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusNotFound, "404.html", dataContext)
}

func Error413File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusRequestEntityTooLarge, "413.html", dataContext)
}

func Error500File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusInternalServerError, "500.html", dataContext)
}

func Error501File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusNotImplemented, "501.html", dataContext)
}

func Error502File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusBadGateway, "502.html", dataContext)
}

func Error503File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusServiceUnavailable, "503.html", dataContext)
}

func Error504File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusGatewayTimeout, "504.html", dataContext)
}

func Error505File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusHTTPVersionNotSupported, "505.html", dataContext)
}

func Error506File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusVariantAlsoNegotiates, "506.html", dataContext)
}

func Error507File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusInsufficientStorage, "507.html", dataContext)
}

func Error508File(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusLoopDetected, "508.html", dataContext)
}

func ReadFile(context echo.Context) error {
	if context.Request().Header.Get("Range") != "" {
		return resumeDownload(context)
	}
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	f := new(File)
	f.FileKey = context.Param("file_key")

	if f.FileKey == "" {
		return context.NoContent(http.StatusNotFound)
	}
	if strings.Contains(f.FileKey, "favicon.ico") {
		return nil
	}
	if strings.Contains(f.FileKey, "robots.txt") {
		return nil
	}
	if strings.Contains(f.FileKey, "sitemap.xml") {
		return nil
	}

	err := GetFile(f)
	if err != nil {
		log.Error("File metadata retrieval failed")
		return context.Render(http.StatusForbidden, "403.html", dataContext)
	}

	var (
		deletableText,
		deletableURL string
	)

	if !f.Deletable {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = GetBaseUrl(context) + "/file/remove/" + f.FileKey
	}

	dataContext["f"] = f
	dataContext["ttl"] = GetTTLText(f.TTL)
	dataContext["dlViews"] = GetDownloadsText(f.Views)
	dataContext["deletableText"] = deletableText
	dataContext["deletableURL"] = deletableURL

	if f.PasswordProvided {
		dataContext["passwordNeeded"] = true
	} else {
		dataContext["passwordNeeded"] = false
	}

	return context.Render(http.StatusOK, "file.html", dataContext)
}

// ArchiveNameFromToken reconstructs a filename from a canonical UUID rather than carrying user-supplied path components into the filesystem operation.
func archiveNameFromToken(token string) (string, error) {
	storageKey, decryptionKey, err := ParseToken(token)
	if err != nil || decryptionKey == "" {
		return "", fmt.Errorf("Invalid file token")
	}
	id, err := uuid.Parse(storageKey)
	if err != nil || id.String() != storageKey {
		return "", fmt.Errorf("Invalid file identifier")
	}
	return id.String() + ".zip", nil
}

func DownloadFile(context echo.Context) error {
	dataContext := NewDataContext()
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	f := new(File)
	f.FileKey = context.Param("file_key")
	archiveName, err := archiveNameFromToken(f.FileKey)
	if err != nil {
		return context.NoContent(http.StatusNotFound)
	}
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	defer guard.Close()
	password := context.FormValue("password")
	if err := ValidateSecretLength(password); err != nil {
		return context.NoContent(http.StatusRequestEntityTooLarge)
	}
	if err := ValidateDownloadSessionTimeout(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	claim, retrieveErr := ClaimFileDownload(f)
	if claim != nil {
		defer func() {
			if err := ReleaseFileDownloadClaim(claim); err != nil {
				log.Error("Could not release download claim")
			}
		}()
	}
	if retrieveErr != nil {
		log.Error("File metadata retrieval failed")
		return context.Render(http.StatusNotFound, "404.html", dataContext)
	}

	wrongPassword := func() error {
		// A wrong password consumes a view, including when the archive itself
		// verifies the password instead of comparing stored metadata.
		f.Password = ""
		dataContext["f"] = f
		dataContext["passwordNeeded"] = true
		dataContext["ttl"] = GetTTLText(f.TTL)
		dataContext["dlViews"] = GetDownloadsText(f.Views)
		if f.Deletable {
			dataContext["deletableText"] = "deletable"
			dataContext["deletableURL"] = GetBaseUrl(context) + "/file/remove/" + f.FileKey
		} else {
			dataContext["deletableText"] = "not deletable"
		}
		dataContext["errors"] = "Forbidden. Wrong password provided"
		return context.Render(http.StatusUnauthorized, "file.html", dataContext)
	}
	if f.PasswordProvided && f.ArchiveFormat != ArchiveFormatAgeUserPassword &&
		subtle.ConstantTimeCompare([]byte(password), []byte(f.Password)) != 1 {
		return wrongPassword()
	}
	if f.PasswordProvided && f.ArchiveFormat == ArchiveFormatAgeUserPassword && password == "" {
		return wrongPassword()
	}

	secret := f.Password
	if f.ArchiveFormat == ArchiveFormatAgeUserPassword {
		secret = password
	} else if f.ArchiveFormat == "" {
		// Legacy ZIPs do not need their former password retained in the
		// continuation record: possession of the session proves the prior check.
		secret = "legacy-unencrypted"
	}
	archive, err := openDownloadArchive(context, f, secret, archiveName)
	if err != nil {
		if f.ArchiveFormat == ArchiveFormatAgeUserPassword && IsArchivePasswordError(err) {
			return wrongPassword()
		}
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	value, lifetime, session, err := CreateClaimedDownloadSession(f, secret, archive.size, claim, archive.etag)
	if err != nil {
		_ = archive.file.Close()
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	progress := &downloadProgress{session: session, representationOK: true}
	defer func() {
		_ = archive.file.Close()
		progress.finish()
	}()
	cookieName, err := downloadSessionCookie(f.FileKey, value)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	context.SetCookie(&http.Cookie{
		Name: cookieName, Value: value, Path: "/file/" + f.FileKey,
		MaxAge: lifetime, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	archive.etag = sessionETag(archive.etag, value)
	if f.ArchiveFormat == "" {
		// Preserve net/http's existing Range and conditional-request behavior
		// for original unencrypted ZIPs, including authenticated POST ranges.
		info, err := archive.file.Stat()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}
		h := context.Response().Header()
		h.Set(echo.HeaderContentDisposition, mime.FormatMediaType("attachment", map[string]string{"filename": archiveName}))
		h.Set("ETag", archive.etag)
		h.Set("Cache-Control", "private, no-store")
		writer := &responseWriteTracker{ResponseWriter: context.Response()}
		http.ServeContent(writer, context.Request(), archiveName, info.ModTime(), archive.file)
		unchanged := archive.verifyUnchanged() == nil
		recordLegacyResponse(progress, writer, archive.size, unchanged, context.Request().Context().Err() == nil)
		if !unchanged || writer.writeErr != nil {
			panic(http.ErrAbortHandler)
		}
		return nil
	}
	return writeDownloadArchive(context, archive, archiveName, nil, progress)
}

// getZipMethod decides which ZIP compression method to use based on environment variables.
// Supported values for OKURU_ZIP_COMPRESSION:
// After headers are committed, an authentication or transport error must abort
// the HTTP stream so a truncated body is not mistaken for a complete ZIP.
func streamDecryptedArchive(c echo.Context, plain io.Reader) error {
	if err := c.Stream(http.StatusOK, "application/zip", plain); err != nil {
		if c.Response().Committed {
			panic(http.ErrAbortHandler)
		}
		return err
	}
	return nil
}

// - "store"   -> zip.Store (no compression, fastest)
// - "deflate" -> zip.Deflate (standard compression)
// - "auto"    -> use deflate if file size < threshold, otherwise store
// Threshold is defined in OKURU_ZIP_AUTO_THRESHOLD_MB (default 100 MB) and default fallback is zip.Store.
func getZipMethodForSize(size int64) uint16 {
	mode := strings.ToLower(os.Getenv("OKURU_ZIP_COMPRESSION"))
	switch mode {
	case "store":
		return zip.Store
	case "deflate":
		return zip.Deflate
	case "auto":
		// Default threshold = 100 MB
		thresholdMB := 100
		if v := strings.TrimSpace(os.Getenv("OKURU_ZIP_AUTO_THRESHOLD_MB")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				thresholdMB = n
			}
		}
		thresholdBytes := int64(thresholdMB) * 1024 * 1024

		if size >= thresholdBytes {
			return zip.Store
		}
		return zip.Deflate
	default:
		// Fallback
		return zip.Store
	}
}

// maxUploadFiles bounds file descriptors and per-upload metadata.
const maxUploadFiles = 100

// validateUploadFiles runs before either Redis record is created.
func validateUploadFiles(files []*SecureMultipartFile) ([]string, error) {
	if len(files) == 0 {
		return nil, errors.New("No files selected")
	}
	if len(files) > maxUploadFiles {
		return nil, errors.New("Too many files")
	}
	names := make([]string, 0, len(files))
	seen := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		if file == nil || file.Size < 0 || MaxFileSize <= 0 || file.Size > MaxFileSize-total {
			return nil, errors.New("Upload exceeds the maximum size")
		}
		name := file.Filename
		key, valid := UploadFilenameKey(name)
		if !valid || seen[key] {
			return nil, errors.New("Invalid or duplicate file name")
		}
		seen[key] = true
		names = append(names, name)
		total += file.Size
	}
	return names, nil
}

// writeEncryptedUploadArchive never creates a plaintext ZIP or staging copy.
func writeEncryptedUploadArchive(ctx context.Context, path, password string, files []*SecureMultipartFile, names []string, format string) (resultErr error) {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	var encrypted io.WriteCloser
	switch format {
	case ArchiveFormatAge, ArchiveFormatAgeUserPassword:
		encrypted, err = EncryptArchive(ctx, out, password)
	case ArchiveFormatAgeX25519:
		encrypted, err = EncryptArchiveWithIdentity(ctx, out, password)
	default:
		return errors.New("Unsupported archive format")
	}
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, encrypted.Close())
		if resultErr == nil {
			resultErr = out.Sync()
		}
	}()
	zw := zip.NewWriter(encrypted)
	defer func() { resultErr = errors.Join(resultErr, zw.Close()) }()
	for i, file := range files {
		in, err := file.Open()
		if err != nil {
			return err
		}
		header := &zip.FileHeader{Name: names[i], Method: getZipMethodForSize(file.Size)}
		header.SetMode(0600)
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return errors.Join(err, in.Close())
		}
		n, copyErr := io.Copy(writer, io.LimitReader(in, file.Size+1))
		closeErr := in.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if n != file.Size {
			return errors.New("Multipart file size changed")
		}
	}
	return nil
}

// discardUnpublishedUpload removes only records created by this upload. If
// Redis is unavailable, their configured TTL remains the fallback.
func discardUnpublishedUpload(fileToken, passwordToken string) {
	var keys []interface{}
	if fileToken != "" {
		if id, _, err := ParseToken(fileToken); err == nil {
			keys = append(keys, REDIS_PREFIX+"file_"+id)
		}
	}
	if passwordToken != "" {
		if id, _, err := ParseToken(passwordToken); err == nil {
			keys = append(keys, REDIS_PREFIX+id)
		}
	}
	if len(keys) == 0 {
		return
	}
	pool := NewPool()
	c := pool.Get()
	defer c.Close()
	if _, err := c.Do("DEL", keys...); err != nil {
		log.Error("Failed to remove unpublished upload metadata")
	}
}

func AddFile(context echo.Context) error {
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}
	defer guard.Close()
	form := GetSecureMultipart(context.Request())
	if form == nil {
		form, err = ParseSecureMultipart(context.Request(), FILEFOLDER, MaxFileSize, maxUploadFiles)
		if err != nil {
			return context.NoContent(http.StatusBadRequest)
		}
		defer func() {
			if err := form.Close(); err != nil {
				log.Error("Failed to remove encrypted multipart staging")
			}
		}()
	}
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	dataContext["csrfToken"] = context.Get("csrf")
	dataContext["maxFileSize"] = MaxFileSize
	dataContext["maxFileSizeText"] = GetMaxFileSizeText()
	fail := func(status int, message string) error {
		dataContext["errors"] = displayError(message)
		return context.Render(status, "index_file.html", dataContext)
	}

	f := new(File)
	f.Password = context.FormValue("password")
	if err := ValidateSecretLength(f.Password); err != nil {
		return fail(http.StatusRequestEntityTooLarge, "Password exceeds the maximum size")
	}
	f.TTL, err = ParseWebNumber(context.FormValue("ttl"))
	if err != nil {
		log.Warn("Invalid duration field")
		return fail(http.StatusBadRequest, "Invalid duration")
	}
	f.Views, err = ParseWebNumber(context.FormValue("ttlViews"))
	if err != nil {
		log.Warn("Invalid attempt count field")
		return fail(http.StatusBadRequest, "Invalid attempt count")
	}
	if err := ValidateWebLimits(f.TTL, f.Views); err != nil {
		return fail(http.StatusBadRequest, err.Error())
	}
	f.Deletable = context.FormValue("deletable") == "on"
	if err := context.Validate(f); err != nil {
		log.Warn("Invalid upload metadata")
		return fail(http.StatusBadRequest, "Invalid upload metadata")
	}

	// Fields were parsed without plaintext disk spill before CSRF.
	files := form.Files
	names, err := validateUploadFiles(files)
	if err != nil {
		return fail(http.StatusBadRequest, err.Error())
	}

	if admissionErr := admitFileCreation(context); admissionErr != nil {
		if admissionErr.Code == http.StatusTooManyRequests {
			return fail(http.StatusTooManyRequests, "File creation limit reached")
		}
		return fail(http.StatusServiceUnavailable, "File creation is unavailable")
	}

	// The temporary directory is excluded from UUID.zip reconciliation.
	stage, err := CreateLockedStagingDir(FILEFOLDER, ".okuru-upload-")
	if err != nil {
		log.Error("Failed to prepare upload")
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	defer func() {
		if err := stage.Close(); err != nil {
			log.Error("Failed to remove upload temporary directory")
		}
	}()
	provided := f.Password != ""
	archiveFormat := ArchiveFormatAgeUserPassword
	if !provided {
		archiveFormat = ArchiveFormatAgeX25519
		f.Password, err = GenerateArchiveIdentity()
		if err != nil {
			return fail(http.StatusInternalServerError, "There was a problem during file processing")
		}
	}
	temporaryArchive := filepath.Join(stage.Path, "archive.tmp")
	if err := writeEncryptedUploadArchive(context.Request().Context(), temporaryArchive, f.Password, files, names, archiveFormat); err != nil {
		log.Error("Failed to create encrypted upload archive")
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	// Remove the encrypted upload staging before confirming success.
	if err := form.Close(); err != nil {
		log.Error("Failed to remove encrypted multipart staging")
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	f.TTL = GetTtlSeconds(f.TTL)
	var passwordToken, fileToken, finalArchive string
	published := false
	defer func() {
		if !published {
			if finalArchive != "" {
				if err := os.Remove(finalArchive); err != nil && !os.IsNotExist(err) {
					log.Error("Failed to remove unpublished archive")
				}
			}
			discardUnpublishedUpload(fileToken, passwordToken)
		}
	}()
	if provided {
		var httpErr *echo.HTTPError
		passwordToken, httpErr = SetPassword(f.Password, f.TTL, f.Views, false)
		if httpErr != nil {
			return fail(http.StatusInternalServerError, "There was a problem during file processing")
		}
		f.PasswordProvidedKey, _, err = ParseToken(passwordToken)
		if err != nil {
			return fail(http.StatusInternalServerError, "There was a problem during file processing")
		}
	}
	var httpErr *echo.HTTPError
	fileToken, httpErr = SetFile(f.Password, f.TTL, f.Views, f.Deletable, provided, f.PasswordProvidedKey, archiveFormat)
	if httpErr != nil {
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	archiveName, err := archiveNameFromToken(fileToken)
	if err != nil {
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	candidateArchive := filepath.Join(FILEFOLDER, archiveName)
	// A hard link atomically publishes on the same filesystem without ever
	// overwriting an existing archive. Metadata already exists for cleanup.
	if err := os.Link(temporaryArchive, candidateArchive); err != nil {
		log.Error("Failed to publish upload archive")
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	finalArchive = candidateArchive
	// Remove the temporary encrypted archive after publication.
	if err := stage.Close(); err != nil {
		log.Error("Failed to remove upload temporary directory")
		return fail(http.StatusInternalServerError, "There was a problem during file processing")
	}
	baseURL := GetBaseUrl(context) + "/file/"
	deletableText, deletableURL := "not deletable", ""
	if f.Deletable {
		deletableText = "deletable"
		deletableURL = baseURL + "remove/" + fileToken
	}
	f.FileKey = ""
	f.Link = baseURL + fileToken
	f.Password = ""
	dataContext["f"] = f
	dataContext["ttl"] = GetTTLText(f.TTL)
	dataContext["ttlViews"] = GetViewsText(f.Views)
	dataContext["dlViews"] = GetDownloadsText(f.Views)
	dataContext["deletableText"] = deletableText
	dataContext["deletableURL"] = deletableURL
	if provided {
		dataContext["passwordLink"] = GetBaseUrl(context) + "/" + passwordToken
	} else {
		dataContext["passwordLink"] = ""
	}
	if err := context.Render(http.StatusOK, "confirm_file.html", dataContext); err != nil {
		return err
	}
	published = true
	return nil
}
func DeleteFile(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	f := new(File)
	f.FileKey = context.Param("file_key")
	if f.FileKey == "" || strings.Contains(f.FileKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemoveFile(f)
	var status int
	if err != nil {
		status = err.Code
		return context.Render(status, "403.html", dataContext)
	} else {
		dataContext["type"] = "File"
		return context.Render(http.StatusOK, "removed.html", dataContext)
	}
}
