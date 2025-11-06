package controllers

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

func IndexFile(context echo.Context) error {
	viewData := NewViewData()
	// Retrieve the CSRF token provided by the middleware.
	if csrfToken := context.Get("csrf"); csrfToken != nil {
		viewData["csrfToken"] = csrfToken
	}
	viewData["maxFileSize"] = MaxFileSize
	viewData["maxFileSizeText"] = GetMaxFileSizeText()

	return context.Render(http.StatusOK, "index_file.html", viewData)
}

func Error400File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusBadRequest, "400.html", viewData)
}

func Error401File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusUnauthorized, "401.html", viewData)
}

func Error403File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusForbidden, "403.html", viewData)
}

func Error404File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusNotFound, "404.html", viewData)
}

func Error413File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusRequestEntityTooLarge, "413.html", viewData)
}

func Error500File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusInternalServerError, "500.html", viewData)
}

func Error501File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusNotImplemented, "501.html", viewData)
}

func Error502File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusBadGateway, "502.html", viewData)
}

func Error503File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusServiceUnavailable, "503.html", viewData)
}

func Error504File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusGatewayTimeout, "504.html", viewData)
}

func Error505File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusHTTPVersionNotSupported, "505.html", viewData)
}

func Error506File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusVariantAlsoNegotiates, "506.html", viewData)
}

func Error507File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusInsufficientStorage, "507.html", viewData)
}

func Error508File(context echo.Context) error {
	viewData := NewViewData()
	return context.Render(http.StatusLoopDetected, "508.html", viewData)
}

func ReadFile(context echo.Context) error {
	viewData := NewViewData()
	// Retrieve the CSRF token provided by the middleware.
	if csrfToken := context.Get("csrf"); csrfToken != nil {
		viewData["csrfToken"] = csrfToken
	}

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
		log.Error("Error while retrieving file : %s\n")
		return context.Render(http.StatusForbidden, "403.html", viewData)
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
		println("deletableURL : ", deletableURL)
	}

	viewData["f"] = f
	viewData["ttl"] = GetTTLText(f.TTL)
	viewData["dlViews"] = GetDownloadsText(f.Views)
	viewData["deletableText"] = deletableText
	viewData["deletableURL"] = deletableURL

	viewData["passwordNeeded"] = f.PasswordProvided

	return context.Render(http.StatusOK, "file.html", viewData)
}

func DownloadFile(context echo.Context) error {
	viewData := NewViewData()
	// Retrieve the CSRF token provided by the middleware.
	if csrfToken := context.Get("csrf"); csrfToken != nil {
		viewData["csrfToken"] = csrfToken
	}

	var passwordOk = true
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

	err := RetrieveFilePassword(f)
	if err != nil {
		log.Error("%+v\n", err)
		return context.Render(http.StatusNotFound, "404.html", viewData)
	}

	if f.PasswordProvided {
		password := context.FormValue("password")
		if password != f.Password {
			passwordOk = false
		}
	}

	if !passwordOk {
		// Security: This will cause a view counted if the user try to download the file with a wrong password.
		viewData["errors"] = "Forbidden. Wrong password provided"
		return context.Render(http.StatusUnauthorized, "file.html", viewData)
	}

	fileName := strings.Split(f.FileKey, TOKEN_SEPARATOR)[0]

	// Security: Ensure that the fileName does not contain path traversal sequences.
	safeFileName := filepath.Base(fileName)

	filePathName := filepath.Join(FILEFOLDER, safeFileName+".zip")
	return context.Attachment(filePathName, safeFileName+".zip")
}

// getZipMethod decides which ZIP compression method to use based on environment variables.
// Supported values for OKURU_ZIP_COMPRESSION:
// - "store"   -> zip.Store (no compression, fastest)
// - "deflate" -> zip.Deflate (standard compression)
// - "auto"    -> use deflate if file size < threshold, otherwise store
// Threshold is defined in OKURU_ZIP_AUTO_THRESHOLD_MB (default 100 MB) and default fallback is zip.Store.
func getZipMethod(filePath string) uint16 {
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

		info, err := os.Stat(filePath)
		if err != nil {
			// If file stat fails, fallback to safe/fast mode
			return zip.Store
		}
		if info.Size() >= thresholdBytes {
			return zip.Store
		}
		return zip.Deflate
	default:
		// Fallback
		return zip.Store
	}
}

func AddFile(context echo.Context) error {
	viewData := NewViewData()
	// Retrieve the CSRF token provided by the middleware.
	if csrfToken := context.Get("csrf"); csrfToken != nil {
		viewData["csrfToken"] = csrfToken
	}

	var err error
	f := new(File)
	f.Password = context.FormValue("password")

	if f.TTL, err = strconv.Atoi(context.FormValue("ttl")); err != nil {
		log.Error("%+v\n", err)
		viewData["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	if f.Views, err = strconv.Atoi(context.FormValue("ttlViews")); err != nil {
		log.Error("%+v\n", err)
		viewData["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	f.Deletable = context.FormValue("deletable") == "on"

	if validationErr := context.Validate(f); validationErr != nil {
		log.Error("%+v\n", validationErr)
		viewData["errors"] = validationErr.Error()
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	if f.TTL > 30 {
		errorMessage := "TTL is too high"
		escapedError := strings.ReplaceAll(strings.ReplaceAll(errorMessage, "\n", ""), "\r", "")
		log.Error(escapedError)
		viewData["errors"] = errorMessage
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}
	f.TTL = GetTtlSeconds(f.TTL)

	provided := false
	var passwordLink string

	if f.Password == "" {
		f.Password, err = GenerateRandomString(50)
		if err != nil {
			log.Error("%+v\n", err)
			viewData["errors"] = err.Error()
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}
	} else {
		provided = true

		// Security: Don't give the possibility to delete the password, it will be auto deleted if the file is deleted.
		token, httpErr := SetPassword(f.Password, f.TTL, f.Views, false)
		if httpErr != nil {
			log.Error("%+v\n", httpErr)
			viewData["errors"] = fmt.Sprint(httpErr.Message)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}
		f.PasswordProvidedKey = strings.Split(token, TOKEN_SEPARATOR)[0]
		passwordLink = GetBaseUrl(context) + "/" + token
	}

	token, httpErr := SetFile(f.Password, f.TTL, f.Views, f.Deletable, provided, f.PasswordProvidedKey)
	if httpErr != nil {
		log.Error("%+v\n", httpErr)
		viewData["errors"] = "There was a problem during the file processing, please try again"
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	form, err := context.MultipartForm()
	if err != nil {
		log.Error("%+v\n", err)
		viewData["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}
	files := form.File["files"]

	if len(files) == 0 {
		errorMessage := "No file was selected. Please provide a file to generate a link"
		escapedError := strings.ReplaceAll(strings.ReplaceAll(errorMessage, "\n", ""), "\r", "")
		log.Error(escapedError)
		viewData["errors"] = errorMessage
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	var fileList []string
	var totalUploadedFileSize int64

	// Proceed with file operations for each file.
	folderName := strings.Split(token, TOKEN_SEPARATOR)[0]
	folderPathName := filepath.Join(FILEFOLDER, folderName)
	if err := os.MkdirAll(folderPathName, os.ModePerm); err != nil {
		log.Error("AddFile Error while creating folder : %+v\n", err)
		viewData["errors"] = "There was a problem during the file processing, please try again"
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	/*File upload start*/

	for _, file := range files {
		// Security: Sanitize the file name in helper function to prevent path traversal attacks.
		cleanFileName := sanitizeFileName(file.Filename)
		if cleanFileName == "" {
			// Security: Check if the sanitized file name is empty, which indicates a sanitization issue and prevent file creation in /data folder.
			errorMessage := "File name contains prohibited characters or is not valid"
			escapedError := strings.ReplaceAll(strings.ReplaceAll(errorMessage, "\n", ""), "\r", "")
			log.Error(escapedError)
			viewData["errors"] = errorMessage
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusUnauthorized, "index_file.html", viewData)
		}

		// Open and start file integration.
		src, err := file.Open()
		if err != nil {
			log.Error("Error while opening file : %+v\n", err)
			viewData["errors"] = err.Error()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}

		if file.Size > MaxFileSize {
			errorMessage := fmt.Sprintf("File %s is too big %d (%d mb max)", file.Filename, file.Size*1024*1024, MaxFileSize)
			escapedError := strings.ReplaceAll(strings.ReplaceAll(errorMessage, "\n", ""), "\r", "")
			log.Error(escapedError)
			viewData["errors"] = errorMessage
			src.Close()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}
		totalUploadedFileSize += file.Size

		// Security: Secure the file path to prevent path traversal attacks.
		dstPath := filepath.Join(folderPathName, filepath.Base(cleanFileName))
		// Destination
		dst, err := os.Create(dstPath)
		if err != nil {
			log.Error("Error while creating file : %+v\n", err)
			viewData["errors"] = err.Error()
			src.Close()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}

		// Copy
		if _, err = io.Copy(dst, src); err != nil {
			log.Error("Error while copying file : %+v\n", err)
			viewData["errors"] = err.Error()
			dst.Close()
			src.Close()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}

		dst.Close()
		src.Close()
		fileList = append(fileList, dstPath)
	}

	/*File upload end*/

	if totalUploadedFileSize > MaxFileSize {
		errorMessage := fmt.Sprintf("Total upload size (%d) is greater than %d mb (max authorized)", totalUploadedFileSize, MaxFileSize)
		escapedError := strings.ReplaceAll(strings.ReplaceAll(errorMessage, "\n", ""), "\r", "")
		log.Error(escapedError)
		viewData["errors"] = errorMessage
		os.RemoveAll(folderPathName)
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	zipPath := filepath.Join(FILEFOLDER, folderName+".zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		log.Error("Error while creating zip file : %+v\n", err)
		viewData["errors"] = err.Error()
		os.RemoveAll(folderPathName)
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)
	defer zw.Close()

	cleanupZip := true
	defer func() {
		if cleanupZip {
			if removeErr := os.Remove(zipPath); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Error("Failed to remove incomplete zip file %s : %+v\n", zipPath, removeErr)
			}
		}
	}()

	for _, filePath := range fileList {
		fileToZip, err := os.Open(filePath)
		if err != nil {
			log.Error("Error while opening file for zipping : %+v\n", err)
			viewData["errors"] = err.Error()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}

		info, err := fileToZip.Stat()
		if err != nil {
			fileToZip.Close()
			log.Error("Error while stating file for zipping : %+v\n", err)
			viewData["errors"] = err.Error()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			fileToZip.Close()
			log.Error("Error creating zip header : %+v\n", err)
			viewData["errors"] = err.Error()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}
		header.Name = filepath.Base(filePath)
		header.Method = getZipMethod(filePath)

		writer, err := zw.CreateHeader(header)
		if err != nil {
			fileToZip.Close()
			log.Error("Error adding file to zip : %+v\n", err)
			viewData["errors"] = err.Error()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}

		if _, err := io.Copy(writer, fileToZip); err != nil {
			fileToZip.Close()
			log.Error("Error copying file to zip : %+v\n", err)
			viewData["errors"] = err.Error()
			os.RemoveAll(folderPathName)
			return context.Render(http.StatusOK, "index_file.html", viewData)
		}
		fileToZip.Close()
	}

	if err = os.RemoveAll(folderPathName); err != nil {
		log.Error("Error while removing folder : %+v\n", err)
		viewData["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", viewData)
	}

	var (
		deletableText,
		deletableURL string
	)

	baseURL := GetBaseUrl(context) + "/file/"
	if !f.Deletable {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = baseURL + "remove/" + token
	}
	link := baseURL + token
	f.FileKey = ""
	f.Link = link
	f.Password = ""

	viewData["f"] = f
	viewData["ttl"] = GetTTLText(f.TTL)
	viewData["ttlViews"] = GetViewsText(f.Views)
	viewData["dlViews"] = GetDownloadsText(f.Views)
	viewData["deletableText"] = deletableText
	viewData["deletableURL"] = deletableURL
	viewData["passwordLink"] = passwordLink

	cleanupZip = false
	return context.Render(http.StatusOK, "confirm_file.html", viewData)
}
func DeleteFile(context echo.Context) error {
	viewData := NewViewData()
	// Retrieve the CSRF token provided by the middleware.
	if csrfToken := context.Get("csrf"); csrfToken != nil {
		viewData["csrfToken"] = csrfToken
	}

	f := new(File)
	f.FileKey = context.Param("file_key")
	if f.FileKey == "" || strings.Contains(f.FileKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemoveFile(f)
	var status int
	if err != nil {
		status = err.Code
		return context.Render(status, "403.html", viewData)
	}

	viewData["type"] = "File"
	return context.Render(http.StatusOK, "removed.html", viewData)
}

// Security: Helper function to call for sanitizing the file name.

func sanitizeFileName(Filename string) string {

	// Replace newline characters to prevent path traversal attacks.
	escapedFileName := strings.ReplaceAll(Filename, "\n", "")
	escapedFileName = strings.ReplaceAll(escapedFileName, "\r", "")
	log.Debug("CleanFolderName folderName : %s\n", escapedFileName)
	checkFileName := filepath.Base(escapedFileName)

	// Check for path traversal patterns.
	if strings.Contains(checkFileName, "..") || strings.ContainsAny(checkFileName, "/\\") {
		return ""
	}

	// Check for valid length to prevent potential buffer overflow attacks.
	if len(checkFileName) > 255 || len(checkFileName) < 1 {
		return ""
	}

	// Validate the file name to prevent path traversal attacks.
	disallowedPattern := `([^\p{L}\s\d\-_~,;:\[\]\(\).'])`
	re := regexp.MustCompile(disallowedPattern)
	if re.MatchString(checkFileName) {
		return ""
	}

	return checkFileName
}
