package controllers

import (
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
	"github.com/mholt/archives"
	log "github.com/sirupsen/logrus"
)

func IndexFile(context echo.Context) error {
	delete(DataContext, "errors")
	csrfToken := context.Get("csrf")
	DataContext["maxFileSize"] = MaxFileSize
	DataContext["maxFileSizeText"] = GetMaxFileSizeText()
	DataContext["csrfToken"] = csrfToken

	return context.Render(http.StatusOK, "index_file.html", DataContext)
}

func Error400File(context echo.Context) error {
	delete(DataContext, "errors")
	return context.Render(http.StatusBadRequest, "400.html", DataContext)
}

func Error403File(context echo.Context) error {
	delete(DataContext, "errors")
	return context.Render(http.StatusForbidden, "403.html", DataContext)
}

func Error404File(context echo.Context) error {
	delete(DataContext, "errors")
	return context.Render(http.StatusNotFound, "404.html", DataContext)
}

func Error413File(context echo.Context) error {
	delete(DataContext, "errors")
	return context.Render(http.StatusRequestEntityTooLarge, "413.html", DataContext)
}

func Error500File(context echo.Context) error {
	delete(DataContext, "errors")
	return context.Render(http.StatusInternalServerError, "500.html", DataContext)
}

func ReadFile(context echo.Context) error {
	delete(DataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	DataContext["csrfToken"] = csrfToken

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
		return context.Render(http.StatusForbidden, "403.html", DataContext)
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

	DataContext["f"] = f
	DataContext["ttl"] = GetTTLText(f.TTL)
	DataContext["dlViews"] = GetDownloadsText(f.Views)
	DataContext["deletableText"] = deletableText
	DataContext["deletableURL"] = deletableURL

	if f.PasswordProvided {
		DataContext["passwordNeeded"] = true
	} else {
		DataContext["passwordNeeded"] = false
	}

	return context.Render(http.StatusOK, "file.html", DataContext)
}

func DownloadFile(context echo.Context) error {
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	DataContext["csrfToken"] = csrfToken
	
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
		return context.Render(http.StatusNotFound, "404.html", DataContext)
	}

	if f.PasswordProvided {
		password := context.FormValue("password")
		if password != f.Password {
			passwordOk = false
		}
	}

	if !passwordOk {
		// Security: This will cause a view counted if the user try to download the file with a wrong password.
		DataContext["errors"] = "Forbidden. Wrong password provided"
		return context.Render(http.StatusUnauthorized, "file.html", DataContext)
	}
	
	fileName := strings.Split(f.FileKey, TOKEN_SEPARATOR)[0]

 	// Security: Ensure that the fileName does not contain path traversal sequences.
 	safeFileName := filepath.Base(fileName)

 	filePathName := filepath.Join(FILEFOLDER, safeFileName+".zip")
 	return context.Attachment(filePathName, safeFileName+".zip")
}

func AddFile(context echo.Context) error {
	delete(DataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	DataContext["csrfToken"] = csrfToken
	
	var err error
	f := new(File)
	f.Password = context.FormValue("password")

	f.TTL, err = strconv.Atoi(context.FormValue("ttl"))
	if err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	f.Views, err = strconv.Atoi(context.FormValue("ttlViews"))
	if err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	f.Deletable = false
	if context.FormValue("deletable") == "on" {
		f.Deletable = true
	}

	if err := context.Validate(f); err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	if f.TTL > 30 {
		errorMessage := "TTL is too high"
		escapederrorMessage := strings.ReplaceAll(errorMessage, "\n", "")
		escapederrorMessage = strings.ReplaceAll(escapederrorMessage, "\r", "")
		log.Error(escapederrorMessage)
		DataContext["errors"] = errorMessage
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}
	f.TTL = GetTtlSeconds(f.TTL)

	var provided = false
	var passwordLink string

	if f.Password == "" {
		f.Password, err = GenerateRandomString(50)
		if err != nil {
			log.Error("%+v\n", err)
			DataContext["errors"] = err.Error()
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}

	} else {
		provided = true

		// Security: Don't give the possibility to delete the password, it will be auto deleted if the file is deleted.
		token, err := SetPassword(f.Password, f.TTL, f.Views, false)
		if err != nil {
			log.Error("%+v\n", err)
			DataContext["errors"] = err.Message
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}
		f.PasswordProvidedKey = strings.Split(token, TOKEN_SEPARATOR)[0]
		passwordLink = GetBaseUrl(context) + "/" + token
	}

	token, err := SetFile(f.Password, f.TTL, f.Views, f.Deletable, provided, f.PasswordProvidedKey)

	form, err := context.MultipartForm()
	if err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}
	files := form.File["files"]

	if len(files) == 0 {
		errorMessage := "No file was selected. Please provide a file to generate a link"
		escapederrorMessage := strings.ReplaceAll(errorMessage, "\n", "")
		escapederrorMessage = strings.ReplaceAll(escapederrorMessage, "\r", "")
		log.Error(escapederrorMessage)
		DataContext["errors"] = errorMessage
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	var fileList []string
	var totalUploadedFileSize int64
	
	// Proceed with file operations for each file.
	folderName := strings.Split(token, TOKEN_SEPARATOR)[0]
	folderPathName := FILEFOLDER + "/" + folderName + "/"
	for _, file := range files {
		
		// Security: Sanitize the file name in helper function to prevent path traversal attacks.
		cleanFileName := sanitizeFileName(file.Filename)

		// Security: Check if the sanitized file name is empty, which indicates a sanitization issue and prevent file creation in /data folder.
		if cleanFileName == "" {
    		errorMessage := "File name contains prohibited characters or is not valid"
		escapederrorMessage := strings.ReplaceAll(errorMessage, "\n", "")
		escapederrorMessage = strings.ReplaceAll(escapederrorMessage, "\r", "")
		log.Error(escapederrorMessage)
		DataContext["errors"] = errorMessage
    		return context.Render(http.StatusUnauthorized, "index_file.html", DataContext)
		}

		// If all file names are sanitized successfully, create the folder.
		err = os.Mkdir(folderPathName, os.ModePerm)
		if err != nil {
		log.Error("AddFile Error while mkdir : %+v\n", err)
		DataContext["errors"] = "There was a problem during the file processing, please try again"
		return context.Render(http.StatusOK, "index_file.html", DataContext)
		}

		/*File upload start*/
		
		// Open and start file integration.
		src, err := file.Open()
		if err != nil {
			log.Error("Error while opening file : %+v\n", err)
			DataContext["errors"] = err.Error()
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}
		defer src.Close()
		
		if file.Size > MaxFileSize {
			errorMessage := fmt.Sprintf("File %s is too big %d (%d mb max)", file.Filename, file.Size*1024*1024, MaxFileSize)
			escapederrorMessage := strings.ReplaceAll(errorMessage, "\n", "")
			escapederrorMessage = strings.ReplaceAll(escapederrorMessage, "\r", "")
			log.Error(escapederrorMessage)
			DataContext["errors"] = errorMessage
			err := os.RemoveAll(folderPathName)
			if err != nil {
				log.Error("Failed to remove directory %s, %+v\n", folderPathName, err)
			}
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}
		totalUploadedFileSize += file.Size
		
		// Security: Secure the file path to prevent path traversal attacks
		dstFile := filepath.Base(cleanFileName)
		
		// Destination
		dst, err := os.Create(folderPathName + dstFile)
		if err != nil {
			log.Error("Error while creating file : %+v\n", err)
			DataContext["errors"] = err.Error()
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}
		defer dst.Close()

		// Copy
		if _, err = io.Copy(dst, src); err != nil {
			log.Error("Error while copying file : %+v\n", err)
			DataContext["errors"] = err.Error()
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}

		fileList = append(fileList, folderPathName+dstFile)
	}

	if totalUploadedFileSize > MaxFileSize {
		errorMessage := fmt.Sprintf("Total upload size (%d) is greater than %d mb (max authorized)", totalUploadedFileSize, MaxFileSize)
		escapederrorMessage := strings.ReplaceAll(errorMessage, "\n", "")
		escapederrorMessage = strings.ReplaceAll(escapederrorMessage, "\r", "")
		log.Error(escapederrorMessage)
		DataContext["errors"] = errorMessage
		err := os.RemoveAll(folderPathName)
		if err != nil {
			log.Error("Failed to remove directory %s, %+v\n", folderPathName, err)
		}
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	// Archive the files using https://github.com/mholt/archives
	outFile, err := os.Create(FILEFOLDER + "/" + folderName + ".zip")
	if err != nil {
		log.Error("Error while creating ZIP archive: %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}
	defer outFile.Close()

	// Map files to their archive paths
	fileMappings := map[string]string{}
	for _, file := range fileList {
		fileMappings[file] = filepath.Base(file)
	}

	// Generate FileInfo structs for the archive
	files, err := archives.FilesFromDisk(archives.DiskOptions{}, map[string]string{}, fileMappings)
	if err != nil {
		log.Error("Error while preparing files for archiving: %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	// Configure the ZIP format
	zipFormat := archives.Zip{}

	// Create the archive
	err = zipFormat.Archive(context.Background(), outFile, files)
	if err != nil {
		log.Error("Error while archiving: %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	// Remove the folder after successful archiving
	err = os.RemoveAll(folderPathName)
	if err != nil {
		log.Error("Error while removing folder: %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	// Remove the folder after successful archiving
	err = os.RemoveAll(folderPathName)
	if err != nil {
		log.Error("Error while removing folder : %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	// Remove the temporary folder created
	err = os.RemoveAll(folderPathName)
	if err != nil {
		log.Error("Error while removing folder: %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	return context.Render(http.StatusOK, "confirm_file.html", DataContext)
	
	/*File upload end*/

	var (
		deletableText,
		deletableURL string
	)

	baseUrl := GetBaseUrl(context) + "/file/"
	if !f.Deletable {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = baseUrl + "remove/" + token
	}
	link := baseUrl + token
	f.FileKey = ""
	f.Link = link
	f.Password = ""

	DataContext["f"] = f
	DataContext["ttl"] = GetTTLText(f.TTL)
	DataContext["ttlViews"] = GetViewsText(f.Views)
	DataContext["dlViews"] = GetDownloadsText(f.Views)
	DataContext["deletableText"] = deletableText
	DataContext["deletableURL"] = deletableURL
	DataContext["passwordLink"] = passwordLink

	return context.Render(http.StatusOK, "confirm_file.html", DataContext)
}

func DeleteFile(context echo.Context) error {
	delete(DataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	DataContext["csrfToken"] = csrfToken
	
	f := new(File)
	f.FileKey = context.Param("file_key")
	if f.FileKey == "" || strings.Contains(f.FileKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemoveFile(f)
	var status int
	if err != nil {
		status = err.Code
		return context.Render(status, "403.html", DataContext)
	} else {
		DataContext["type"] = "File"
		return context.Render(http.StatusOK, "removed.html", DataContext)
	}
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

