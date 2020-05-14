package controllers

import (
	"compress/flate"
	"fmt"
	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"github.com/mholt/archiver/v3"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func IndexFile(context echo.Context) error {
	delete(DataContext, "errors")
	DataContext["maxFileSize"] = MaxFileSize
	DataContext["maxFileSizeText"] = GetMaxFileSizeText()

	return context.Render(http.StatusOK, "index_file.html", DataContext)
}

func ReadFile(context echo.Context) error {
	delete(DataContext, "errors")
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

	err := GetFile(f)
	if err != nil {
		return context.Render(http.StatusNotFound, "404.html", DataContext)
	}

	var (
		deletableText,
		deletableURL string
	)

	if f.Deletable == false {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = GetBaseUrl(context) + "/file/remove/" + f.FileKey
		println("deletableURL : ", deletableURL)
	}

	DataContext["f"] = f
	DataContext["ttl"] = GetTTLText(f.TTL)
	DataContext["deletableText"] = deletableText
	DataContext["deletableURL"] = deletableURL

	if f.PasswordProvided == true {
		DataContext["passwordNeeded"] = true
	} else {
		DataContext["passwordNeeded"] = false
	}

	//Todo: change text "is up for" is ttl < 3600

	return context.Render(http.StatusOK, "file.html", DataContext)
}

func DownloadFile(context echo.Context) error {
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

	err := RetrieveFilePassword(f)
	if err != nil {
		log.Error("%+v\n", err)
		return context.NoContent(http.StatusNotFound)
	}

	if f.PasswordProvided == true {
		password := context.FormValue("password")
		if password != f.Password {
			passwordOk = false
		}
	}

	if passwordOk == false {
		// Todo: this will cause a views counted if the person comme again on the link instead of back button
		DataContext["errors"] = "Forbidden. No password provided"
		return context.Render(http.StatusUnauthorized, "file.html", DataContext)
	}

	fileName := strings.Split(f.FileKey, TOKEN_SEPARATOR)[0]
	filePathName := FILEFOLDER + "/" + fileName + ".zip"
	return context.Attachment(filePathName, fileName+".zip")
}

func AddFile(context echo.Context) error {
	delete(DataContext, "errors")
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
		log.Error(errorMessage)
		DataContext["errors"] = errorMessage
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}
	f.TTL = GetTtlSeconds(f.TTL)

	var provided = false
	var passwordLink string

	if f.Password == "" {
		f.Password = RandomSequence(50)
	} else {
		provided = true

		token, err := SetPassword(f.Password, f.TTL, f.Views, false) // Don't give the possibility to delete the password, it will be auto deleted if the file is deleted
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
		log.Error(errorMessage)
		DataContext["errors"] = errorMessage
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	folderName := strings.Split(token, TOKEN_SEPARATOR)[0]
	folderPathName := FILEFOLDER + "/" + folderName + "/"
	err = os.Mkdir(folderPathName, os.ModePerm)
	if err != nil {
		log.Error("AddFile Error while mkdir : %+v\n", err)
		DataContext["errors"] = "There was a problem during the process, please contact your administrator"
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	var fileList []string
	var totalUploadedFileSize int64
	for _, file := range files {
		// Source
		src, err := file.Open()
		if err != nil {
			log.Error("Error while opening file : %+v\n", err)
			DataContext["errors"] = err.Error()
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}
		defer src.Close()

		if file.Size > MaxFileSize {
			errorMessage := fmt.Sprintf("File %s is too big %d (%d mb max)", file.Filename, file.Size*1024*1024, MaxFileSize)
			log.Error(errorMessage)
			DataContext["errors"] = errorMessage
			err := os.RemoveAll(folderPathName)
			if err != nil {
				log.Error("Failed to remove directory %s, %+v\n", folderPathName, err)
			}
			return context.Render(http.StatusOK, "index_file.html", DataContext)
		}
		totalUploadedFileSize += file.Size

		// Destination
		dst, err := os.Create(folderPathName + file.Filename)
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

		fileList = append(fileList, folderPathName+file.Filename)
	}

	if totalUploadedFileSize > MaxFileSize {
		erroMessage := fmt.Sprintf("Total upload size (%d) is greater than %d mb (max authorized)", totalUploadedFileSize, MaxFileSize)
		log.Error(erroMessage)
		DataContext["errors"] = erroMessage
		err := os.RemoveAll(folderPathName)
		if err != nil {
			log.Error("Failed to remove directory %s, %+v\n", folderPathName, err)
		}
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	z := archiver.Zip{
		CompressionLevel: flate.NoCompression,
	}
	err = z.Archive(fileList, FILEFOLDER+"/"+folderName+".zip")
	if err != nil {
		log.Error("Error while archive : %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}

	err = os.RemoveAll(folderPathName)
	if err != nil {
		log.Error("Error while removing folder : %+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "index_file.html", DataContext)
	}
	/*File upload end*/

	var (
		deletableText,
		deletableURL string
	)

	baseUrl := GetBaseUrl(context) + "/file/"
	if f.Deletable == false {
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
	DataContext["deletableText"] = deletableText
	DataContext["deletableURL"] = deletableURL
	DataContext["passwordLink"] = passwordLink

	return context.Render(http.StatusOK, "confirm_file.html", DataContext)
}

func DeleteFile(context echo.Context) error {
	delete(DataContext, "errors")
	f := new(File)
	f.FileKey = context.Param("file_key")
	if f.FileKey == "" || strings.Contains(f.FileKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemoveFile(f)
	var status int
	if err != nil {
		status = err.Code
		return context.NoContent(status)
	} else {
		DataContext["type"] = "File"
		return context.Render(http.StatusOK, "removed.html", DataContext)
	}
}
