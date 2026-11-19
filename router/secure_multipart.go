package router

import (
	"errors"
	"io"
	"net/http"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

// Run before CSRF: FormValue must only see our in-memory field cache.
func secureMultipart(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		if !multipartFileUpload(c.Request()) {
			return next(c)
		}
		r := c.Request()
		parse := utils.ParseSecureMultipart
		maxFileBytes := utils.MaxFileSize
		if r.URL.Path == directFilePath {
			parse = utils.ParseDirectFileMultipart
			maxFileBytes = min(maxFileBytes, directRequestLimit)
		}
		var form *utils.SecureMultipart
		var err error
		if r.URL.Path == preparedFilePath {
			session, _ := c.Get("okuru-prepared-upload").(*utils.UploadSession)
			if session == nil {
				return echo.ErrForbidden
			}
			form, err = utils.ParsePreparedMultipart(r, utils.FILEFOLDER, maxFileBytes, session.Metadata)
		} else {
			form, err = parse(r, utils.FILEFOLDER, maxFileBytes, 100)
		}
		if err == nil {
			defer func() {
				if err := form.Close(); err != nil {
					log.Error("Failed to remove encrypted multipart staging")
				}
			}()
			// Multipart parsing stops at the closing boundary. Count the MIME
			// epilogue too, including when the client omitted Content-Length.
			if r.URL.Path == directFilePath || r.URL.Path == preparedFilePath {
				_, err = io.Copy(io.Discard, r.Body)
			}
		}
		if err != nil {
			closeUnreadHTTP1(c)
			// Echo v5 BodyLimit returns a status sentinel rather than an
			// *echo.HTTPError. Parsing may wrap it with errors.Join.
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) || errors.Is(err, utils.ErrSecureMultipartFileSize) || echo.StatusCode(err) == http.StatusRequestEntityTooLarge {
				return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Multipart upload too large").Wrap(utils.ErrSecureMultipartFileSize)
			}
			if errors.Is(err, utils.ErrSecureMultipartTooLarge) {
				return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Multipart upload too large")
			}
			if errors.Is(err, utils.ErrSecureMultipartFileCount) {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid multipart upload").Wrap(utils.ErrSecureMultipartFileCount)
			}
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid multipart upload")
		}
		return next(c)
	}
}
