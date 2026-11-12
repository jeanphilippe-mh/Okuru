package router

import (
	"errors"
	"net/http"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

// Run before CSRF: FormValue must only see our in-memory field cache.
func secureMultipart(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !multipartFileUpload(c.Request()) {
			return next(c)
		}
		form, err := utils.ParseSecureMultipart(c.Request(), utils.FILEFOLDER, utils.MaxFileSize, 100)
		if err != nil {
			closeUnreadHTTP1(c)
			if errors.Is(err, utils.ErrSecureMultipartTooLarge) {
				return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Multipart upload too large")
			}
			var httpErr *echo.HTTPError
			if errors.As(err, &httpErr) && httpErr.Code == http.StatusRequestEntityTooLarge {
				return httpErr
			}
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid multipart upload")
		}
		defer func() {
			if err := form.Close(); err != nil {
				log.Error("Failed to remove encrypted multipart staging")
			}
		}()
		return next(c)
	}
}
