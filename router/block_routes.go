package router

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"net/http"
)

const tusResource = "/api/v2/uploads/:id/files/:index"

func registerBlockRoutes(e *echo.Echo) {
	e.OPTIONS(tusResource, controllers.UploadTusOptions)
	e.HEAD(tusResource, controllers.UploadTusHead)
	e.PATCH(tusResource, controllers.UploadTusPatch)
}

// Even pre-body rejection on a recognized resource carries the tus version.
func checkTusVersion(c *echo.Context) error {
	h := c.Response().Header()
	h.Set("Tus-Resumable", controllers.TusVersion)
	v := c.Request().Header.Values("Tus-Resumable")
	if len(v) != 1 || v[0] != controllers.TusVersion {
		h.Set("Tus-Version", controllers.TusVersion)
		closeUnreadHTTP1(c)
		return echo.NewHTTPError(http.StatusPreconditionFailed, "Unsupported tus version")
	}
	return nil
}
func checkPatchAdmission(c *echo.Context) error {
	r := c.Request()
	if _, err := utils.AuthorizeUploadSession(r.Context(), c.Param("id"), utils.UploadBearer(r), false); err != nil {
		return controllers.UploadSessionErrorResponse(c, err)
	}
	if r.Header.Get("Content-Type") != "application/offset+octet-stream" {
		return echo.ErrUnsupportedMediaType
	}
	limit := utils.UploadPatchLimit()
	if limit < 1 {
		return echo.ErrServiceUnavailable
	}
	if r.ContentLength > limit {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Upload block too large")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, limit)
	return nil
}
