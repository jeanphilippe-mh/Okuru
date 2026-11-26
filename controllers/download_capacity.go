package controllers

import (
	"net/http"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

const (
	maxConcurrentArchiveDownloads = 16
	maxArchiveDownloadsPerClient  = 4
	maxDownloadsPerArchive        = 4
)

var archiveDownloads = utils.NewRequestCapacity(maxConcurrentArchiveDownloads, maxArchiveDownloadsPerClient, maxDownloadsPerArchive)

// Take capacity before reserving a view or claiming a continuation. The
// archive name is canonical and contains only the file UUID and extension.
func admitArchiveDownload(c *echo.Context, archiveName string) (func(), error) {
	release := archiveDownloads.TryAcquire(c.Request(), archiveName)
	if release == nil {
		c.Response().Header().Set(echo.HeaderRetryAfter, "1")
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Download capacity is busy")
	}
	return release, nil
}
