package controllers

import (
	"net/http"
	"time"

	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

// Bound archive creation across processes, including tiny/passwordless
// uploads, before spending the shared retained-archive quota. Client identity
// is derived using the explicitly configured trusted proxies.
const fileCreationPerClient, fileCreationGlobal = 20, 100
const fileCreationWindow = 24 * time.Hour

func admitFileCreation(c *echo.Context) *echo.HTTPError {
	allowed, err := AllowClientAction(c.Request(), "file_create", fileCreationPerClient, fileCreationGlobal, fileCreationWindow)
	return fileCreationAdmissionResult(c, allowed, err)
}

func admitPreparedFileCreation(c *echo.Context, id, bearer string) *echo.HTTPError {
	allowed, err := AllowPreparedFileCreation(c.Request(), id, bearer, fileCreationPerClient, fileCreationGlobal, fileCreationWindow)
	return fileCreationAdmissionResult(c, allowed, err)
}

func fileCreationAdmissionResult(c *echo.Context, allowed bool, err error) *echo.HTTPError {
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "File creation is unavailable")
	}
	if !allowed {
		c.Response().Header().Set("Retry-After", "86400")
		return echo.NewHTTPError(http.StatusTooManyRequests, "File creation limit reached")
	}
	return nil
}
