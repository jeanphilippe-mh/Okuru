package controllers

import (
	"net/http"
	"time"

	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

// Bound archive creation across processes, including tiny/passwordless
// uploads, before spending the shared retained-archive quota. Client identity
// is derived using the explicitly configured trusted proxies.
func admitFileCreation(c echo.Context) *echo.HTTPError {
	allowed, err := AllowClientAction(c.Request(), "file_create", 20, 100, 24*time.Hour)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "File creation is unavailable")
	}
	if !allowed {
		c.Response().Header().Set("Retry-After", "86400")
		return echo.NewHTTPError(http.StatusTooManyRequests, "File creation limit reached")
	}
	return nil
}
