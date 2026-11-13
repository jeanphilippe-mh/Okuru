package controllers

import (
	"net/http"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

// Web and API text-secret creation share one Redis-backed budget. The global
// bound also limits growth of per-origin counter keys during a fixed window.
func admitSecretCreation(c echo.Context) *echo.HTTPError {
	allowed, err := utils.AllowClientAction(c.Request(), "secret_create", 50, 400, 24*time.Hour)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Secret creation is temporarily unavailable")
	}
	if !allowed {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many secret creation requests")
	}
	return nil
}
