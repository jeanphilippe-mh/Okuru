package controllers

import (
	"net/http"

	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

// auditUnavailable distinguishes an internal failure from an unavailable
// resource without recording the error body, bearer token, or concrete path.
// The caller remains responsible for preserving its existing public response.
func auditUnavailable(c *echo.Context, err *echo.HTTPError, event, message string) {
	if err != nil && err.Code >= http.StatusInternalServerError {
		AuditError(c, event, message)
		return
	}
	AuditAlert(c, event, message)
}
