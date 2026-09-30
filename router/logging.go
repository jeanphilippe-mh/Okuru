package router

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
)

// Log the router pattern, never the concrete RequestURI or its query string.
func safeLogRoute(c echo.Context) string {
	if route := c.Path(); route != "" {
		return route
	}
	return "unmatched"
}

// Errors may embed attacker-controlled URLs, payloads or file names. Keep a
// useful status category without copying arbitrary error text into logs.
func safeLogError(err error) string {
	var httpErr *echo.HTTPError
	if errors.As(err, &httpErr) {
		return http.StatusText(httpErr.Code)
	}
	return "request failed"
}
