package router

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// removeTrailingSlash keeps the encoded and decoded request paths in sync.
// It forwards in place without redirects, as Okuru did with Echo v4.
func removeTrailingSlash(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		req := c.Request()
		path := req.URL.EscapedPath()
		if len(path) > 1 && strings.HasSuffix(path, "/") {
			path = strings.TrimSuffix(path, "/")
			req.URL.Path = strings.TrimSuffix(req.URL.Path, "/")
			if req.URL.RawPath != "" {
				req.URL.RawPath = path
			}
			req.RequestURI = path
			if req.URL.RawQuery != "" {
				req.RequestURI += "?" + req.URL.RawQuery
			}
		}
		return next(c)
	}
}
