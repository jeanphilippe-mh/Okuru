package router

import (
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

// Apply to candidates, including method errors, before slash normalization or
// any middleware can produce a response.
func shortLinkHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		path := c.Request().URL.Path
		if utils.IsRootShortLinkPath(path) {
			c.Response().Header().Set("Cache-Control", "no-store")
		}
		return next(c)
	}
}
