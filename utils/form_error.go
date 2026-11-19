package utils

import (
	"fmt"

	"github.com/flosch/pongo2"
	"github.com/labstack/echo/v5"
)

const formErrorReturnDelay = 3

// RenderFormError displays the failure before navigating to the form via GET.
// The destination is a local form path selected by the caller.
func RenderFormError(c *echo.Context, status int, template, destination string, data pongo2.Context) error {
	data["returnPath"] = destination
	data["returnDelay"] = formErrorReturnDelay
	header := c.Response().Header()
	header.Set(echo.HeaderCacheControl, "private, no-store")
	header.Set("Refresh", fmt.Sprintf("%d; url=%s", formErrorReturnDelay, destination))
	err := c.Render(status, template, data)
	if err != nil {
		header.Del("Refresh")
	}
	return err
}
