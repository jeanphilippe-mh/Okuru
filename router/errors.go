package router

import (
	"fmt"
	"github.com/labstack/echo/v5"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Preserve the error status and write each response only once, including when
// RequestLogger has already invoked the handler through HandleError.
func ConfigureErrorHandler(e *echo.Echo, viewDir string) {
	e.HTTPErrorHandler = func(c *echo.Context, err error) {
		response, unwrapErr := echo.UnwrapResponse(c.Response())
		if unwrapErr != nil {
			// We cannot safely know whether headers have been sent. Abort rather
			// than return an empty implicit 200 or append to a partial response.
			panic(http.ErrAbortHandler)
		}
		if response.Committed {
			return
		}
		code := echo.StatusCode(err)
		if code < 400 || code > 599 {
			code = http.StatusInternalServerError
		}
		if c.Request().Method == http.MethodHead {
			_ = c.NoContent(code)
			return
		}
		path := c.Request().URL.Path
		if path == "/api" || strings.HasPrefix(path, "/api/") {
			c.Response().Header().Set("Cache-Control", "no-store")
			_ = c.JSON(code, map[string]string{"error": http.StatusText(code)})
			return
		}
		page, readErr := os.ReadFile(filepath.Join(viewDir, fmt.Sprintf("%d.html", code)))
		if readErr == nil {
			_ = c.HTMLBlob(code, page)
			return
		}
		// A missing error page must not turn the failure into a blank 200.
		_ = c.String(code, http.StatusText(code))
	}
}
