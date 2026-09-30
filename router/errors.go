package router

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Preserve the error status and write each response only once, including when
// RequestLogger has already invoked the handler through HandleError.
func ConfigureErrorHandler(e *echo.Echo, viewDir string) {
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		code := http.StatusInternalServerError
		var httpErr *echo.HTTPError
		if errors.As(err, &httpErr) {
			code = httpErr.Code
		}
		if code < 400 || code > 599 {
			code = http.StatusInternalServerError
		}
		if c.Request().Method == http.MethodHead {
			_ = c.NoContent(code)
			return
		}
		path := c.Request().URL.Path
		if path == "/api" || strings.HasPrefix(path, "/api/") {
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
