package router

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func fileSelectionMessage(r *http.Request, err error) string {
	if (r.URL.Path != "/file" && r.URL.Path != "/file/") || !multipartFileUpload(r) {
		return ""
	}
	switch {
	case errors.Is(err, utils.ErrSecureMultipartFileCount):
		return "Select no more than 100 files."
	case errors.Is(err, utils.ErrSecureMultipartFileSize):
		return "The upload exceeds the size limit. Select fewer or smaller files."
	default:
		return ""
	}
}

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
			c.Response().Header().Set("Cache-Control", "private, no-store")
			statusText := http.StatusText(code)
			_ = c.JSON(code, map[string]string{
				"code": strings.ToLower(strings.ReplaceAll(statusText, " ", "_")), "message": statusText,
			})
			return
		}
		r := c.Request()
		if message := fileSelectionMessage(r, err); message != "" {
			accept, mode := r.Header.Get("Accept"), r.Header.Get("Sec-Fetch-Mode")
			if accept == echo.MIMEApplicationJSON {
				c.Response().Header().Set("Cache-Control", "private, no-store")
				_ = c.JSON(code, map[string]string{"code": "file_selection_limit", "error": message})
				return
			}
			navigation := mode == "navigate" || (mode == "" && strings.HasPrefix(accept, echo.MIMETextHTML))
			if navigation && r.Header.Get("X-Requested-With") == "" {
				data := utils.NewDataContext()
				data["message"] = message
				c.Response().Header().Set("Refresh", "5; url=/file")
				if renderErr := c.Render(code, "file_upload_limit.html", data); renderErr == nil || response.Committed {
					return
				}
				c.Response().Header().Del("Refresh")
			}
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
