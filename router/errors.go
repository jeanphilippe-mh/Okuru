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

func formErrorDestination(r *http.Request) string {
	if r.Method != http.MethodPost || r.Header.Get("X-Requested-With") != "" {
		return ""
	}
	accept, mode := r.Header.Get(echo.HeaderAccept), r.Header.Get("Sec-Fetch-Mode")
	navigation := mode == "navigate" || (mode == "" && strings.HasPrefix(accept, echo.MIMETextHTML))
	if accept == echo.MIMEApplicationJSON || !navigation {
		return ""
	}
	switch r.URL.Path {
	case "/":
		return "/"
	case "/file", "/file/":
		return "/file"
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
		message := fileSelectionMessage(r, err)
		if message != "" && r.Header.Get(echo.HeaderAccept) == echo.MIMEApplicationJSON {
			c.Response().Header().Set(echo.HeaderCacheControl, "private, no-store")
			_ = c.JSON(code, map[string]string{"code": "file_selection_limit", "error": message})
			return
		}
		if destination := formErrorDestination(r); destination != "" {
			if destination == "/file" && errors.Is(err, utils.ErrSecureMultipartFilename) {
				message = utils.ErrSecureMultipartFilename.Error()
			}
			if message == "" {
				message = http.StatusText(code)
			}
			data := utils.NewDataContext()
			data["errors"] = message
			if renderErr := utils.RenderFormError(c, code, "form_error.html", destination, data); renderErr == nil || response.Committed {
				return
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
