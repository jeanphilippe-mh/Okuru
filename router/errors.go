package router

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func multipartFormError(r *http.Request, err error) (message, code string) {
	if (r.URL.Path != "/file" && r.URL.Path != "/file/") || !multipartFileUpload(r) {
		return "", ""
	}
	switch {
	case errors.Is(err, utils.ErrSecureMultipartFileCount):
		return "Select no more than 100 files.", "file_selection_limit"
	case errors.Is(err, utils.ErrSecureMultipartFileSize):
		return "The upload exceeds the size limit. Select fewer or smaller files.", "file_selection_limit"
	case errors.Is(err, utils.ErrSecureMultipartFilename):
		return utils.UploadFilenameErrorMessage(err), utils.UploadFilenameErrorCode
	default:
		return "", ""
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
		message, formCode := multipartFormError(r, err)
		csrfFailed, _ := c.Get(csrfVerificationFailedKey).(bool)
		if csrfFailed && (path == "/file" || path == "/file/") && multipartFileUpload(r) {
			message, formCode = csrfVerificationErrorText, csrfVerificationErrorCode
		}
		if message != "" && r.Header.Get(echo.HeaderAccept) == echo.MIMEApplicationJSON {
			c.Response().Header().Set(echo.HeaderCacheControl, "private, no-store")
			if formCode == csrfVerificationErrorCode && requestFromOwnOrigin(c) {
				c.Response().Header().Set(echo.HeaderXCSRFToken, formCSRFToken(c))
			}
			_ = c.JSON(code, map[string]string{"error": message, "code": formCode})
			return
		}
		if destination := formErrorDestination(r); destination != "" {
			if csrfFailed || formCode == utils.UploadFilenameErrorCode && message != "" {
				if csrfFailed {
					message = csrfVerificationErrorText
				}
				if renderErr := renderInlineFormError(c, code, destination, message); renderErr != nil && !response.Committed {
					_ = c.String(code, message)
				}
				return
			}
			data := utils.NewDataContext()
			if message == "" {
				message = http.StatusText(code)
			} else {
				data["showErrorIcon"] = true
			}
			data["errors"] = message
			if renderErr := utils.RenderFormError(c, code, "form_error.html", destination, data); renderErr == nil || response.Committed {
				return
			}
		}
		if code == http.StatusRequestEntityTooLarge {
			if renderErr := c.Render(code, "request_too_large.html", utils.NewDataContext()); renderErr == nil || response.Committed {
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

func renderInlineFormError(c *echo.Context, status int, destination, message string) error {
	if maySetFormCSRFCookie(c) {
		formCSRFToken(c)
	}
	if destination == "/file" {
		return controllers.RenderFileForm(c, status, message)
	}
	return controllers.RenderSecretForm(c, status, message)
}
