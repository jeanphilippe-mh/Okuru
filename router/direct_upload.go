package router

import (
	"crypto/rand"
	"crypto/subtle"
	"mime"
	"net/http"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

const directFilePath = "/api/v2/files/direct"
const uploadBootstrapPath = "/api/v2/uploads/bootstrap"
const directCSRFCookie = "__Host-okuru-upload-csrf"
const directRequestLimit int64 = 90_000_000

// The two v2 endpoints share a host-only cookie across their different paths.
// When the cookie is already present, a bootstrap from another tab reuses it.
func directUploadBootstrap(c *echo.Context) error {
	cookie, err := c.Cookie(directCSRFCookie)
	if err != nil || cookie.Value == "" {
		cookie = &http.Cookie{
			Name: directCSRFCookie, Value: rand.Text(), Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		}
		c.SetCookie(cookie)
	}
	c.Response().Header().Set(echo.HeaderXCSRFToken, cookie.Value)
	api, blocks, err := utils.UploadAdmission(c.Request().Context())
	if err != nil {
		api, blocks = false, false
	}
	modes := []string{"direct"}
	if api {
		modes = append(modes, "multipart")
	}
	if blocks && api && utils.UploadPatchLimit() > 0 {
		modes = append(modes, "blocks")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"modes": modes, "max_total_bytes": utils.MaxFileSize, "max_patch_bytes": utils.UploadPatchLimit(),
		"direct_url": directFilePath, "max_request_bytes": directRequestLimit,
		"max_file_bytes_total": min(utils.MaxFileSize, directRequestLimit),
	})
}

// Check the header before admission, storage reservation or the first body read.
// Asking the global form-based CSRF extractor to read this body could create
// plaintext temporary files. Only these two endpoints use the separate cookie.
func directUploadGuard(enabled bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()
			if !isFileAPIPath(r.URL.Path) {
				return next(c)
			}
			c.Response().Header().Set(echo.HeaderCacheControl, "private, no-store")
			c.Response().Header().Set("Referrer-Policy", "no-referrer")
			reject := func(status int) error {
				closeUnreadHTTP1(c)
				return echo.NewHTTPError(status, http.StatusText(status))
			}
			if !enabled {
				return reject(http.StatusNotFound)
			}
			if r.URL.Path == uploadBootstrapPath {
				if r.Method != http.MethodGet {
					c.Response().Header().Set("Allow", http.MethodGet)
					return reject(http.StatusMethodNotAllowed)
				}
				return next(c)
			}
			if r.URL.Path != directFilePath && (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions) {
				return next(c)
			}
			if r.URL.Path == directFilePath && r.Method != http.MethodPost {
				c.Response().Header().Set("Allow", http.MethodPost)
				return reject(http.StatusMethodNotAllowed)
			}
			site := r.Header.Get(echo.HeaderSecFetchSite)
			cookie, err := r.Cookie(directCSRFCookie)
			token := r.Header.Get(echo.HeaderXCSRFToken)
			if (site != "" && site != "same-origin" && site != "none" && site != "same-site") ||
				err != nil || token == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
				return reject(http.StatusForbidden)
			}
			if r.Method == http.MethodPatch && c.Path() == tusResource {
				if err := checkPatchAdmission(c); err != nil {
					return err
				}
				if resp, e := echo.UnwrapResponse(c.Response()); e != nil || resp.Committed {
					return nil
				}
			}
			if r.URL.Path == preparedFilePath && r.Method == http.MethodPost {
				return receivePreparedMultipart(c, next)
			}
			if r.URL.Path != directFilePath {
				return next(c)
			}
			mediaType, params, err := mime.ParseMediaType(r.Header.Get(echo.HeaderContentType))
			if err != nil || mediaType != echo.MIMEMultipartForm {
				return reject(http.StatusUnsupportedMediaType)
			}
			if params["boundary"] == "" {
				return reject(http.StatusBadRequest)
			}
			if r.ContentLength > directRequestLimit {
				return reject(http.StatusRequestEntityTooLarge)
			}
			r.Body = http.MaxBytesReader(c.Response(), r.Body, directRequestLimit)
			return next(c)
		}
	}
}
