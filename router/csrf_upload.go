package router

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// Echo and the early upload guard use this check for values other than
// same-origin, none or an absent Sec-Fetch-Site header.
func checkBrowserCSRFNonSameOrigin(c *echo.Context) (bool, error) {
	if c.Request().Header.Get(echo.HeaderSecFetchSite) == "same-site" {
		return false, nil
	}
	return false, markCSRFVerificationFailure(c, echo.ErrForbidden)
}

// Reject requests Echo would deny before taking an upload lease or parsing the
// body. The remaining requests still go through the full CSRF middleware.
func rejectCrossSiteMultipartUpload(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		r := c.Request()
		if r.Method != http.MethodPost || (r.URL.Path != "/file" && r.URL.Path != "/file/") {
			return next(c)
		}
		switch r.Header.Get(echo.HeaderSecFetchSite) {
		case "", "same-origin", "none":
			return next(c)
		}
		if multipartFileUpload(r) {
			if _, err := checkBrowserCSRFNonSameOrigin(c); err != nil {
				closeUnreadHTTP1(c)
				return err
			}
		}
		return next(c)
	}
}
