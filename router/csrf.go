package router

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

const browserCSRFCookie = "__Host-okuru-csrf"
const csrfVerificationFailedKey = "okuru.csrf.verification_failed"
const csrfVerificationErrorText = "The form could not be verified. Please submit it again."
const csrfVerificationErrorCode = "form_verification_failed"

func browserCSRFConfig() middleware.CSRFConfig {
	config := middleware.DefaultCSRFConfig
	config.Skipper = func(c *echo.Context) bool {
		path := c.Request().URL.Path
		return c.Path() == "/api/*" || c.Path() == "/api" || path == "/api/v2/secrets" || strings.HasPrefix(path, "/api/v2/secrets/") || isFileAPIPath(path)
	}
	config.TokenLookup = "form:_csrf,header:X-CSRF-Token"
	// The __Host- prefix requires Secure, Path=/ and no Domain attribute.
	// Ignore cookies issued under the old name instead of migrating their values.
	config.CookieName = browserCSRFCookie
	config.CookiePath = "/"
	config.CookieDomain = ""
	config.CookieSecure = true
	config.CookieHTTPOnly = true
	config.CookieSameSite = http.SameSiteStrictMode
	config.ErrorHandler = markCSRFVerificationFailure
	// Echo v4 validated tokens for same-site, cross-origin requests.
	// Keep that behavior without bypassing the token check or allowing
	// cross-site and unrecognized Fetch Metadata values.
	config.AllowSecFetchSiteFunc = func(c *echo.Context) (bool, error) {
		if c.Request().Header.Get(echo.HeaderSecFetchSite) == "same-site" {
			return false, nil
		}
		return false, markCSRFVerificationFailure(c, echo.NewHTTPError(http.StatusForbidden, "cross-site request blocked by CSRF"))
	}
	return config
}

func markCSRFVerificationFailure(c *echo.Context, err error) error {
	c.Set(csrfVerificationFailedKey, true)
	return err
}

func requestFromOwnOrigin(c *echo.Context) bool {
	r := c.Request()
	site := r.Header.Get(echo.HeaderSecFetchSite)
	return (site == "" || site == "same-origin") &&
		strings.EqualFold(r.Header.Get(echo.HeaderOrigin), c.Scheme()+"://"+r.Host)
}

func maySetFormCSRFCookie(c *echo.Context) bool {
	r := c.Request()
	if r.Header.Get(echo.HeaderOrigin) != "" {
		return requestFromOwnOrigin(c)
	}
	site := r.Header.Get(echo.HeaderSecFetchSite)
	return site == "" || site == "same-origin" || site == "none"
}

// formCSRFToken restores the form after a rejected POST without using its
// submitted token. A valid existing cookie keeps other open forms usable.
func formCSRFToken(c *echo.Context) string {
	config := browserCSRFConfig()
	if token, ok := c.Get(config.ContextKey).(string); ok && token != "" {
		return token
	}
	c.Response().Header().Add(echo.HeaderVary, echo.HeaderCookie)
	if cookie, err := c.Cookie(config.CookieName); err == nil && len(cookie.Value) == 32 {
		if _, err := base64.RawURLEncoding.DecodeString(cookie.Value); err == nil {
			c.Set(config.ContextKey, cookie.Value)
			return cookie.Value
		}
	}
	var random [24]byte
	_, _ = rand.Read(random[:])
	token := base64.RawURLEncoding.EncodeToString(random[:])
	c.SetCookie(&http.Cookie{
		Name: config.CookieName, Value: token, Domain: config.CookieDomain, Path: config.CookiePath,
		Secure: config.CookieSecure, HttpOnly: config.CookieHTTPOnly, SameSite: config.CookieSameSite,
		Expires: time.Now().Add(time.Duration(config.CookieMaxAge) * time.Second),
	})
	c.Set(config.ContextKey, token)
	return token
}
