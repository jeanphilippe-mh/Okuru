package controllers

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

// Bound concurrent resolutions so they cannot exhaust the dedicated Redis
// pool and starve new aliases. This is per-process and is not DDoS protection.
var shortLinkResolveSlots = make(chan struct{}, 8)

// ReadRootShare dispatches the root segment without altering the established
// GET and POST behavior for password tokens. HEAD is only enabled for aliases.
func ReadRootShare(c echo.Context) error {
	// Echo may expose RawPath in parameters. Use net/http's decoded URL.Path
	// for classification so percent-encoded alias characters behave the same
	// way as their literal equivalents; do not decode it a second time.
	path := c.Request().URL.Path
	if strings.HasPrefix(path, "/") && IsShortLinkCandidate(path[1:]) {
		return redirectShortLink(c, path[1:])
	}
	if c.Request().Method == http.MethodHead {
		return echo.ErrMethodNotAllowed
	}
	return ReadIndex(c)
}

// redirectShortLink resolves only a locally generated, authenticated mapping.
// The shortener never fetches the target: the browser follows the redirect and
// the original share handler remains responsible for views and expiry.
func redirectShortLink(c echo.Context, alias string) error {
	select {
	case shortLinkResolveSlots <- struct{}{}:
		defer func() { <-shortLinkResolveSlots }()
	default:
		c.Response().Header().Set("Retry-After", "1")
		return c.NoContent(http.StatusServiceUnavailable)
	}

	target, err := ResolveShortLink(c.Request().Context(), alias)
	if errors.Is(err, ErrShortLinkNotFound) {
		return c.NoContent(http.StatusNotFound)
	}
	if err != nil {
		return c.NoContent(http.StatusServiceUnavailable)
	}
	// A defense in depth check: the storage layer reconstructs a relative path
	// from a validated token and resource type, never from an arbitrary URL.
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.ContainsAny(target, "\\\r\n?#") {
		return c.NoContent(http.StatusNotFound)
	}
	return c.Redirect(http.StatusFound, target)
}

// shareLink returns the existing URL when short-link creation is disabled or
// unavailable, without making a successfully created secret inaccessible.
func shareLink(c echo.Context, token string, isFile bool) (string, string) {
	longPath := "/" + token
	if isFile {
		longPath = "/file/" + token
	}
	origin, ok := shortLinkPublicOrigin(os.Getenv("OKURU_SHORTLINK_PUBLIC_ORIGIN"))
	if !ok {
		base := GetBaseUrl(c)
		return base + longPath, base + longPath
	}
	original := origin + longPath
	alias, err := CreateShortLink(c.Request().Context(), token, isFile)
	if err != nil {
		return original, original
	}
	return origin + "/" + alias, original
}

// sharePublicOrigin keeps the historical origin when short-link configuration
// is absent or invalid; otherwise all rendered share and deletion URLs use the
// configured trusted origin rather than the request's Host header.
func sharePublicOrigin(c echo.Context) string {
	if origin, ok := shortLinkPublicOrigin(os.Getenv("OKURU_SHORTLINK_PUBLIC_ORIGIN")); ok {
		return origin
	}
	return GetBaseUrl(c)
}

// shortLinkPublicOrigin requires a configured canonical HTTPS origin. The
// request Host never determines the short URL; unconfigured or malformed
// origins disable short-link creation rather than risking host poisoning.
func shortLinkPublicOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || u.Scheme != "https" || u.Opaque != "" || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != raw {
		return "", false
	}
	host := u.Hostname()
	if host == "" || host != strings.ToLower(host) {
		return "", false
	}
	canonicalHost := host
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" || addr.Is4In6() || addr.String() != host {
			return "", false
		}
		if addr.Is6() {
			canonicalHost = "[" + host + "]"
		}
	} else {
		if len(host) > 253 {
			return "", false
		}
		labels := strings.Split(host, ".")
		// Browsers interpret domains ending in a number as IPv4 candidates.
		// Reject noncanonical numeric forms instead of accepting a host that a
		// browser would normalize to a different origin or refuse altogether.
		if endsInNumber(labels[len(labels)-1]) {
			return "", false
		}
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || !asciiAlphaNum(label[0]) || !asciiAlphaNum(label[len(label)-1]) {
				return "", false
			}
			for i := 1; i < len(label)-1; i++ {
				if !asciiAlphaNum(label[i]) && label[i] != '-' {
					return "", false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", false
		}
		canonicalHost += ":" + port
	}
	if u.Host != canonicalHost {
		return "", false
	}
	return raw, true
}

func asciiAlphaNum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// Match browser IPv4-number candidates, including hexadecimal and legacy
// octal forms. Canonical IP addresses were handled by netip.ParseAddr above.
func endsInNumber(label string) bool {
	if label == "" {
		return false
	}
	if strings.HasPrefix(label, "0x") {
		for i := 2; i < len(label); i++ {
			c := label[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}
