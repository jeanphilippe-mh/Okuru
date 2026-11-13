package router

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
)

const (
	maxLoggedHostBytes      = 255
	maxLoggedUserAgentBytes = 256
	maxLoggedRemoteIPBytes  = 64
	maxLoggedMethodBytes    = 32
	maxLoggedLengthBytes    = 32
)

// boundedLogText limits attacker-controlled request metadata without making an
// unbounded copy. Invalid UTF-8 bytes are replaced, and truncation is marked
// within the byte limit. JSON encoding and control escaping are left to slog.
func boundedLogText(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	var out strings.Builder
	out.Grow(min(len(value), maxBytes))
	rest := value
	for len(rest) > 0 {
		r, size := utf8.DecodeRuneInString(rest)
		if out.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		out.WriteRune(r)
		rest = rest[size:]
	}
	result := out.String()
	if len(rest) == 0 {
		return result
	}
	const marker = "..."
	if maxBytes < len(marker) {
		return result
	}
	for len(result)+len(marker) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(result)
		result = result[:len(result)-size]
	}
	return result + marker
}

// Log the router pattern, never the concrete RequestURI or its query string.
func safeLogRoute(c echo.Context) string {
	if route := c.Path(); route != "" {
		return route
	}
	return "unmatched"
}

// Errors may embed attacker-controlled URLs, payloads or file names. Keep a
// useful status category without copying arbitrary error text into logs.
func safeLogError(err error) string {
	var httpErr *echo.HTTPError
	if errors.As(err, &httpErr) {
		return http.StatusText(httpErr.Code)
	}
	return "request failed"
}
