package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

// Browser reports are untrusted observations, not evidence of an attack or of
// a specific cause of a resource loading failure. They never contain URLs,
// document content, CSP policies, nonces, cookies, or arbitrary strings.
const (
	browserSecurityPath        = "/.well-known/okuru-browser-security"
	maxBrowserReportBytes      = 1024
	browserReportWindow        = time.Minute
	maxBrowserReportsPerWindow = 60
)

type browserReportLimiter struct {
	mu         sync.Mutex
	start      time.Time
	count      uint32
	suppressed uint32
	alerted    bool
}

func (l *browserReportLimiter) allow(now time.Time) (allowed, firstRefusal bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.start.IsZero() || now.Before(l.start) || now.Sub(l.start) >= browserReportWindow {
		l.start, l.count = now, 0
		l.alerted = false
	}
	if l.count >= maxBrowserReportsPerWindow {
		if l.suppressed < ^uint32(0) {
			l.suppressed++
		}
		first := !l.alerted
		l.alerted = true
		return false, first
	}
	l.count++
	return true, false
}

var processBrowserReportLimiter browserReportLimiter

func (l *browserReportLimiter) takeSuppressed() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	suppressed := l.suppressed
	l.suppressed = 0
	return suppressed
}

const browserReportLimiterKey = "okuru.browser_security.limiter"

// browserSecurityGuard must precede the generic body-buffering middleware.
// Its shared process budget also covers malformed reports and CSRF failures.
func browserSecurityGuard(limiter *browserReportLimiter) echo.MiddlewareFunc {
	return browserSecurityGuardWithClock(limiter, time.Now)
}

func browserSecurityGuardWithClock(limiter *browserReportLimiter, now func() time.Time) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()
			if r.URL.Path != browserSecurityPath || r.Method != http.MethodPost {
				return next(c)
			}
			allowed, firstRefusal := limiter.allow(now())
			if !allowed {
				if firstRefusal {
					// A bounded alert is emitted even when the budget is saturated
					// continuously and no subsequent valid report is accepted.
					utils.SecurityAlert(nil, "security.browser_report_rate_limited", "Browser report budget reached", log.Fields{
						"limit": maxBrowserReportsPerWindow, "window_seconds": int(browserReportWindow.Seconds()), "scope": "process",
					})
				}
				closeUnreadHTTP1(c)
				return c.NoContent(http.StatusTooManyRequests)
			}
			c.Set(browserReportLimiterKey, limiter)
			if r.ContentLength > maxBrowserReportBytes {
				closeUnreadHTTP1(c)
				return c.NoContent(http.StatusRequestEntityTooLarge)
			}
			return next(c)
		}
	}
}

// parseBrowserReport rejects duplicate and unknown fields, non-string values,
// trailing JSON and anything outside an explicit, finite category vocabulary.
func parseBrowserReport(body []byte) (string, string, error) {
	if len(body) > maxBrowserReportBytes {
		return "", "", errors.New("report too large")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	open, err := d.Token()
	if err != nil || open != json.Delim('{') {
		return "", "", errors.New("invalid report")
	}
	var kind, category string
	seenKind, seenCategory := false, false
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return "", "", errors.New("invalid report")
		}
		switch key {
		case "kind":
			if seenKind || d.Decode(&kind) != nil {
				return "", "", errors.New("invalid report")
			}
			seenKind = true
		case "category":
			if seenCategory || d.Decode(&category) != nil {
				return "", "", errors.New("invalid report")
			}
			seenCategory = true
		default:
			return "", "", errors.New("invalid report")
		}
	}
	closeToken, err := d.Token()
	if err != nil || closeToken != json.Delim('}') || !seenKind || !seenCategory {
		return "", "", errors.New("invalid report")
	}
	if _, err := d.Token(); err != io.EOF {
		return "", "", errors.New("invalid report")
	}
	switch kind {
	case "csp_violation":
		switch category {
		case "script", "style", "connect", "worker", "frame", "form", "base", "object", "trusted_types", "img", "font", "media", "manifest", "other":
			return kind, category, nil
		}
	case "script_load_failure":
		switch category {
		case "bootstrap", "purify", "clipboard", "worker_registration", "other":
			return kind, category, nil
		}
	}
	return "", "", errors.New("invalid report")
}

func browserSecurityReport(c *echo.Context) error {
	mediaType, _, err := mime.ParseMediaType(c.Request().Header.Get(echo.HeaderContentType))
	if err != nil || mediaType != "application/json" {
		return c.NoContent(http.StatusUnsupportedMediaType)
	}
	if c.Request().Body == nil {
		return c.NoContent(http.StatusBadRequest)
	}
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, maxBrowserReportBytes+1))
	if err != nil || len(body) > maxBrowserReportBytes {
		return c.NoContent(http.StatusRequestEntityTooLarge)
	}
	kind, category, err := parseBrowserReport(body)
	if err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	fields := log.Fields{"kind": kind, "browser_category": category, "source": "untrusted_browser"}
	if limiter, ok := c.Get(browserReportLimiterKey).(*browserReportLimiter); ok && limiter != nil {
		fields["suppressed"] = limiter.takeSuppressed()
	}
	utils.SecurityAlert(c, "security.browser_report", "Browser reported a security-related observation", fields)
	return c.NoContent(http.StatusNoContent)
}
