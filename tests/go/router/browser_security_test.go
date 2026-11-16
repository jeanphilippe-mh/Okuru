package router

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

func TestBrowserReportStrictVocabulary(t *testing.T) {
	valid := []struct{ body, kind, category string }{
		{`{"kind":"csp_violation","category":"script"}`, "csp_violation", "script"},
		{` { "category" : "worker_registration", "kind" : "script_load_failure" } `, "script_load_failure", "worker_registration"},
		{`{"kind":"csp_violation","category":"trusted_types"}`, "csp_violation", "trusted_types"},
	}
	for _, tt := range valid {
		kind, category, err := parseBrowserReport([]byte(tt.body))
		if err != nil || kind != tt.kind || category != tt.category {
			t.Fatalf("valid report %s => %q %q: %v", tt.body, kind, category, err)
		}
	}
	invalid := []string{
		`null`, `[]`, `{}`, `{"kind":"csp_violation"}`,
		`{"kind":"csp_violation","category":"script","nonce":"secret"}`,
		`{"kind":"csp_violation","kind":"script_load_failure","category":"script"}`,
		`{"kind":"csp_violation","category":"script","category":"style"}`,
		`{"kind":"csp_violation","category":null}`,
		`{"kind":"csp_violation","category":5}`,
		`{"kind":"csp_violation","category":"https://example.test/secret"}`,
		`{"kind":"script_load_failure","category":"script"}`,
		`{"kind":"csp_violation","category":"script"} {}`,
		`{"kind":"csp_violation","category":"script"} false`,
		strings.Repeat("x", maxBrowserReportBytes+1),
	}
	for _, body := range invalid {
		if _, _, err := parseBrowserReport([]byte(body)); err == nil {
			t.Errorf("accepted invalid report %q", body)
		}
	}
}

func TestBrowserReportLimiterSharedBoundAndSuppression(t *testing.T) {
	var limiter browserReportLimiter
	now := time.Unix(1234, 0)
	var admitted atomic.Int32
	var saturationAlerts atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < maxBrowserReportsPerWindow*4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			allowed, first := limiter.allow(now)
			if allowed {
				admitted.Add(1)
			}
			if first {
				saturationAlerts.Add(1)
			}
		}()
	}
	group.Wait()
	if admitted.Load() != maxBrowserReportsPerWindow {
		t.Fatalf("admitted %d reports", admitted.Load())
	}
	if saturationAlerts.Load() != 1 {
		t.Fatalf("first-refusal alerts = %d, want 1", saturationAlerts.Load())
	}
	if got := limiter.takeSuppressed(); got != maxBrowserReportsPerWindow*3 {
		t.Fatalf("suppressed %d reports", got)
	}
	if allowed, _ := limiter.allow(now.Add(browserReportWindow - time.Nanosecond)); allowed {
		t.Fatal("budget reopened before its window ended")
	}
	if allowed, _ := limiter.allow(now.Add(browserReportWindow)); !allowed {
		t.Fatal("budget did not reopen at the next window")
	}
	if got := limiter.takeSuppressed(); got != 1 {
		t.Fatalf("next window suppressed = %d", got)
	}
}

type countedReportBody struct {
	r io.Reader
	n int
}

func (b *countedReportBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += n
	return n, err
}
func (*countedReportBody) Close() error { return nil }

func TestBrowserReportBoundsBeforeGenericBodyBuffer(t *testing.T) {
	var limiter browserReportLimiter
	e := echo.New()
	e.Use(browserSecurityGuard(&limiter))
	e.Use(requestLimits(time.Second, time.Second, time.Second))
	e.POST(browserSecurityPath, browserSecurityReport)
	for _, declared := range []int64{maxBrowserReportBytes + 1, -1} {
		body := &countedReportBody{r: strings.NewReader(strings.Repeat("x", maxBrowserReportBytes*4))}
		req := httptest.NewRequest(http.MethodPost, browserSecurityPath, nil)
		req.Header.Set("Content-Type", "application/json")
		req.Body, req.ContentLength = body, declared
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("declared %d: status %d, want 413", declared, rec.Code)
		}
		if declared > 0 && body.n != 0 {
			t.Fatalf("declared oversized body read %d bytes", body.n)
		}
		if body.n > maxBrowserReportBytes+1 {
			t.Fatalf("streamed body read %d bytes", body.n)
		}
	}
}

// A partial chunked HTTP/1 body must be rejected promptly after 1025 bytes;
// waiting to close/drain the unfinished stream would consume server capacity.
func TestBrowserReportChunkedExcessDoesNotWaitForDrain(t *testing.T) {
	var limiter browserReportLimiter
	e := echo.New()
	e.Use(browserSecurityGuard(&limiter))
	e.Use(requestLimits(10*time.Second, 10*time.Second, 10*time.Second))
	e.POST(browserSecurityPath, browserSecurityReport)
	server := httptest.NewServer(e)
	defer server.Close()
	connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(connection, "POST %s HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", browserSecurityPath, maxBrowserReportBytes+1, strings.Repeat("x", maxBrowserReportBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately leave the chunked body unfinished while awaiting the reply.
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("server waited for the unfinished body: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge || !response.Close {
		t.Fatalf("status=%d close=%v, want 413 and closed HTTP/1 connection", response.StatusCode, response.Close)
	}
}

func TestBrowserReportActualRouterCSRFAndSafeLogs(t *testing.T) {
	processBrowserReportLimiter = browserReportLimiter{}
	t.Cleanup(func() { processBrowserReportLimiter = browserReportLimiter{} })
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.Level
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(utils.NewAuditJSONFormatter())
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() { logger.SetOutput(oldOut); logger.SetFormatter(oldFormatter); logger.SetLevel(oldLevel) })
	e := New()
	e.POST("/browser-security-csrf-check", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	send := func(path, body, site, contentType string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		r.Header.Set("User-Agent", "sensitive-header-marker")
		r.Header.Set("Referer", "https://example.test/secret-link-marker")
		r.Header.Set("X-Request-Id", "request-id-marker")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, r)
		return rec.Code
	}
	payload := `{"kind":"script_load_failure","category":"purify"}`
	if got := send(browserSecurityPath+"?secret=query-marker", payload, "same-origin", "application/json"); got != http.StatusNoContent {
		t.Fatalf("valid report returned %d", got)
	}
	for _, tt := range []struct {
		body, site, content string
		want                int
	}{
		{`{"kind":"csp_violation","category":"script","nonce":"body-secret-marker"}`, "same-origin", "application/json", http.StatusBadRequest},
		{payload, "cross-site", "application/json", http.StatusForbidden},
		{payload, "same-site", "application/json", http.StatusBadRequest},
		{payload, "same-origin", "text/plain", http.StatusUnsupportedMediaType},
	} {
		if got := send(browserSecurityPath, tt.body, tt.site, tt.content); got != tt.want {
			t.Errorf("report site=%q content=%q status = %d, want %d", tt.site, tt.content, got, tt.want)
		}
	}
	if got := send("/browser-security-csrf-check", payload, "cross-site", "application/json"); got != http.StatusForbidden {
		t.Fatalf("CSRF protection changed for another endpoint: %d", got)
	}
	logs := output.String()
	if !strings.Contains(logs, `"event":"security.browser_report"`) || !strings.Contains(logs, `"source":"untrusted_browser"`) || !strings.Contains(logs, `"browser_category":"purify"`) {
		t.Fatalf("missing bounded browser event: %s", logs)
	}
	for _, marker := range []string{"query-marker", "body-secret-marker", "secret-link-marker", "request-id-marker"} {
		if strings.Contains(logs, marker) {
			t.Errorf("logs contain %s: %s", marker, logs)
		}
	}
	// An unrelated route may record its own bounded user agent, so assert that
	// the browser-report requests alone did not add ordinary request records.
	if got := strings.Count(logs, `"event":"security.browser_report"`); got != 1 {
		t.Fatalf("expected one browser event, got %d: %s", got, logs)
	}
	if got := strings.Count(logs, `"event":"http.request"`); got != 1 {
		t.Fatalf("unexpected generic report log count %d: %s", got, logs)
	}
}

func TestBrowserReportGuardThrottlesBeforeReading(t *testing.T) {
	var limiter browserReportLimiter
	e := echo.New()
	e.Use(browserSecurityGuard(&limiter))
	e.POST(browserSecurityPath, func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	for i := 0; i < maxBrowserReportsPerWindow; i++ {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, browserSecurityPath, nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	body := &countedReportBody{r: strings.NewReader("should-not-be-read")}
	r := httptest.NewRequest(http.MethodPost, browserSecurityPath, nil)
	r.Body, r.ContentLength = body, -1
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests || body.n != 0 {
		t.Fatal(fmt.Sprintf("rate limited status=%d body read=%d", rec.Code, body.n))
	}
}

func TestBrowserReportContinuousSaturationEmitsBoundedAlerts(t *testing.T) {
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.Level
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(utils.NewAuditJSONFormatter())
	logger.SetLevel(log.WarnLevel)
	t.Cleanup(func() { logger.SetOutput(oldOut); logger.SetFormatter(oldFormatter); logger.SetLevel(oldLevel) })
	var limiter browserReportLimiter
	now := time.Unix(2000, 0)
	e := echo.New()
	e.Use(browserSecurityGuardWithClock(&limiter, func() time.Time { return now }))
	e.POST(browserSecurityPath, func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	for window := 0; window < 3; window++ {
		now = time.Unix(2000, 0).Add(time.Duration(window) * browserReportWindow)
		for i := 0; i < maxBrowserReportsPerWindow+20; i++ {
			r := httptest.NewRequest(http.MethodPost, browserSecurityPath+"?leak=secret-marker", nil)
			r.Header.Set("User-Agent", "header-secret-marker")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, r)
			if (i < maxBrowserReportsPerWindow && rec.Code != http.StatusNoContent) || (i >= maxBrowserReportsPerWindow && rec.Code != http.StatusTooManyRequests) {
				t.Fatalf("window %d request %d: %d", window, i, rec.Code)
			}
		}
	}
	logs := output.String()
	if count := strings.Count(logs, `"event":"security.browser_report_rate_limited"`); count != 3 {
		t.Fatalf("saturation alerts = %d, want one per window: %s", count, logs)
	}
	if strings.Contains(logs, "secret-marker") || strings.Contains(logs, browserSecurityPath) {
		t.Fatalf("saturation alert contains request data: %s", logs)
	}
}
