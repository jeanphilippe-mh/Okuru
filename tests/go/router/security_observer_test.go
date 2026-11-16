package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

func TestSecurityProbePatternsAreFixedAndDoNotMatchArbitraryShares(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/.env", "environment_file"},
		{"/.ENV.production", "environment_file"},
		{"/.git/config", "git_metadata"},
		{"/wp-login.php", "wordpress_endpoint"},
		{"/phpmyadmin/", "database_admin_endpoint"},
		{"/", ""},
		{"/share-token-containing-.env", ""},
		{"/other/wp-login.php", ""},
		{strings.Repeat("a", 257), ""},
	}
	for _, tt := range tests {
		if got := securityProbeClass(tt.path); got != tt.want {
			t.Errorf("securityProbeClass(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestSecurityObservationThresholdsWindowsAndAlertThrottling(t *testing.T) {
	s := newSecurityObserver()
	now := time.Unix(1_000, 0)
	for n := 1; n <= securityPerSourceLimit; n++ {
		got := s.observe(now, "1.1.1.1", "")
		if got.sourceHigh != (n == securityPerSourceLimit) || got.globalHigh || got.probe {
			t.Fatalf("source request %d unexpected observation: %+v", n, got)
		}
	}
	for n := securityPerSourceLimit + 1; n <= securityGlobalLimit; n++ {
		got := s.observe(now, "1.1.1.1", "")
		if got.sourceHigh || got.globalHigh != (n == securityGlobalLimit) {
			t.Fatalf("global request %d unexpected observation: %+v", n, got)
		}
	}
	if got := s.observe(now, "1.1.1.1", "environment_file"); !got.probe || got.sourceHigh || got.globalHigh {
		t.Fatalf("first probe unexpected: %+v", got)
	}
	if got := s.observe(now, "1.1.1.1", "environment_file"); got.probe {
		t.Fatal("repeated probe was not throttled")
	}
	if got := s.observe(now.Add(securityObservationWindow), "1.1.1.1", ""); got.sourceHigh || got.globalHigh {
		t.Fatalf("new observation window did not reset counters: %+v", got)
	}
	if got := s.observe(now.Add(securityAlertInterval), "1.1.1.1", "git_metadata"); !got.probe || got.suppressed[0] != 1 {
		t.Fatalf("probe did not report one suppressed observation: %+v", got)
	}
}

func TestSecurityObservationMemoryBoundAndConcurrency(t *testing.T) {
	s := newSecurityObserver()
	now := time.Unix(2_000, 0)
	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for n := 0; n < 400; n++ {
				s.observe(now, fmt.Sprintf("public-test-%d-%d", w, n), "")
			}
		}(worker)
	}
	wg.Wait()
	if got := len(s.sources); got != securityMaxSources {
		t.Fatalf("stored source count = %d, want bounded %d", got, securityMaxSources)
	}
	if s.total != securityGlobalLimit {
		t.Fatalf("global count = %d, want capped %d", s.total, securityGlobalLimit)
	}
	s.observe(now.Add(securityObservationWindow), "next", "")
	if len(s.sources) != 1 || s.sources["next"] != 1 {
		t.Fatal("source map was not reset for the next window")
	}
}

func TestSecuritySourceIgnoresUntrustedOrNonPublicAddresses(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := securitySource(r); got != "" {
		t.Fatalf("untrusted loopback attributed as a visitor: %q", got)
	}
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
	if got := securitySource(r); got != "1.1.1.1" {
		t.Fatalf("valid forwarded address = %q", got)
	}
	r.Header.Set("X-Forwarded-For", "192.0.2.7")
	if got := securitySource(r); got != "" {
		t.Fatalf("documentation range attributed as public: %q", got)
	}
	r.Header.Set("X-Forwarded-For", "2606:4700:4700::1111")
	if got := securitySource(r); got != "2606:4700:4700::/64" {
		t.Fatalf("IPv6 /64 budget = %q", got)
	}
}

func TestSecurityMiddlewareDoesNotLogRawPathHeadersOrProxyAsVisitor(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.Level
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(utils.NewAuditJSONFormatter())
	logger.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})

	e := echo.New()
	e.Use(securityObservations(newSecurityObserver()))
	e.GET("/.env", func(c *echo.Context) error { return c.NoContent(http.StatusNotFound) })
	r := httptest.NewRequest(http.MethodGet, "https://example.test/.env?share=PRIVATE_SHARING_KEY_123", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	r.Header.Set("User-Agent", "PRIVATE_SHARING_KEY_123")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("middleware changed HTTP status: %d", rec.Code)
	}
	line := strings.TrimSpace(output.String())
	if !strings.HasPrefix(line, "[SECURITY] ") || strings.Contains(line, "PRIVATE_SHARING_KEY_123") || strings.Contains(line, "/.env") || strings.Contains(line, "1.1.1.1") || strings.Contains(line, `"client_ip":"127.0.0.1"`) {
		t.Fatalf("unsafe or incorrect security alert: %s", line)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[SECURITY] ")), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["event"] != "security.suspicious_probe" || fields["signal"] != "environment_file" || fields["client_ip_source"] != "unavailable" {
		t.Fatalf("unexpected alert fields: %+v", fields)
	}
}

type securityTestRenderer struct{}

func (securityTestRenderer) Render(_ *echo.Context, w io.Writer, _ string, _ interface{}) error {
	_, err := io.WriteString(w, "test response")
	return err
}

func TestSecurityObserverRunsInProductionRouterForCatchAllAndUnmatchedPaths(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	oldObserver := processSecurityObserver
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(utils.NewAuditJSONFormatter())
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
		processSecurityObserver = oldObserver
	})

	for _, tt := range []struct{ path, wantSignal string }{
		{"/.env", "environment_file"},
		{"/.git/config", "git_metadata"},
	} {
		t.Run(tt.wantSignal, func(t *testing.T) {
			output.Reset()
			processSecurityObserver = newSecurityObserver()
			e := New()
			e.Renderer = securityTestRenderer{}
			r := httptest.NewRequest(http.MethodGet, "https://example.test"+tt.path+"?key=PRIVATE_SHARING_KEY_123", nil)
			r.RemoteAddr = "1.1.1.1:1234"
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, r)
			var alert string
			for _, line := range strings.Split(output.String(), "\n") {
				if strings.HasPrefix(line, "[SECURITY] ") {
					if alert != "" {
						t.Fatal("duplicate security alerts for one request")
					}
					alert = line
				}
			}
			if alert == "" || !strings.Contains(alert, `"event":"security.suspicious_probe"`) || !strings.Contains(alert, `"signal":"`+tt.wantSignal+`"`) {
				t.Fatalf("production router did not report probe: %q", alert)
			}
			if strings.Contains(alert, tt.path) || strings.Contains(output.String(), "PRIVATE_SHARING_KEY_123") {
				t.Fatalf("sensitive request path or query reached logs: %s", output.String())
			}
		})
	}
}

func TestSecurityGlobalTrafficAlertDoesNotAttributeSharedProxy(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(utils.NewAuditJSONFormatter())
	logger.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})

	e := echo.New()
	e.Use(securityObservations(newSecurityObserver()))
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
	for n := 0; n < securityGlobalLimit; n++ {
		r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, r)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("observer changed request status: %d", rec.Code)
		}
	}
	line := strings.TrimSpace(output.String())
	if strings.Count(line, "[SECURITY] ") != 1 || !strings.Contains(line, `"event":"security.high_request_rate"`) || strings.Contains(line, `"client_ip":"127.0.0.1"`) || !strings.Contains(line, `"trigger_request_id":`) {
		t.Fatalf("incorrect aggregate alert: %s", line)
	}
}
