package utils

import (
	"bytes"
	"encoding/json"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

type diagnosticBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *diagnosticBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *diagnosticBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func diagnosticTestLogger() (*logrus.Logger, *diagnosticBuffer) {
	var output diagnosticBuffer
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(&output)
	return logger, &output
}

func diagnosticRecord(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("invalid structured diagnostic: %v", err)
	}
	return record
}

func TestHTTPDiagnosticLoggerClassifiesAndProtectsInput(t *testing.T) {
	const secret = "private-password-token-not-for-logs"
	for _, tc := range []struct {
		name, input, event, level, peer, reason, location string
	}{
		{"ping", "timeout waiting for PING response", "http2.ping_timeout", "warning", "", "", ""},
		{"TLS IPv4", "http: TLS handshake error from 127.0.0.1:12345: EOF", "tls.handshake_failed", "warning", "127.0.0.1", "peer_closed", ""},
		{"TLS IPv6", "http: TLS handshake error from [2001:db8::1]:12345: tls: client offered only unsupported versions: [303]", "tls.handshake_failed", "warning", "2001:db8::1", "protocol_version", ""},
		{"TLS unknown", "http: TLS handshake error from 127.0.0.1:12345: " + secret, "tls.handshake_failed", "warning", "127.0.0.1", "other", ""},
		{"untrusted peer", "http: TLS handshake error from " + secret + ": EOF", "tls.handshake_failed", "warning", "", "peer_closed", ""},
		{"unknown diagnostic", "unexpected: /path/" + secret, "http.server_diagnostic", "error", "", "", ""},
		{"HTTP panic", "http: panic serving 127.0.0.1:4443: " + secret + "\ngoroutine 42 [running]:\ngithub.com/jeanphilippe-mh/Okuru/router.TestHandler(0xc000)\n\t/private/path.go:42 +0x12", "http.handler_panic", "error", "127.0.0.1", "", "github.com/jeanphilippe-mh/Okuru/router.TestHandler"},
		{"forged panic stack", "http: panic serving 127.0.0.1:4443: " + secret + "\ngoroutine 3 [running]:\ngithub.com/jeanphilippe-mh/Okuru/fake.Secret()\n\ngoroutine 42 [running]:\ngithub.com/jeanphilippe-mh/Okuru/router.RealHandler(0xc000)\n\t/private/path.go:42", "http.handler_panic", "error", "127.0.0.1", "", "github.com/jeanphilippe-mh/Okuru/router.RealHandler"},
		{"HTTP2 panic", "http2: panic serving [::1]:4443: " + secret + "\ngoroutine 51 [running]:\ngithub.com/jeanphilippe-mh/Okuru/controllers.(*Handler).Run(0xc000)\n\t/private/path.go:42", "http2.handler_panic", "error", "::1", "", "github.com/jeanphilippe-mh/Okuru/controllers.(*Handler).Run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, output := diagnosticTestLogger()
			NewHTTPDiagnosticLogger(logger).Print(tc.input)
			record := diagnosticRecord(t, []byte(output.String()))
			if record["event"] != tc.event || record["level"] != tc.level || record["component"] != "http.server" {
				t.Fatalf("unexpected diagnostic: %v", record)
			}
			for key, expected := range map[string]string{"peer_ip": tc.peer, "reason_class": tc.reason, "panic_function": tc.location} {
				got, present := record[key]
				if expected == "" && present || expected != "" && got != expected {
					t.Errorf("%s = %v, present = %v; want %q", key, got, present, expected)
				}
			}
			if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "/private/path.go") {
				t.Fatal("diagnostic leaked a secret or stack path")
			}
		})
	}
}

func TestHTTPDiagnosticLoggerBoundsOversizedInput(t *testing.T) {
	logger, output := diagnosticTestLogger()
	NewHTTPDiagnosticLogger(logger).Print("http2: panic serving 127.0.0.1:12345: " + strings.Repeat("sensitive", 20_000))
	record := diagnosticRecord(t, []byte(output.String()))
	if record["event"] != "http2.handler_panic" || record["diagnostic_truncated"] != true {
		t.Fatalf("oversized diagnostic was not marked safely: %v", record)
	}
	if strings.Contains(output.String(), "sensitive") {
		t.Fatal("oversized diagnostic leaked its raw contents")
	}
}

func TestHTTPAcceptDiagnosticPreservesSafeCauseAndRetry(t *testing.T) {
	const secret = "private-listener-diagnostic"
	for _, tc := range []struct {
		message, reason, retry string
	}{
		{"accept tcp 127.0.0.1:4443: accept4: too many open files; retrying in 5ms", "file_descriptor_exhaustion", "5ms"},
		{"accept: cannot allocate memory; retrying in 10ms", "memory_exhaustion", "10ms"},
		{"accept: no buffer space available; retrying in 20ms", "buffer_exhaustion", "20ms"},
		{"accept: connection aborted; retrying in 40ms", "connection_aborted", "40ms"},
		{"accept: connection reset by peer; retrying in 80ms", "connection_reset", "80ms"},
		{"accept: network is down; retrying in 160ms", "network_unavailable", "160ms"},
		{"accept: interrupted system call; retrying in 1s", "interrupted", "1s"},
		{"accept: " + secret + "; retrying in 10ms", "other", "10ms"},
		{"accept: " + secret + "; retrying in not-a-duration", "other", ""},
		{"accept: " + secret + "; retrying in 100h", "other", ""},
	} {
		t.Run(tc.reason+"/"+tc.retry, func(t *testing.T) {
			logger, output := diagnosticTestLogger()
			NewHTTPDiagnosticLogger(logger).Printf("http: Accept error: %s", tc.message)
			record := diagnosticRecord(t, []byte(output.String()))
			if record["event"] != "http.accept_failed" || record["level"] != "error" || record["reason_class"] != tc.reason {
				t.Fatalf("unexpected accept diagnostic: %v", record)
			}
			if retry, present := record["retry_delay"]; tc.retry == "" && present || tc.retry != "" && retry != tc.retry {
				t.Errorf("retry_delay = %v, present = %v; want %q", retry, present, tc.retry)
			}
			if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "127.0.0.1:4443") {
				t.Fatal("accept diagnostic leaked raw error details")
			}
		})
	}
}

func TestHTTPDiagnosticLoggerPreservesEventAcrossRealHandlerPanic(t *testing.T) {
	const secret = "private-panic-value-never-log"
	logger, output := diagnosticTestLogger()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(secret) }))
	server.Config.ErrorLog = NewHTTPDiagnosticLogger(logger)
	server.Start()
	defer server.Close()
	response, _ := server.Client().Get(server.URL + "/?secret=" + secret)
	if response != nil {
		response.Body.Close()
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("HTTP handler panic leaked the panic value or URL")
	}
	record := diagnosticRecord(t, []byte(output.String()))
	if record["event"] != "http.handler_panic" || record["level"] != "error" || record["stack_trace_present"] != true {
		t.Fatalf("handler panic diagnostic missing: %v", record)
	}
}

func TestStandardDiagnosticWriterProducesOneSafeEvent(t *testing.T) {
	const secret = "private-standard-log-message"
	logger, output := diagnosticTestLogger()
	standardLogger := stdlog.New(NewStandardDiagnosticWriter(logger), "", 0)
	standardLogger.Print("arbitrary diagnostic " + secret)
	if strings.Contains(output.String(), secret) {
		t.Fatal("the standard logger leaked an untrusted message")
	}
	record := diagnosticRecord(t, []byte(output.String()))
	if record["component"] != "go.standard" || record["event"] != "go.standard_diagnostic" || record["level"] != "warning" {
		t.Fatalf("unexpected standard diagnostic: %v", record)
	}
}
