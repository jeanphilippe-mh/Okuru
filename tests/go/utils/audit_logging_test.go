package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

func TestAuditJSONFormatterLevelsAndUTC(t *testing.T) {
	timestamp := time.Date(2026, 11, 15, 14, 3, 4, 123456789, time.FixedZone("UTC+2", 2*60*60))
	for _, tc := range []struct {
		level log.Level
		label string
	}{
		{log.InfoLevel, "[INFO]"},
		{log.WarnLevel, "[WARNING]"},
		{log.ErrorLevel, "[ERROR]"},
		{log.FatalLevel, "[ERROR]"},
		{log.PanicLevel, "[ERROR]"},
		{log.DebugLevel, "[DEBUG]"},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			entry := &log.Entry{
				Logger:  log.New(),
				Data:    log.Fields{"event": "secret.preview"},
				Time:    timestamp,
				Level:   tc.level,
				Message: "Secret page displayed",
			}
			result, err := NewAuditJSONFormatter().Format(entry)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(result, []byte(tc.label+" ")) {
				t.Fatalf("severity does not start the line: %s", result)
			}
			result = bytes.TrimPrefix(result, []byte(tc.label+" "))
			if bytes.Count(result, []byte(`"time":`)) != 1 {
				t.Fatalf("expected exactly one time field: %s", result)
			}
			var record map[string]interface{}
			if err := json.Unmarshal(result, &record); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if got := record["msg"]; got != "Secret page displayed" {
				t.Fatalf("message = %q", got)
			}
			if record["level"] != tc.level.String() || record["event"] != "secret.preview" {
				t.Fatalf("unexpected structured fields: %v", record)
			}
			encodedTime, ok := record["time"].(string)
			if !ok || !strings.HasSuffix(encodedTime, "Z") {
				t.Fatalf("timestamp is not UTC: %v", record["time"])
			}
			parsed, err := time.Parse(time.RFC3339Nano, encodedTime)
			if err != nil || !parsed.Equal(timestamp) {
				t.Fatalf("timestamp = %q, %v; want %s", encodedTime, err, timestamp)
			}
			if entry.Message != "Secret page displayed" || entry.Time.Location().String() != "UTC+2" {
				t.Fatal("formatter mutated the original entry")
			}
		})
	}
}

func TestAuditUserActionsHaveVisibleMarkerAndStructuredCategory(t *testing.T) {
	logger := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(NewAuditJSONFormatter())
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})

	request := httptest.NewRequest(http.MethodGet, "/private-token?password=private", nil)
	request.RemoteAddr = "192.0.2.42:12345"
	context := echo.New().NewContext(request, httptest.NewRecorder())
	cases := []struct {
		name, prefix, outcome, level string
		emit                         func(*echo.Context, string, string)
	}{
		{"preview", "[ACTION] ", "success", "info", AuditEvent},
		{"denied", "[WARNING] ", "failure", "warning", AuditAlert},
		{"failed", "[ERROR] ", "failure", "error", AuditError},
		{"started", "[ACTION] ", "started", "info", AuditStarted},
	}
	var requestID string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.Reset()
			tc.emit(context, "test."+tc.name, "Example action")
			line := output.String()
			if !strings.HasPrefix(line, tc.prefix) {
				t.Fatalf("missing visible action prefix %q: %s", tc.prefix, line)
			}
			var record map[string]interface{}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, tc.prefix)), &record); err != nil {
				t.Fatalf("invalid JSON payload: %v", err)
			}
			if record["category"] != "user_action" || record["event"] != "test."+tc.name || record["outcome"] != tc.outcome || record["level"] != tc.level || record["msg"] != "Example action" {
				t.Fatalf("unexpected action fields: %v", record)
			}
			id, ok := record["request_id"].(string)
			if !ok || id == "" || (requestID != "" && id != requestID) {
				t.Fatalf("invalid request correlation: %v", record["request_id"])
			}
			requestID = id
			if strings.Contains(line, "private-token") || strings.Contains(line, "password=private") {
				t.Fatal("concrete URL or query leaked into action log")
			}
		})
	}
}

func TestAuditJSONFormatterCanBeUsedConcurrently(t *testing.T) {
	formatter := NewAuditJSONFormatter()
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for n := 0; n < 50; n++ {
				entry := &log.Entry{Logger: log.New(), Data: log.Fields{"category": "user_action"}, Time: time.Now(), Level: log.InfoLevel, Message: "Action"}
				line, err := formatter.Format(entry)
				if err != nil || !bytes.HasPrefix(line, []byte("[ACTION] ")) || !json.Valid(bytes.TrimPrefix(line, []byte("[ACTION] "))) {
					t.Errorf("invalid concurrent format: %s (%v)", line, err)
					return
				}
			}
		}()
	}
	group.Wait()
}

func TestAuditRequestFieldsUseTrustedIdentityAndServerRequestID(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,10.0.0.0/8")
	const untrustedID = "attacker-request-id"
	const secret = "private-secret-key"
	e := echo.New()
	var ids []string
	e.GET("/:password_key", func(c *echo.Context) error {
		first := AuditRequestID(c)
		second := AuditRequestID(c)
		fields := AuditRequestFields(c)
		if first != second || fields["request_id"] != first || first == untrustedID {
			t.Errorf("request ID not stable or trusted input leaked: %q, %q, %v", first, second, fields["request_id"])
		}
		if _, err := uuid.Parse(first); err != nil {
			t.Errorf("request ID is not a UUID: %v", err)
		}
		if fields["client_ip"] != "203.0.113.9" || fields["peer_ip"] != "127.0.0.1" || fields["client_ip_source"] != "forwarded" {
			t.Errorf("unexpected trusted proxy identity: %v", fields)
		}
		if fields["route"] != "/:password_key" || fields["method"] != "GET" {
			t.Errorf("unexpected request route or method: %v", fields)
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Error(err)
		}
		for _, sensitive := range []string{secret, untrustedID, "private-cookie", "private-referrer", "private-body"} {
			if strings.Contains(string(encoded), sensitive) {
				t.Errorf("sensitive value %q appeared in structured fields", sensitive)
			}
		}
		ids = append(ids, first)
		return c.NoContent(http.StatusNoContent)
	})
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/"+secret+"?q="+secret, strings.NewReader("private-body"))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "192.0.2.7, 203.0.113.9, 10.2.3.4")
		req.Header.Set("X-Request-ID", untrustedID)
		req.Header.Set("Cookie", "private-cookie")
		req.Header.Set("Referer", "https://example.test/private-referrer")
		response := httptest.NewRecorder()
		e.ServeHTTP(response, req)
		if response.Code != http.StatusNoContent {
			t.Fatalf("unexpected response status: %d", response.Code)
		}
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("separate requests reused the same ID: %v", ids)
	}
}

func TestAuditRequestFieldsRejectUntrustedOrMalformedForwarding(t *testing.T) {
	for _, tc := range []struct {
		name, trusted, peer, forwarded, client, source, peerIP string
	}{
		{"direct ignores spoofed forwarding", "", "198.51.100.8:1234", "203.0.113.99", "198.51.100.8", "peer", "198.51.100.8"},
		{"invalid chain retains peer only", "127.0.0.1/32", "127.0.0.1:1234", "attacker-value", "", "unavailable", "127.0.0.1"},
		{"invalid peer yields no addresses", "", "invalid-peer", "203.0.113.99", "", "unavailable", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", tc.trusted)
			r := httptest.NewRequest("GET", "/private?key=secret", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			c := echo.New().NewContext(r, httptest.NewRecorder())
			fields := AuditRequestFields(c)
			if fields["client_ip_source"] != tc.source || fields["route"] != "unmatched" {
				t.Fatalf("unexpected provenance or route: %v", fields)
			}
			for key, want := range map[string]string{"client_ip": tc.client, "peer_ip": tc.peerIP} {
				got, exists := fields[key]
				if (want == "" && exists) || (want != "" && got != want) {
					t.Errorf("%s = %v, exists=%v; want %q", key, got, exists, want)
				}
			}
		})
	}
}

