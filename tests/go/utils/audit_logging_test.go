package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestAuditJSONFormatterPrioritizesProminentMessages(t *testing.T) {
	const text = "Message \"quoted\"\nÉté <tag> 日本 \x1b[31m"
	for _, tc := range []struct {
		name, category, label string
		level                 log.Level
		first                 bool
	}{
		{"action", "user_action", "ACTION", log.InfoLevel, true},
		{"security warning", "security", "SECURITY", log.WarnLevel, true},
		{"security error", "security", "SECURITY", log.ErrorLevel, true},
		{"error", "other", "ERROR", log.ErrorLevel, true},
		{"fatal", "other", "ERROR", log.FatalLevel, true},
		{"panic", "other", "ERROR", log.PanicLevel, true},
		{"info", "other", "INFO", log.InfoLevel, false},
		{"warning", "other", "WARNING", log.WarnLevel, false},
		{"action warning", "user_action", "WARNING", log.WarnLevel, false},
		{"security info", "security", "INFO", log.InfoLevel, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := &log.Entry{
				Logger: log.New(), Time: time.Date(2026, 11, 16, 12, 0, 0, 42, time.UTC),
				Level: tc.level, Message: text,
				Data: log.Fields{"category": tc.category, "event": "test.event", "msg": "field collision", "aaa_nested": map[string]any{"msg": "nested, not the message", "value": 7}},
			}
			got, err := NewAuditJSONFormatter().Format(entry)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "[" + tc.label + "] "
			if !bytes.HasPrefix(got, []byte(prefix)) {
				t.Fatalf("unexpected label: %s", got)
			}
			payload := bytes.TrimPrefix(got, []byte(prefix))
			if bytes.Contains(payload, []byte{0x1b}) {
				t.Fatalf("JSON contains a raw terminal escape: %q", payload)
			}
			if tc.first && !bytes.HasPrefix(payload, []byte(`{"msg":`)) {
				t.Fatalf("message is not the first field: %s", payload)
			}
			original := *entry
			original.Time = original.Time.UTC()
			baseline, err := (&log.JSONFormatter{TimestampFormat: time.RFC3339Nano}).Format(&original)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.first && !bytes.Equal(payload, baseline) {
				t.Fatalf("ordinary record changed: %s; want %s", payload, baseline)
			}
			var actual, expected map[string]any
			if err := json.Unmarshal(payload, &actual); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if err := json.Unmarshal(baseline, &expected); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expected) || actual["msg"] != text || actual["fields.msg"] != "field collision" {
				t.Fatalf("record values changed: got %v, want %v", actual, expected)
			}
		})
	}
}

func TestPrioritizeAuditMessagePreservesRawJSON(t *testing.T) {
	input := []byte("{\"alpha\":{\"msg\":\"nested\"},\"msg\":\"x\\\"y\",\"unicode\":\"\\u003c\"}\n")
	want := "{\"msg\":\"x\\\"y\",\"alpha\":{\"msg\":\"nested\"},\"unicode\":\"\\u003c\"}\n"
	if got := string(prioritizeAuditMessage(input)); got != want {
		t.Fatalf("raw fields changed: got %q, want %q", got, want)
	}
	for _, malformed := range [][]byte{[]byte(`{"other":1}`), []byte(`{"msg":"first","msg":"second"}`), []byte(`{"msg":`)} {
		if got := prioritizeAuditMessage(malformed); !bytes.Equal(got, malformed) {
			t.Fatalf("invalid or ambiguous record changed: got %q, want %q", got, malformed)
		}
	}
}

func TestAuditJSONFormatterEmptyMessageComesFirst(t *testing.T) {
	entry := &log.Entry{Logger: log.New(), Data: log.Fields{"category": "user_action", "event": "test.event"}, Time: time.Now(), Level: log.InfoLevel}
	got, err := NewAuditJSONFormatter().Format(entry)
	if err != nil || !bytes.HasPrefix(got, []byte(`[ACTION] {"msg":"",`)) || !json.Valid(bytes.TrimPrefix(got, []byte("[ACTION] "))) {
		t.Fatalf("empty message record = %q, err = %v", got, err)
	}
}

func TestSecurityAlertKeepsSeverityAndTrustedRequestFields(t *testing.T) {
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
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	request := httptest.NewRequest(http.MethodGet, "/sensitive?token=never-log", nil)
	request.RemoteAddr = "81.2.69.160:12345"
	context := echo.New().NewContext(request, httptest.NewRecorder())
	SecurityAlert(context, "security.probe", "Suspicious request pattern", log.Fields{
		"client_ip": "198.51.100.9", "client_country_code": "FAKE", "client_country_name": "SPOOF", "category": "forged", "event": "forged", "count": 3,
	})
	line := output.String()
	if !strings.HasPrefix(line, "[SECURITY] ") || strings.Contains(line, "never-log") || strings.Contains(line, "198.51.100.9") || strings.Contains(line, "SPOOF") || strings.Contains(line, "FAKE") {
		t.Fatalf("security record leaked data or used untrusted fields: %s", line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[SECURITY] ")), &record); err != nil {
		t.Fatal(err)
	}
	if record["category"] != "security" || record["event"] != "security.probe" || record["level"] != "warning" || record["client_ip"] != "81.2.69.160" {
		t.Fatalf("unexpected security record: %v", record)
	}
	output.Reset()
	SecurityAlert(nil, "security.high_request_rate", "High request rate observed", log.Fields{
		"client_ip": "198.51.100.9", "peer_ip": "127.0.0.1", "client_country_code": "FR", "client_country_name": "France", "request_id": "forged", "trigger_request_id": "trusted-trigger",
	})
	line = output.String()
	for _, forbidden := range []string{"198.51.100.9", "127.0.0.1", `"client_country_code"`, `"client_country_name"`, `"request_id"`} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("global security record falsely attributes a client: %s", line)
		}
	}
	if !strings.Contains(line, `"trigger_request_id":"trusted-trigger"`) {
		t.Fatalf("global alert lost request correlation: %s", line)
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

func TestAuditRequestFieldsUseValidatedClientCountry(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
	if err := ConfigureGeoIPCountry("../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseGeoIPCountry() })

	r := httptest.NewRequest("GET", "/secret-value", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	// The rightmost untrusted hop is the real peer recorded by the trusted
	// proxy; an attacker-controlled leftmost value must not be geolocated.
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 81.2.69.160")
	c := echo.New().NewContext(r, httptest.NewRecorder())
	fields := AuditRequestFields(c)
	if fields["client_ip"] != "81.2.69.160" || fields["peer_ip"] != "127.0.0.1" || fields["client_ip_source"] != "forwarded" {
		t.Fatalf("unexpected trusted client identity: %v", fields)
	}
	if fields["client_country_code"] != "GB" || fields["client_country_name"] != "Royaume-Uni" || fields["client_country_status"] != GeoIPFound {
		t.Fatalf("country not attributed to validated client: %v", fields)
	}
	// Action and HTTP events for the same request retain the same estimate.
	if err := ConfigureGeoIPCountry(""); err != nil {
		t.Fatal(err)
	}
	cached := AuditRequestFields(c)
	if cached["client_country_code"] != "GB" || cached["client_country_status"] != GeoIPFound {
		t.Fatalf("request's country result was not cached: %v", cached)
	}

	local := httptest.NewRequest("GET", "/", nil)
	local.RemoteAddr = "127.0.0.1:1234"
	localFields := AuditRequestFields(echo.New().NewContext(local, httptest.NewRecorder()))
	if localFields["client_country_status"] != GeoIPAddressUnavailable || localFields["client_ip_source"] != "unavailable" || localFields["peer_ip"] != "127.0.0.1" || localFields["client_country_code"] != nil {
		t.Fatalf("loopback was incorrectly attributed to a country: %v", localFields)
	}
}
