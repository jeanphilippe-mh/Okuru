package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

func TestSensitiveURLsAreNotLogged(t *testing.T) {
	e := echo.New()
	e.GET("/:password_key", func(c *echo.Context) error {
		route := safeLogRoute(c)
		if route != "/:password_key" || strings.Contains(route, "secret-key") {
			t.Fatalf("unsafe route %q", route)
		}
		return c.NoContent(204)
	})
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/uuid~secret-key?password=private", nil))
	c := e.NewContext(httptest.NewRequest("GET", "/unknown~secret-key", nil), httptest.NewRecorder())
	if safeLogRoute(c) != "unmatched" {
		t.Fatal("unmatched path logged")
	}
	if safeLogError(errors.New("failure at /uuid~secret-key")) != "request failed" {
		t.Fatal("raw error logged")
	}
	if safeLogError(echo.NewHTTPError(400, "private-payload")) != "Bad Request" {
		t.Fatal("HTTP error body logged")
	}
}

// Exercise the production middleware chain, including the request-size
// rejection which runs before CSRF, without a Redis dependency.
func TestHTTPAuditLogUsesSafeRouteAndRecordsRejectedRequests(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(utils.NewAuditJSONFormatter())
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})

	e := New()
	e.GET("/audit-test/:token", func(c *echo.Context) error {
		utils.AuditEvent(c, "test.operation", "Test operation completed")
		return c.NoContent(http.StatusNoContent)
	})
	const secret = "private-token-should-not-appear"
	const forgedID = "attacker-request-id"
	good := httptest.NewRequest(http.MethodGet, "/audit-test/"+secret+"?password="+secret, nil)
	good.RemoteAddr = "198.51.100.27:1234"
	good.Header.Set("X-Request-ID", forgedID)
	good.Header.Set("X-Forwarded-For", "203.0.113.99")
	goodResult := httptest.NewRecorder()
	e.ServeHTTP(goodResult, good)
	if goodResult.Code != http.StatusNoContent {
		t.Fatalf("unexpected test-route status: %d", goodResult.Code)
	}

	oversized := httptest.NewRequest(http.MethodPost, "/api/v1?password="+secret, strings.NewReader(strings.Repeat("x", maxSmallRequestBytes+1)))
	oversized.RemoteAddr = "198.51.100.27:1235"
	oversized.Header.Set("X-Request-ID", forgedID)
	oversizedResult := httptest.NewRecorder()
	e.ServeHTTP(oversizedResult, oversized)
	if oversizedResult.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want 413", oversizedResult.Code)
	}

	contents := output.String()
	for _, forbidden := range []string{secret, forgedID, "/audit-test/" + secret, "203.0.113.99"} {
		if strings.Contains(contents, forbidden) {
			t.Errorf("logs contain an untrusted or sensitive value %q", forbidden)
		}
	}
	var operationID, successfulID, rejectedID string
	requests := 0
	for _, line := range strings.Split(strings.TrimSpace(contents), "\n") {
		if line == "" {
			continue
		}
		payload := line
		var severity string
		for _, label := range []string{"[INFO] ", "[ACTION] ", "[WARNING] ", "[ERROR] "} {
			if strings.HasPrefix(payload, label) {
				severity = label
				payload = strings.TrimPrefix(payload, label)
				break
			}
		}
		if severity == "" {
			t.Fatalf("missing severity prefix: %s", line)
		}
		action := severity == "[ACTION] "
		var record map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			t.Fatalf("invalid structured log: %v", err)
		}
		event, _ := record["event"].(string)
		if event != "http.request" && event != "test.operation" {
			continue
		}
		id, ok := record["request_id"].(string)
		if !ok || id == forgedID {
			t.Fatalf("invalid request identifier: %v", record["request_id"])
		}
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("request identifier is not a UUID: %v", err)
		}
		if record["client_ip"] != "198.51.100.27" || record["peer_ip"] != "198.51.100.27" || record["client_ip_source"] != "peer" {
			t.Errorf("direct request attributed incorrectly: %v", record)
		}
		if event == "test.operation" {
			if !action || severity != "[ACTION] " || record["category"] != "user_action" {
				t.Errorf("user action not clearly marked: %s", line)
			}
			operationID = id
			continue
		}
		requests++
		switch record["status"] {
		case float64(http.StatusNoContent):
			successfulID = id
			if record["route"] != "/audit-test/:token" || record["level"] != "info" {
				t.Errorf("successful request logged incorrectly: %v", record)
			}
		case float64(http.StatusRequestEntityTooLarge):
			rejectedID = id
			if record["route"] != "/api/v1" || record["level"] != "warning" {
				t.Errorf("rejected request logged incorrectly: %v", record)
			}
		default:
			t.Errorf("unexpected logged status: %v", record["status"])
		}
	}
	if requests != 2 || operationID == "" || successfulID != operationID || rejectedID == "" || rejectedID == successfulID {
		t.Fatalf("unexpected request correlation: requests=%d operation=%q success=%q rejected=%q", requests, operationID, successfulID, rejectedID)
	}
}

func TestBoundedRequestLogMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limit       int
		want        string
	}{
		{"unchanged", "normal host", 12, "normal host"},
		{"byte boundary", "aééz", 5, "a..."},
		{"replacement", "a\xffb", 5, "a\ufffdb"},
		{"replacement truncation", "a\xffb", 4, "a..."},
		{"tiny limit", "éé", 1, ""},
		{"zero limit", "abc", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := boundedLogText(tc.input, tc.limit)
			if got != tc.want || len(got) > tc.limit || !utf8.ValidString(got) {
				t.Fatalf("boundedLogText(%q, %d) = %q, want %q", tc.input, tc.limit, got, tc.want)
			}
		})
	}

	// Verify the values remain bounded, valid JSON strings even with control
	// characters and invalid UTF-8. A suffix beyond the limit is not logged.
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	input := "\n\xff" + strings.Repeat("é", 1024) + "secret-beyond-limit"
	logger.Info("http_request",
		slog.String("host", boundedLogText(input, maxLoggedHostBytes)),
		slog.String("user_agent", boundedLogText(input, maxLoggedUserAgentBytes)))
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("log was not valid JSON: %v", err)
	}
	for _, field := range []struct {
		name  string
		limit int
	}{{"host", maxLoggedHostBytes}, {"user_agent", maxLoggedUserAgentBytes}} {
		got, ok := record[field.name].(string)
		if !ok || len(got) > field.limit || !utf8.ValidString(got) || strings.Contains(got, "secret-beyond-limit") {
			t.Fatalf("unsafe %s field %q", field.name, got)
		}
	}
}
