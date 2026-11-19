package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	log "github.com/sirupsen/logrus"
)

// Exercise the real API and Redis boundary: audit successes must be emitted
// only for completed actions, and neither bearer links nor payloads may leak.
func TestSecretAuditEventsReflectRealOutcomesWithoutSecrets(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	e := apiContractServer(t) // skips when an isolated Redis instance is unavailable
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

	cookie, csrf := apiCredentials(t, e)
	const secret = "audit-private-password-value"
	created := apiRequest(e, http.MethodPost, "/api/v2/secrets", `{"password":"`+secret+`","ttl_seconds":300,"views":1}`, "application/json", cookie, csrf)
	if created.Code != http.StatusCreated {
		t.Fatalf("create returned %d", created.Code)
	}
	var response struct {
		Link string `json:"api_link"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	link, err := url.Parse(response.Link)
	if err != nil || link.Path == "" {
		t.Fatalf("invalid API link: %v", err)
	}
	first := apiRequest(e, http.MethodGet, link.Path, "", "", nil, "")
	second := apiRequest(e, http.MethodGet, link.Path, "", "", nil, "")
	if first.Code != http.StatusOK || second.Code != http.StatusNotFound {
		t.Fatalf("unexpected reveal statuses: %d, %d", first.Code, second.Code)
	}
	logged := output.String()
	for _, value := range []string{secret, response.Link, link.Path, csrf, cookie.Value} {
		if value != "" && strings.Contains(logged, value) {
			t.Fatal("audit log contains a secret, bearer link or CSRF credential")
		}
	}
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if line == "" {
			continue
		}
		payload := line
		var label string
		for _, candidate := range []string{"[INFO] ", "[ACTION] ", "[WARNING] ", "[ERROR] "} {
			if strings.HasPrefix(payload, candidate) {
				label = candidate
				payload = strings.TrimPrefix(payload, candidate)
				break
			}
		}
		var record map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			t.Fatalf("audit output has invalid JSON payload: %v", err)
		}
		event, _ := record["event"].(string)
		if event != "secret.create" && event != "secret.reveal" && event != "secret.reveal_unavailable" {
			continue
		}
		counts[event]++
		if record["category"] != "user_action" || (record["level"] == "info" && label != "[ACTION] ") {
			t.Errorf("user event lacks action category or prefix: %s", event)
		}
		if record["client_ip"] != "192.0.2.1" || record["client_ip_source"] != "peer" {
			t.Fatalf("%s has incorrect direct client identity: %v", event, record["client_ip_source"])
		}
		if requestID, ok := record["request_id"].(string); !ok || requestID == "" {
			t.Fatalf("%s has no request correlation identifier", event)
		}
		timestamp, ok := record["time"].(string)
		if !ok {
			t.Fatalf("%s has no timestamp", event)
		}
		if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
			t.Fatalf("%s has invalid timestamp: %v", event, err)
		}
	}
	if counts["secret.create"] != 1 || counts["secret.reveal"] != 1 || counts["secret.reveal_unavailable"] != 1 {
		t.Fatalf("unexpected audit event counts: %v", counts)
	}
}
