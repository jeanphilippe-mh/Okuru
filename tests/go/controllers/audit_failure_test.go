package controllers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

type auditFailureRenderer struct{}

func (auditFailureRenderer) Render(_ *echo.Context, out io.Writer, name string, _ any) error {
	_, err := io.WriteString(out, "rendered "+name)
	return err
}

func captureFailureAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
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
	return &output
}

func failureAuditRecord(t *testing.T, line, wantPrefix, wantEvent string) {
	t.Helper()
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("unexpected audit severity for %s: %q", wantEvent, line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), wantPrefix)), &record); err != nil {
		t.Fatal(err)
	}
	if record["event"] != wantEvent || record["category"] != "user_action" || record["outcome"] != "failure" {
		t.Fatalf("incorrect event or outcome: %#v", record)
	}
	if requestID, ok := record["request_id"].(string); !ok || requestID == "" {
		t.Fatalf("missing request correlation ID: %#v", record)
	}
}

func TestAuditUnavailableDistinguishesInternalFailureWithoutLeakingDetails(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	output := captureFailureAudit(t)
	e := echo.New()
	for _, tc := range []struct {
		status int
		prefix string
	}{
		{http.StatusForbidden, "[WARNING] "},
		{http.StatusNotFound, "[WARNING] "},
		{http.StatusInternalServerError, "[ERROR] "},
		{http.StatusServiceUnavailable, "[ERROR] "},
	} {
		output.Reset()
		ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/secret-do-not-log?key=secret-do-not-log", nil), httptest.NewRecorder())
		auditUnavailable(ctx, echo.NewHTTPError(tc.status, "secret-do-not-log"), "secret.test_unavailable", "Secret unavailable")
		line := output.String()
		failureAuditRecord(t, line, tc.prefix, "secret.test_unavailable")
		if strings.Contains(line, "secret-do-not-log") {
			t.Fatal("audit event included the path, query or error detail")
		}
	}
}

func TestMaskedControllerFailuresRetainPublicStatusesAndLogErrors(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	output := captureFailureAudit(t)
	oldDB, oldSeparator, oldFolder := utils.REDIS_DB, utils.TOKEN_SEPARATOR, utils.FILEFOLDER
	_ = utils.CloseRedisPool()
	utils.REDIS_DB, utils.TOKEN_SEPARATOR, utils.FILEFOLDER = "invalid-db", "~", t.TempDir()
	t.Cleanup(func() {
		_ = utils.CloseRedisPool()
		utils.REDIS_DB, utils.TOKEN_SEPARATOR, utils.FILEFOLDER = oldDB, oldSeparator, oldFolder
	})
	e := echo.New()
	e.Renderer = auditFailureRenderer{}
	const token = "f47ac10b-58cc-4372-a567-0e02b2c3d479~private-decryption-key"
	for _, tc := range []struct {
		name, param, event, template string
		handler                      echo.HandlerFunc
		status                       int
	}{
		{"secret preview", "password_key", "secret.preview_unavailable", "403.html", ReadIndex, http.StatusForbidden},
		{"secret reveal", "password_key", "secret.reveal_unavailable", "", RevealPassword, http.StatusNotFound},
		{"secret API reveal", "password_key", "secret.reveal_unavailable", "", ReadPassword, http.StatusNotFound},
		{"file preview", "file_key", "file.preview_unavailable", "403.html", ReadFile, http.StatusForbidden},
		{"secret delete confirmation", "password_key", "secret.delete_confirmation_unavailable", "404.html", ConfirmDeleteIndex, http.StatusNotFound},
		{"file delete confirmation", "file_key", "file.delete_confirmation_unavailable", "404.html", ConfirmDeleteFile, http.StatusNotFound},
		{"secret delete", "password_key", "secret.delete_unavailable", "403.html", DeleteIndex, http.StatusInternalServerError},
		{"secret API delete", "password_key", "secret.delete_unavailable", "", DeletePassword, http.StatusInternalServerError},
		{"file delete", "file_key", "file.delete_unavailable", "403.html", DeleteFile, http.StatusInternalServerError},
		{"file download", "file_key", "file.download_unavailable", "404.html", DownloadFile, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output.Reset()
			recorder := httptest.NewRecorder()
			ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/private-url-do-not-log", nil), recorder)
			ctx.SetPathValues(echo.PathValues{{Name: tc.param, Value: token}})
			err := tc.handler(ctx)
			status := recorder.Code
			if err != nil {
				status = echo.StatusCode(err)
			}
			if status != tc.status {
				t.Fatalf("public status = %d, want %d (error %v)", status, tc.status, err)
			}
			if tc.template != "" && recorder.Body.String() != "rendered "+tc.template {
				t.Fatalf("public template changed: %q", recorder.Body.String())
			}
			line := output.String()
			failureAuditRecord(t, line, "[ERROR] ", tc.event)
			for _, secret := range []string{token, "private-decryption-key", "private-url-do-not-log", "invalid-db"} {
				if strings.Contains(line, secret) {
					t.Fatalf("audit event leaked protected detail %q", secret)
				}
			}
		})
	}
}
