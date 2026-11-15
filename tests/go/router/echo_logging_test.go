package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

func TestEchoDiagnosticsUseApplicationLoggerWithoutSensitiveValues(t *testing.T) {
	logger := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})

	e := New()
	const secret = "private-token-in-error"
	e.Logger.With("error", echo.NewHTTPError(400, secret)).WithGroup("response").Error(
		"echo default error handler failed to send error to client", "url", "/"+secret)
	e.Logger.Warn("untrusted "+secret, "details", secret)
	e.Logger.Debug("disabled")

	if strings.Contains(output.String(), secret) {
		t.Fatal("Echo diagnostic leaked sensitive message or attribute")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d diagnostics, expected two", len(lines))
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["event"] != "echo.diagnostic" || first["source"] != "echo" || first["level"] != "error" || first["error"] != "Bad Request" || first["msg"] != "Echo error handler failed to send response" {
		t.Fatalf("unexpected Echo diagnostic: %v", first)
	}
	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if second["level"] != "warning" || second["msg"] != "Echo diagnostic" {
		t.Fatalf("unexpected generic diagnostic: %v", second)
	}
}

func TestEchoHandlerCopiesAttrsAndGroups(t *testing.T) {
	base := &echoLogHandler{}
	one := base.WithAttrs([]slog.Attr{slog.Any("error", errors.New("private value"))})
	_ = one.WithGroup("group").WithAttrs([]slog.Attr{slog.String("ignored", "private")})
	if len(base.attrs) != 0 {
		t.Fatal("derived handler mutated original attrs")
	}
}

func TestEnvironmentDiagnosticsOmitArbitraryValues(t *testing.T) {
	logger := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	oldPassword, oldCopyright, oldDisclaimer, oldPrefix, oldCompression, oldPort := utils.REDIS_PASSWORD, utils.COPYRIGHT, utils.DISCLAIMER, utils.REDIS_PREFIX, utils.ZIP_COMPRESSION, utils.APP_PORT
	const secret = "private-env-value"
	utils.REDIS_PASSWORD, utils.COPYRIGHT, utils.DISCLAIMER, utils.REDIS_PREFIX, utils.ZIP_COMPRESSION, utils.APP_PORT = secret, secret, secret, secret, secret, secret
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		utils.REDIS_PASSWORD, utils.COPYRIGHT, utils.DISCLAIMER, utils.REDIS_PREFIX, utils.ZIP_COMPRESSION, utils.APP_PORT = oldPassword, oldCopyright, oldDisclaimer, oldPrefix, oldCompression, oldPort
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	utils.LogConfiguration()
	if strings.Contains(output.String(), secret) {
		t.Fatal("configuration log leaked an arbitrary environment value")
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["event"] != "configuration.loaded" || record["redis_password_configured"] != true {
		t.Fatalf("unexpected configuration diagnostic: %v", record)
	}
}

func TestSafeEchoErrorCategories(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, "request canceled"},
		{context.DeadlineExceeded, "deadline exceeded"},
		{errors.New("private-value"), "request failed"},
	} {
		if got := safeEchoError(tc.err); got != tc.want {
			t.Fatalf("safe error category = %q; want %q", got, tc.want)
		}
	}
}
