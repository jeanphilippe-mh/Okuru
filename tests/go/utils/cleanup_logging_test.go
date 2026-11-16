package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

func TestCleanupDiagnosticClassifiesWithoutLeakingErrors(t *testing.T) {
	logger := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	const secret = "private-path-and-token"
	for _, tc := range []struct {
		name   string
		err    error
		reason string
	}{
		{"wrapped EOF", fmt.Errorf("%s: %w", secret, io.EOF), "eof"},
		{"redis", redis.Error(secret), "redis_error"},
		{"unknown", errors.New(secret), "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output.Reset()
			logCleanupFailure("archive.test", "Archive test failure", tc.err)
			if strings.Contains(output.String(), secret) {
				t.Fatal("raw error content leaked to the log")
			}
			var record map[string]any
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["event"] != "archive.test" || record["reason_class"] != tc.reason || record["level"] != "warning" {
				t.Fatalf("unexpected cleanup diagnostic: %#v", record)
			}
			if _, ok := record["error"]; ok {
				t.Fatal("raw error field must not be recorded")
			}
		})
	}
}
