package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPriorityProcessOutputPreservesMessage(t *testing.T) {
	const message = "unexpected \"quoted\" output \\ and é"
	var output bytes.Buffer
	if err := NormalizeUntrustedProcessOutput(strings.NewReader(message+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	line := output.String()
	if !strings.HasPrefix(line, `[ERROR] {"msg":`) {
		t.Fatalf("message is not first: %q", line)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[ERROR] ")), &record); err != nil {
		t.Fatal(err)
	}
	if record["msg"] != message || record["event"] != "process.output" {
		t.Fatalf("incorrect normalized record: %#v", record)
	}
}

func TestPrioritySupervisorAlertAndStructuredOutput(t *testing.T) {
	var output bytes.Buffer
	if err := writeSupervisorAlert(&output, errors.New("test error")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), `[ERROR] {"msg":`) {
		t.Fatalf("supervisor message is not first: %q", output.String())
	}
	output.Reset()
	const original = `[SECURITY] {"category":"security","event":"security.test","level":"warning","msg":"test message"}` + "\n"
	if err := NormalizeProcessOutput(strings.NewReader(original), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), `[SECURITY] {"msg":`) {
		t.Fatalf("structured security message is not first: %q", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(output.String(), "[SECURITY] ")), &record); err != nil {
		t.Fatal(err)
	}
	if record["msg"] != "test message" || record["event"] != "security.test" {
		t.Fatalf("structured output changed: %#v", record)
	}
}

func TestPriorityStructuredOutputWithoutFinalNewline(t *testing.T) {
	const input = `[ERROR] {"event":"test","level":"error","msg":"unfinished line"}`
	var output bytes.Buffer
	if err := NormalizeProcessOutput(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	line := output.String()
	if !strings.HasPrefix(line, `[ERROR] {"msg":"unfinished line",`) || !strings.HasSuffix(line, "\n") {
		t.Fatalf("unterminated structured record was not normalized: %q", line)
	}
}
