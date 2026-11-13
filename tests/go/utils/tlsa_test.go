package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runTLSATestShell(t *testing.T, script string, env ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}
	path, err := filepath.Abs("../TLSA_jeanphilippe.io.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script, "tlsa-test", path)
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestTLSATokenIsNotInCurlArgumentsOrEnvironment(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is unavailable")
	}
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	configPath := filepath.Join(dir, "config")
	const token = "test_token-only_for_mock"
	script := `
source "$1"
CF_API_TOKEN="$TEST_TOKEN"
CF_API_TOKEN_FILE=""
export CF_API_TOKEN
load_api_token || exit 1
curl() {
  printf '%s\n' "$@" > "$TEST_ARGS"
  if printenv CF_API_TOKEN >/dev/null; then return 2; fi
  cat > "$TEST_CONFIG"
  printf '{"success":true}200'
}
LOG_FILE="$TEST_LOG"
send_request GET https://invalid.example ''
`
	output, err := runTLSATestShell(t, script,
		"TEST_TOKEN="+token, "TEST_ARGS="+argsPath,
		"TEST_CONFIG="+configPath, "TEST_LOG="+filepath.Join(dir, "log"))
	if err != nil {
		t.Fatalf("mock request failed: %v: %s", err, output)
	}
	if !strings.Contains(output, `{"success":true}`) || strings.Contains(output, token) {
		t.Fatalf("unexpected response from mock request: %q", output)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), token) {
		t.Fatal("token appeared in curl arguments")
	}
	if !strings.Contains(string(args), "--config\n-\n") {
		t.Fatal("curl did not use its standard-input configuration")
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != "header = \"Authorization: Bearer "+token+"\"\n" {
		t.Fatal("curl did not receive the expected header through standard input")
	}
}

func TestTLSATokenRejectsCurlConfigInjection(t *testing.T) {
	for _, token := range []string{"line\nbreak", "line\rbreak", "a\tb", `quote"`, `back\slash`} {
		output, err := runTLSATestShell(t, `source "$1"; CF_API_TOKEN_FILE=""; CF_API_TOKEN="$TEST_TOKEN"; load_api_token`, "TEST_TOKEN="+token)
		if err == nil {
			t.Fatal("unsafe token was accepted")
		}
		if strings.Contains(output, token) {
			t.Fatal("rejected token appeared in an error message")
		}
	}
}

func TestTLSATokenFileMustBePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test_token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `source "$1"; CF_API_TOKEN=""; CF_API_TOKEN_FILE="$TEST_FILE"; load_api_token; [[ "$CF_API_TOKEN" == test_token ]]`
	if output, err := runTLSATestShell(t, script, "TEST_FILE="+path); err != nil {
		t.Fatalf("private token file rejected: %v: %s", err, output)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTLSATestShell(t, script, "TEST_FILE="+path); err == nil {
		t.Fatal("group/world-readable token file accepted")
	}
}

func TestTLSARequestDoesNotLogUntrustedAPIError(t *testing.T) {
	const untrusted = "UNTRUSTED_ERROR_MARKER"
	script := `
source "$1"
CF_API_TOKEN=test_token
curl() { cat >/dev/null; printf '%s403' "$TEST_RESPONSE"; }
if send_request GET https://invalid.example ''; then exit 1; fi
`
	output, err := runTLSATestShell(t, script,
		`TEST_RESPONSE={"errors":[{"message":"`+untrusted+`\nforged log line"}]}`)
	if err != nil {
		t.Fatalf("mock HTTP error was not handled: %v: %s", err, output)
	}
	if strings.Contains(output, untrusted) || strings.Contains(output, "forged log line") {
		t.Fatal("untrusted API error was disclosed or logged")
	}
	if !strings.Contains(output, "HTTP 403") {
		t.Fatal("HTTP status was not recorded")
	}
}

func TestTLSAListingRejectsInvalidCloudflareResponses(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is unavailable")
	}
	const validRecord = `{"id":"0123456789abcdef0123456789abcdef","type":"TLSA","name":"_443._tcp.example.org","data":{"usage":3,"selector":1,"matching_type":1,"certificate":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	cases := []struct {
		name, response string
		wantSuccess    bool
	}{
		{name: "invalid JSON", response: `{`},
		{name: "API failure", response: `{"success":false,"result":[],"result_info":{"total_pages":1}}`},
		{name: "missing pagination", response: `{"success":true,"result":[]}`},
		{name: "multiple pages", response: `{"success":true,"result":[],"result_info":{"total_pages":2}}`},
		{name: "invalid record ID", response: `{"success":true,"result":[{"id":"bad"}],"result_info":{"total_pages":1}}`},
		{name: "missing contents", response: `{"success":true,"result":[{"id":"0123456789abcdef0123456789abcdef","type":"TLSA","name":"_443._tcp.example.org"}],"result_info":{"total_pages":1}}`},
		{name: "empty listing", response: `{"success":true,"result":[],"result_info":{"total_pages":0}}`, wantSuccess: true},
		{name: "valid record", response: `{"success":true,"result":[` + validRecord + `],"result_info":{"total_pages":1}}`, wantSuccess: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := `
source "$1"
send_request() { printf '%s' "$TEST_RESPONSE"; }
if fetch_tlsa_records example.org >/dev/null; then
  [[ "$TEST_SUCCESS" == yes ]] || exit 1
else
  [[ "$TEST_SUCCESS" == no ]] || exit 1
fi
`
			wantSuccess := "no"
			if tc.wantSuccess {
				wantSuccess = "yes"
			}
			output, err := runTLSATestShell(t, script, "TEST_RESPONSE="+tc.response, "TEST_SUCCESS="+wantSuccess)
			if err != nil {
				t.Fatalf("unexpected listing outcome: %v: %s", err, output)
			}
		})
	}
}

func TestTLSAMutationsRequireSuccessfulJSONResponse(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is unavailable")
	}
	cases := []struct {
		name, body  string
		wantSuccess bool
	}{
		{name: "API rejection", body: `{"success":false,"errors":[{"message":"UNTRUSTED_MUTATION"}]}`},
		{name: "malformed", body: `{`},
		{name: "multiple JSON values", body: `{"success":false}{"success":true}`},
		{name: "missing success", body: `{}`},
		{name: "success", body: `{"success":true}`, wantSuccess: true},
	}
	for _, method := range []string{"DELETE", "POST"} {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				script := `
source "$1"
CF_API_TOKEN=test_token
MAX_RETRIES=1
curl() { cat >/dev/null; printf '%s200' "$TEST_BODY"; }
if send_request "$TEST_METHOD" https://invalid.example '{}'; then
  [[ "$TEST_SUCCESS" == yes ]] || exit 1
else
  [[ "$TEST_SUCCESS" == no ]] || exit 1
fi
`
				wantSuccess := "no"
				if tc.wantSuccess {
					wantSuccess = "yes"
				}
				output, err := runTLSATestShell(t, script, "TEST_METHOD="+method, "TEST_BODY="+tc.body, "TEST_SUCCESS="+wantSuccess)
				if err != nil {
					t.Fatalf("unexpected mutation outcome: %v: %s", err, output)
				}
				if strings.Contains(output, "UNTRUSTED_MUTATION") {
					t.Fatal("untrusted API response appeared in output")
				}
			})
		}
	}
}
