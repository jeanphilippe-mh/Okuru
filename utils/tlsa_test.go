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
	if strings.TrimSpace(output) != `{"success":true}` {
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
		output, err := runTLSATestShell(t, `source "$1"; CF_API_TOKEN="$TEST_TOKEN"; load_api_token`, "TEST_TOKEN="+token)
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
	logPath := filepath.Join(t.TempDir(), "log")
	const untrusted = "UNTRUSTED_ERROR_MARKER"
	script := `
source "$1"
LOG_FILE="$TEST_LOG"
CF_API_TOKEN=test_token
curl() { cat >/dev/null; printf '%s403' "$TEST_RESPONSE"; }
if send_request GET https://invalid.example ''; then exit 1; fi
`
	output, err := runTLSATestShell(t, script,
		"TEST_LOG="+logPath, `TEST_RESPONSE={"errors":[{"message":"`+untrusted+`\nforged log line"}]}`)
	if err != nil {
		t.Fatalf("mock HTTP error was not handled: %v: %s", err, output)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, untrusted) || strings.Contains(string(logBytes), untrusted) || strings.Contains(string(logBytes), "forged log line") {
		t.Fatal("untrusted API error was disclosed or logged")
	}
	if !strings.Contains(string(logBytes), "HTTP 403") {
		t.Fatal("HTTP status was not recorded")
	}
}

func TestTLSAListingFailuresStopUpdate(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is unavailable")
	}
	const recordID = "0123456789abcdef0123456789abcdef"
	cases := []struct {
		name, response, mode, wantActions string
		wantSuccess                       bool
	}{
		{name: "request failure", mode: "fail"},
		{name: "invalid JSON", response: `{`},
		{name: "API failure", response: `{"success":false,"result":[],"result_info":{"total_pages":1}}`},
		{name: "missing pagination", response: `{"success":true,"result":[]}`},
		{name: "multiple pages", response: `{"success":true,"result":[],"result_info":{"total_pages":2}}`},
		{name: "invalid record ID", response: `{"success":true,"result":[{"id":"bad\nforged"}],"result_info":{"total_pages":1}}`},
		{name: "empty listing", response: `{"success":true,"result":[],"result_info":{"total_pages":0}}`, wantSuccess: true},
		{name: "existing record", response: `{"success":true,"result":[{"id":"` + recordID + `"}],"result_info":{"total_pages":1}}`, wantSuccess: true, wantActions: "DELETE\n"},
		{name: "delete failure", mode: "deletefail", response: `{"success":true,"result":[{"id":"` + recordID + `"}],"result_info":{"total_pages":1}}`, wantActions: "DELETE\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actionsPath := filepath.Join(t.TempDir(), "actions")
			script := `
source "$1"
send_request() {
  case "$1" in
    GET) [[ "$TEST_MODE" != fail ]] || return 1; printf '%s' "$TEST_RESPONSE" ;;
    DELETE) printf 'DELETE\n' >> "$TEST_ACTIONS"; [[ "$TEST_MODE" != deletefail ]] ;;
    *) printf 'UNEXPECTED\n' >> "$TEST_ACTIONS"; return 1 ;;
  esac
}

if delete_tlsa_records example.org; then
  [[ "$TEST_SUCCESS" == yes ]] || exit 1
  printf 'CREATE\n' >> "$TEST_ACTIONS"
else
  [[ "$TEST_SUCCESS" == no ]] || exit 1
fi
`
			wantSuccess := "no"
			wantActions := tc.wantActions
			if tc.wantSuccess {
				wantSuccess = "yes"
				wantActions += "CREATE\n"
			}
			output, err := runTLSATestShell(t, script, "TEST_MODE="+tc.mode, "TEST_RESPONSE="+tc.response, "TEST_ACTIONS="+actionsPath, "TEST_SUCCESS="+wantSuccess)
			if err != nil {
				t.Fatalf("unexpected listing outcome: %v: %s", err, output)
			}
			actions, err := os.ReadFile(actionsPath)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if string(actions) != wantActions {
				t.Fatalf("actions = %q, want %q", actions, wantActions)
			}
		})
	}
}

func TestTLSAMutationsRequireSuccessfulJSONResponse(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is unavailable")
	}
	cases := []struct {
		name, deleteBody, postBody, wantActions string
		wantSuccess                             bool
	}{
		{name: "delete rejected", deleteBody: `{"success":false,"errors":[{"message":"UNTRUSTED_MUTATION"}]}`, wantActions: "GET\nDELETE\n"},
		{name: "delete malformed", deleteBody: `{`, wantActions: "GET\nDELETE\n"},
		{name: "delete multiple JSON values", deleteBody: `{"success":false}{"success":true}`, wantActions: "GET\nDELETE\n"},
		{name: "post rejected", deleteBody: `{"success":true}`, postBody: `{"success":false,"errors":[{"message":"UNTRUSTED_MUTATION"}]}`, wantActions: "GET\nDELETE\nPOST\n"},
		{name: "post malformed", deleteBody: `{"success":true}`, postBody: `{`, wantActions: "GET\nDELETE\nPOST\n"},
		{name: "post missing success", deleteBody: `{"success":true}`, postBody: `{}`, wantActions: "GET\nDELETE\nPOST\n"},
		{name: "success", deleteBody: `{"success":true}`, postBody: `{"success":true}`, wantActions: "GET\nDELETE\nPOST\n", wantSuccess: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			actionsPath := filepath.Join(dir, "actions")
			logPath := filepath.Join(dir, "log")
			script := `
source "$1"
LOG_FILE="$TEST_LOG"
CF_API_TOKEN=test_token
curl() {
  cat >/dev/null
  local method=""
  while (( $# )); do
    if [[ "$1" == -X ]]; then method="$2"; break; fi
    shift
  done
  printf '%s\n' "$method" >> "$TEST_ACTIONS"
  case "$method" in
    GET) printf '%s200' '{"success":true,"result":[{"id":"0123456789abcdef0123456789abcdef"}],"result_info":{"total_pages":1}}' ;;
    DELETE) printf '%s200' "$TEST_DELETE_BODY" ;;
    POST) printf '%s200' "$TEST_POST_BODY" ;;
    *) return 1 ;;
  esac
}
tlsa() { printf '%s\n' 'IN TLSA abcdef'; }
if delete_tlsa_records example.org && create_tlsa_record example.org; then
  [[ "$TEST_SUCCESS" == yes ]] || exit 1
else
  [[ "$TEST_SUCCESS" == no ]] || exit 1
fi
`
			wantSuccess := "no"
			if tc.wantSuccess {
				wantSuccess = "yes"
			}
			output, err := runTLSATestShell(t, script,
				"TEST_LOG="+logPath, "TEST_ACTIONS="+actionsPath, "TEST_DELETE_BODY="+tc.deleteBody,
				"TEST_POST_BODY="+tc.postBody, "TEST_SUCCESS="+wantSuccess)
			if err != nil {
				t.Fatalf("unexpected mutation outcome: %v: %s", err, output)
			}
			actions, err := os.ReadFile(actionsPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(actions) != tc.wantActions {
				t.Fatalf("actions = %q, want %q", actions, tc.wantActions)
			}
			if !tc.wantSuccess && strings.Contains(output, "New TLSA record successfully added") {
				t.Fatal("failed operation was announced as successful")
			}
			if !strings.Contains(tc.wantActions, "POST\n") && strings.Contains(output, "TLSA record 0123456789abcdef0123456789abcdef deleted") {
				t.Fatal("failed deletion was announced as successful")
			}
			if strings.Contains(output, "UNTRUSTED_MUTATION") {
				t.Fatal("untrusted API response appeared in output")
			}
			if logBytes, err := os.ReadFile(logPath); err == nil {
				if strings.Contains(string(logBytes), "UNTRUSTED_MUTATION") {
					t.Fatal("untrusted API response appeared in log")
				}
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}
