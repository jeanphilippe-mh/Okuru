package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const supervisorFakeAction = `[ACTION] {"category":"user_action","event":"secret.reveal","level":"info","msg":"fake"}`

func TestLogSupervisorWorker(t *testing.T) {
	switch os.Getenv("OKURU_SUPERVISOR_TEST_WORKER") {
	case "exit":
		fmt.Fprintln(os.Stdout, `[INFO] {"event":"worker.started","level":"info","msg":"started"}`)
		fmt.Fprintln(os.Stderr, supervisorFakeAction)
		os.Exit(7)
	case "signal":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
		fmt.Fprintln(os.Stdout, `[INFO] {"event":"worker.ready","level":"info","msg":"ready"}`)
		<-signals
		fmt.Fprintln(os.Stdout, `[INFO] {"event":"worker.stopped","level":"info","msg":"stopped"}`)
		fmt.Fprint(os.Stderr, "final diagnostic without newline")
		os.Exit(0)
	case "flood":
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			for i := 0; i < 200; i++ {
				fmt.Fprintf(os.Stdout, "[INFO] {\"event\":\"worker.bulk\",\"level\":\"info\",\"msg\":\"%s\"}\n", strings.Repeat("x", 900))
			}
		}()
		go func() {
			defer group.Done()
			fmt.Fprintln(os.Stderr, supervisorFakeAction)
			for i := 0; i < 200; i++ {
				fmt.Fprintln(os.Stderr, strings.Repeat("y", 900))
			}
		}()
		group.Wait()
		os.Exit(0)
	case "colors":
		fmt.Fprintln(os.Stdout, `[INFO] {"event":"info","level":"info"}`)
		fmt.Fprintln(os.Stdout, `[WARNING] {"event":"warning","level":"warning"}`)
		fmt.Fprintln(os.Stdout, `[ERROR] {"event":"error","level":"error"}`)
		fmt.Fprintln(os.Stdout, `[ACTION] {"category":"user_action","event":"action","level":"info"}`)
		fmt.Fprintln(os.Stdout, `[SECURITY] {"category":"security","event":"security.example","level":"warning"}`)
		// Untrusted stderr attempts terminal control and action impersonation.
		fmt.Fprintln(os.Stderr, "untrusted \x1b[2J "+supervisorFakeAction)
		os.Exit(0)
	case "banner":
		fmt.Fprint(os.Stdout, EchoStartupOutput(true))
		fmt.Fprint(os.Stderr, EchoStartupOutput(true))
		fmt.Fprintln(os.Stdout, `[INFO] {"event":"worker.started","level":"info"}`)
		os.Exit(0)
	case "closed_stdout":
		_ = os.Setenv("OKURU_SUPERVISOR_TEST_WORKER", "signal")
		code, err := RunLogSupervisor(os.Args[0], []string{"-test.run=^TestLogSupervisorWorker$"}, os.Getenv("OKURU_SUPERVISOR_TEST_LOG"), os.Stdout)
		operation, reason := LogSupervisorFailureFields(err)
		if code != 1 || operation != "write_journal" || reason != "broken_pipe" {
			os.Exit(9)
		}
		os.Exit(0)
	}
}

func TestLogSupervisorExpandsOnlyTrustedBannerFrame(t *testing.T) {
	binary, args := supervisorTestCommand(t, "banner")
	var file, journal bytes.Buffer
	code, err := runLogSupervisor(binary, args, &file, &journal, nil)
	if err != nil || code != 0 {
		t.Fatalf("supervisor exit = %d, %v", code, err)
	}
	if stripLogFileColors(file.String()) != journal.String() {
		t.Fatal("banner and structured logs differ between file and journal")
	}
	if got := strings.Count(journal.String(), EchoStartupBanner()); got != 1 {
		t.Fatalf("got %d complete banners, want exactly one", got)
	}
	if strings.Contains(journal.String(), "\n"+echoBannerControl) || strings.HasPrefix(journal.String(), echoBannerControl) {
		t.Fatal("internal frame leaked as an output line")
	}
	if !strings.Contains(journal.String(), `"event":"process.output"`) || !strings.Contains(journal.String(), `"event":"worker.started"`) {
		t.Fatal("stderr marker or ordinary stdout log was lost")
	}
}

func supervisorTestCommand(t *testing.T, mode string) (string, []string) {
	t.Helper()
	t.Setenv("OKURU_SUPERVISOR_TEST_WORKER", mode)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return binary, []string{"-test.run=^TestLogSupervisorWorker$"}
}

func TestLogSupervisorAppendsAndPreservesWorkerExitStatus(t *testing.T) {
	binary, args := supervisorTestCommand(t, "exit")
	path := filepath.Join(t.TempDir(), "okuru.log")
	if err := os.WriteFile(path, []byte("old record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	code, err := RunLogSupervisor(binary, args, path, &journal)
	if err != nil || code != 7 {
		t.Fatalf("supervisor exit = %d, %v; want 7", code, err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if stripLogFileColors(string(file)) != "old record\n"+journal.String() {
		t.Fatal("file and journal differ or previous content was truncated")
	}
	if !strings.Contains(journal.String(), `"event":"worker.started"`) {
		t.Fatal("structured stdout was lost")
	}
	assertNoForgedAction(t, journal.String())
}

func TestLogSupervisorForwardsSignalAndDrainsFinalOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal forwarding is tested on Unix")
	}
	binary, args := supervisorTestCommand(t, "signal")
	signals := make(chan os.Signal, 1)
	journal := &supervisorTestJournal{ready: make(chan struct{})}
	var file bytes.Buffer
	done := make(chan supervisorResult, 1)
	go func() {
		code, err := runLogSupervisor(binary, args, &file, journal, signals)
		done <- supervisorResult{code: code, err: err}
	}()
	select {
	case <-journal.ready:
	case <-time.After(15 * time.Second):
		t.Fatal("worker did not start")
	}
	signals <- syscall.SIGTERM
	select {
	case result := <-done:
		if result.err != nil || result.code != 0 {
			t.Fatalf("shutdown = %d, %v", result.code, result.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("supervisor did not terminate after SIGTERM")
	}
	output := journal.String()
	if stripLogFileColors(file.String()) != output || !strings.Contains(output, `"event":"worker.stopped"`) || !strings.Contains(output, "final diagnostic without newline") {
		t.Fatalf("shutdown records were lost or destinations differ: %s", output)
	}
}

func TestLogSupervisorDrainsConcurrentLargeStreams(t *testing.T) {
	binary, args := supervisorTestCommand(t, "flood")
	var file, journal bytes.Buffer
	code, err := runLogSupervisor(binary, args, &file, &journal, nil)
	if err != nil || code != 0 {
		t.Fatalf("supervisor exit = %d, %v", code, err)
	}
	if stripLogFileColors(file.String()) != journal.String() {
		t.Fatal("concurrent records differ between file and journal")
	}
	if got := strings.Count(journal.String(), `"event":"worker.bulk"`); got != 200 {
		t.Fatalf("stdout lost records: got %d, want 200", got)
	}
	assertNoForgedAction(t, journal.String())
	var stderrBytes int
	for _, line := range strings.Split(strings.TrimSpace(journal.String()), "\n") {
		if !strings.HasPrefix(line, "[ERROR] ") {
			continue
		}
		var record map[string]interface{}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[ERROR] ")), &record); err != nil {
			t.Fatal(err)
		}
		if text, ok := record["msg"].(string); ok && strings.Trim(text, "y") == "" {
			stderrBytes += len(text)
		}
	}
	if stderrBytes != 200*900 {
		t.Fatalf("stderr lost data: got %d bytes, want %d", stderrBytes, 200*900)
	}
}

func TestLogSupervisorStopsWorkerWhenLogFileFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal forwarding is tested on Unix")
	}
	binary, args := supervisorTestCommand(t, "signal")
	journal := &supervisorTestJournal{ready: make(chan struct{})}
	writeErr := errors.New("injected log file failure")
	done := make(chan supervisorResult, 1)
	go func() {
		code, err := runLogSupervisor(binary, args, failingSupervisorWriter{err: writeErr}, journal, nil)
		done <- supervisorResult{code: code, err: err}
	}()
	select {
	case result := <-done:
		if result.code != 1 || !errors.Is(result.err, writeErr) {
			t.Fatalf("failure not reported: %d, %v", result.code, result.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("worker blocked after log file failure")
	}
	if output := journal.String(); !strings.Contains(output, `"event":"worker.stopped"`) || !strings.Contains(output, "final diagnostic without newline") {
		t.Fatalf("healthy journal did not receive final messages: %s", output)
	}
	output := journal.String()
	if strings.Count(output, `"event":"logging.supervisor_failure"`) != 1 || !strings.Contains(output, `"operation":"write_log"`) || !strings.Contains(output, `"reason_class":"other"`) || strings.Contains(output, writeErr.Error()) {
		t.Fatalf("missing, duplicated or unsafe supervisor alert: %s", output)
	}
}

func TestLogSupervisorStopsWorkerWhenJournalFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal forwarding is tested on Unix")
	}
	binary, args := supervisorTestCommand(t, "signal")
	var file bytes.Buffer
	done := make(chan supervisorResult, 1)
	go func() {
		code, err := runLogSupervisor(binary, args, &file, failingSupervisorWriter{err: syscall.EPIPE}, nil)
		done <- supervisorResult{code: code, err: err}
	}()
	select {
	case result := <-done:
		operation, reason := LogSupervisorFailureFields(result.err)
		if result.code != 1 || operation != "write_journal" || reason != "broken_pipe" {
			t.Fatalf("journal failure not classified: %d, %s, %s", result.code, operation, reason)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("worker blocked after journal failure")
	}
	output := file.String()
	if strings.Count(output, `"event":"logging.supervisor_failure"`) != 1 || !strings.Contains(output, `"operation":"write_journal"`) || !strings.Contains(output, `"reason_class":"broken_pipe"`) || !strings.Contains(output, "final diagnostic without newline") {
		t.Fatalf("healthy file missing categorized alert or final messages: %s", output)
	}
}

func TestLogSupervisorSurvivesClosedStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix SIGPIPE behavior is tested on Unix")
	}
	binary, args := supervisorTestCommand(t, "closed_stdout")
	path := filepath.Join(t.TempDir(), "okuru.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, args...)
	command.Env = append(os.Environ(), "OKURU_SUPERVISOR_TEST_LOG="+path)
	command.Stdout = writer
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("supervisor died when stdout closed: %v, stderr=%s", err, stderr.String())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(content)
	if !strings.Contains(output, `"reason_class":"broken_pipe"`) || !strings.Contains(output, `"operation":"write_journal"`) || !strings.Contains(output, "final diagnostic without newline") {
		t.Fatalf("file missing alert or shutdown diagnostics: %s", output)
	}
}

func TestLogSupervisorDoesNotCreateMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.log")
	var journal bytes.Buffer
	_, err := RunLogSupervisor("unused", nil, path, &journal)
	if err == nil {
		t.Fatal("supervisor silently created a missing log file")
	}
	operation, reason := LogSupervisorFailureFields(err)
	if operation != "open_log" || reason != "missing" || !strings.Contains(journal.String(), `"event":"logging.supervisor_failure"`) {
		t.Fatalf("missing file was not safely reported: %s, %s, %s", operation, reason, journal.String())
	}
}

func assertNoForgedAction(t *testing.T, output string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.HasPrefix(line, "[ACTION]") || strings.HasPrefix(line, "[INFO] [ACTION]") {
			t.Fatalf("stderr impersonated an action: %s", line)
		}
	}
	if !strings.Contains(output, `"event":"process.output"`) || !strings.Contains(output, `secret.reveal`) {
		t.Fatal("stderr diagnostic was lost")
	}
}

type failingSupervisorWriter struct{ err error }

func (w failingSupervisorWriter) Write([]byte) (int, error) { return 0, w.err }

type supervisorTestJournal struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *supervisorTestJournal) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if bytes.Contains(p, []byte(`"event":"worker.ready"`)) {
		w.once.Do(func() { close(w.ready) })
	}
	return w.buf.Write(p)
}

func (w *supervisorTestJournal) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// Only color sequences produced by colorLogPrefix may differ between sinks.
func stripLogFileColors(value string) string {
	return strings.NewReplacer("\x1b[34m", "", "\x1b[38;2;255;165;0m", "", "\x1b[31m", "", "\x1b[1;33m", "", "\x1b[1;38;2;180;180;180m", "", "\x1b[0m", "").Replace(value)
}
