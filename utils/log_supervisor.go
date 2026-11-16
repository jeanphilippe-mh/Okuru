package utils

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// RunLogSupervisor starts an Okuru worker and copies its stdout and stderr to
// both journal and the existing log file. It forwards stop signals and waits
// for both streams to drain before returning the worker's exit status.
//
// The file is opened without O_CREATE: service initialization creates it with
// the intended ownership and mode, and a missing file must not be overlooked.
func RunLogSupervisor(executable string, args []string, logPath string, journal io.Writer) (int, error) {
	// With the default Go SIGPIPE handler, writing to a closed stdout can
	// terminate the process before Write reports EPIPE. Registering SIGPIPE
	// keeps that failure observable so the worker can be stopped and drained.
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		failure := newSupervisorFailure("open_log", err)
		_ = writeSupervisorAlert(journal, failure)
		return 1, failure
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	code, runErr := runLogSupervisor(executable, args, file, journal, signals)
	closeErr := file.Close()
	if closeErr != nil {
		code = 1
		failure := newSupervisorFailure("close_log", closeErr)
		_ = writeSupervisorAlert(journal, failure)
		return code, errors.Join(runErr, failure)
	}
	return code, runErr
}

type supervisorResult struct {
	code int
	err  error
}

// runLogSupervisor accepts injected writers and signals for subprocess tests.
func runLogSupervisor(executable string, args []string, file, journal io.Writer, signals <-chan os.Signal) (int, error) {
	failures := make(chan error, 2)
	sink := &supervisorSink{file: file, journal: journal, failures: failures, colorFile: logFileColorsEnabled()}
	cmd := exec.Command(executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		failure := newSupervisorFailure("open_worker_stdout", err)
		_ = writeSupervisorAlert(sink, failure)
		return 1, failure
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		failure := newSupervisorFailure("open_worker_stderr", err)
		_ = writeSupervisorAlert(sink, failure)
		return 1, failure
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		failure := newSupervisorFailure("start_worker", err)
		_ = writeSupervisorAlert(sink, failure)
		return 1, failure
	}

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		if err := NormalizeProcessOutput(stdout, sink); err != nil {
			notifySupervisorFailure(failures, newSupervisorFailure("read_worker_stdout", err))
		}
	}()
	go func() {
		defer pumps.Done()
		if err := NormalizeUntrustedProcessOutput(stderr, sink); err != nil {
			notifySupervisorFailure(failures, newSupervisorFailure("read_worker_stderr", err))
		}
	}()

	result := make(chan supervisorResult, 1)
	go func() {
		// StdoutPipe and StderrPipe must be drained before Wait closes them.
		pumps.Wait()
		waitErr := cmd.Wait()
		if waitErr == nil {
			result <- supervisorResult{}
			return
		}
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code := exitErr.ExitCode()
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code = 128 + int(status.Signal())
			}
			if code < 0 {
				code = 1
			}
			result <- supervisorResult{code: code}
			return
		}
		result <- supervisorResult{code: 1, err: newSupervisorFailure("wait_worker", waitErr)}
	}()

	var failure error
	for {
		select {
		case sig, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if err := cmd.Process.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
				failure = errors.Join(failure, newSupervisorFailure("forward_signal", err))
			}
		case err := <-failures:
			failure = errors.Join(failure, err)
			// A failed sink or input must not leave the worker running with
			// missing logs. Keep draining both pipes while it stops.
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
				failure = errors.Join(failure, newSupervisorFailure("stop_worker", err))
			}
		case finished := <-result:
			// A sink error can race with completion. Drain all queued reports.
			for len(failures) > 0 {
				failure = errors.Join(failure, <-failures)
			}
			failure = errors.Join(failure, finished.err)
			if failure != nil {
				_ = writeSupervisorAlert(sink, failure)
				return 1, failure
			}
			return finished.code, nil
		}
	}
}

func notifySupervisorFailure(failures chan<- error, err error) {
	select {
	case failures <- err:
	default:
	}
}

// supervisorSink serializes complete records to both destinations. Once a
// destination fails, it reports the error once and continues draining to the
// other destination while the worker terminates, rather than blocking its pipe.
type supervisorSink struct {
	mu         sync.Mutex
	file       io.Writer
	journal    io.Writer
	failures   chan<- error
	fileFailed bool
	logFailed  bool
	colorFile  bool
}

func (s *supervisorSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.fileFailed {
		fileRecord := p
		if s.colorFile {
			fileRecord = colorLogPrefix(p)
		}
		if err := writeProcessOutput(s.file, fileRecord); err != nil {
			s.fileFailed = true
			notifySupervisorFailure(s.failures, newSupervisorFailure("write_log", err))
		}
	}
	if !s.logFailed {
		if err := writeProcessOutput(s.journal, p); err != nil {
			s.logFailed = true
			notifySupervisorFailure(s.failures, newSupervisorFailure("write_journal", err))
		}
	}
	// Continue consuming child pipes even after a sink failure: the main loop
	// terminates the worker, and remaining records go to any healthy sink.
	return len(p), nil
}

type supervisorFailure struct {
	operation string
	reason    string
	cause     error
}

func (e *supervisorFailure) Error() string {
	return "logging supervisor: " + e.operation + ": " + e.reason
}
func (e *supervisorFailure) Unwrap() error { return e.cause }

func newSupervisorFailure(operation string, err error) error {
	reason := "other"
	switch {
	case errors.Is(err, os.ErrPermission):
		reason = "permission"
	case errors.Is(err, os.ErrNotExist):
		reason = "missing"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		reason = "disk_full"
	case errors.Is(err, syscall.EPIPE):
		reason = "broken_pipe"
	}
	return &supervisorFailure{operation: operation, reason: reason, cause: err}
}

// LogSupervisorFailureFields returns only fixed, safe diagnostic categories;
// the original error is retained for errors.Is without appearing in logs.
func LogSupervisorFailureFields(err error) (operation, reasonClass string) {
	var failure *supervisorFailure
	if errors.As(err, &failure) {
		return failure.operation, failure.reason
	}
	return "unknown", "other"
}

func writeSupervisorAlert(output io.Writer, err error) error {
	operation, reason := LogSupervisorFailureFields(err)
	fields := map[string]string{
		"event":        "logging.supervisor_failure",
		"level":        "error",
		"msg":          "Logging supervision failed",
		"operation":    operation,
		"reason_class": reason,
		"time":         time.Now().UTC().Format(time.RFC3339Nano),
	}
	encoded, marshalErr := json.Marshal(fields)
	if marshalErr != nil {
		return marshalErr
	}
	encoded = prioritizeAuditMessage(encoded)
	line := append([]byte("[ERROR] "), encoded...)
	line = append(line, '\n')
	return writeProcessOutput(output, line)
}
