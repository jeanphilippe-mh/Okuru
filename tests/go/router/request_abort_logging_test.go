package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

type trackedResponseWriter struct {
	*httptest.ResponseRecorder
	wrote bool
}

type nonComparablePanic []string

func (nonComparablePanic) Error() string { return "untrusted error" }

func (w *trackedResponseWriter) WriteHeader(status int) {
	w.wrote = true
	w.ResponseRecorder.WriteHeader(status)
}

func (w *trackedResponseWriter) Write(data []byte) (int, error) {
	w.wrote = true
	return w.ResponseRecorder.Write(data)
}

func captureRequestPanic(fn func()) (value any, panicked bool) {
	defer func() {
		if value = recover(); value != nil {
			panicked = true
		}
	}()
	fn()
	return
}

func TestRequestAbortObservationPreservesPanicAndResponse(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})

	const secret = "sensitive-token-and-panic-value"
	ordinary := errors.New(secret)
	for _, tc := range []struct {
		name, event, level string
		value              any
		committed          bool
		protocol           string
	}{
		{"panic before response", "http.request_panic", "error", ordinary, false, "HTTP/1.1"},
		{"panic after response", "http.request_panic", "error", ordinary, true, "HTTP/2.0"},
		{"intentional abort", "http.request_aborted", "warning", http.ErrAbortHandler, true, "HTTP/2.0"},
		{"non-comparable panic", "http.request_panic", "error", []byte(secret), false, "HTTP/1.1"},
		{"slice panic", "http.request_panic", "error", []string{secret}, false, "HTTP/1.1"},
		{"map panic", "http.request_panic", "error", map[string]string{"key": secret}, false, "HTTP/1.1"},
		{"non-comparable error", "http.request_panic", "error", nonComparablePanic{secret}, false, "HTTP/1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output.Reset()
			e := echo.New()
			r := httptest.NewRequest(http.MethodGet, "/test/"+secret+"?password="+secret, nil)
			r.RemoteAddr = "192.0.2.11:1234"
			r.Proto = tc.protocol
			writer := &trackedResponseWriter{ResponseRecorder: httptest.NewRecorder()}
			c := e.NewContext(r, writer)
			c.SetPath("/test/:token")
			fn := observeRequestAbort(func(c *echo.Context) error {
				if tc.committed {
					if err := c.String(http.StatusAccepted, "already written"); err != nil {
						t.Fatal(err)
					}
				}
				panic(tc.value)
			})
			value, panicked := captureRequestPanic(func() { _ = fn(c) })
			if !panicked || !reflect.DeepEqual(value, tc.value) {
				t.Fatalf("panic was swallowed or changed: %#v", value)
			}
			if writer.wrote != tc.committed {
				t.Fatalf("observation changed the response: wrote=%v", writer.wrote)
			}
			if strings.Contains(output.String(), secret) {
				t.Fatal("diagnostic exposed request or panic content")
			}
			var record map[string]any
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatalf("invalid diagnostic: %v", err)
			}
			if record["event"] != tc.event || record["level"] != tc.level || record["route"] != "/test/:token" || record["response_committed"] != tc.committed {
				t.Fatalf("unexpected diagnostic fields: %#v", record)
			}
			if _, exists := record["status"]; exists {
				t.Fatal("unconfirmed HTTP status was recorded")
			}
			if _, ok := record["request_id"].(string); !ok || record["request_id"] == "" {
				t.Fatal("missing request correlation")
			}
		})
	}
}

func TestRequestAbortObservationNilPanicModes(t *testing.T) {
	if mode := os.Getenv("OKURU_TEST_NIL_PANIC_MODE"); mode != "" {
		e := echo.New()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
		returned := false
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_ = observeRequestAbort(func(*echo.Context) error { panic(nil) })(c)
			returned = true
		}()
		if returned {
			t.Fatal("panic(nil) was swallowed")
		}
		if mode == "0" {
			if _, ok := recovered.(*runtime.PanicNilError); !ok {
				t.Fatalf("panic(nil) type changed: %T", recovered)
			}
		} else if recovered != nil {
			t.Fatalf("legacy panic(nil) value changed: %T", recovered)
		}
		return
	}
	for _, mode := range []string{"0", "1"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRequestAbortObservationNilPanicModes$")
		cmd.Env = append(os.Environ(), "GODEBUG=panicnil="+mode, "OKURU_TEST_NIL_PANIC_MODE="+mode)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("panic(nil) subprocess failed in mode %s: %v\n%s", mode, err, output)
		}
	}
}

func TestRequestAbortObservationPreservesGoexit(t *testing.T) {
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	done := make(chan struct{})
	returned := make(chan struct{}, 1)
	go func() {
		defer close(done)
		_ = observeRequestAbort(func(*echo.Context) error {
			runtime.Goexit()
			return nil
		})(c)
		returned <- struct{}{}
	}()
	<-done
	select {
	case <-returned:
		t.Fatal("runtime.Goexit was swallowed")
	default:
	}
}

func TestRequestAbortObservationInProductionRouter(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	e := New()
	original := errors.New("private-panic")
	var handlerRequestID string
	e.GET("/abort-check/:token", func(c *echo.Context) error {
		handlerRequestID = utils.AuditRequestID(c)
		if _, ok := c.Response().(http.Flusher); !ok {
			t.Fatal("response no longer supports flushing")
		}
		panic(original)
	})
	req := httptest.NewRequest(http.MethodGet, "/abort-check/private-token", nil)
	req.RemoteAddr = "192.0.2.11:1234"
	writer := &trackedResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	value, panicked := captureRequestPanic(func() { e.ServeHTTP(writer, req) })
	if !panicked || value != original || writer.wrote {
		t.Fatalf("router changed panic or response: %#v, wrote=%v", value, writer.wrote)
	}
	if strings.Contains(output.String(), "private-token") || strings.Contains(output.String(), "private-panic") {
		t.Fatal("diagnostic exposed private request or panic text")
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("expected exactly one diagnostic, got %q: %v", output.String(), err)
	}
	if record["event"] != "http.request_panic" || record["route"] != "/abort-check/:token" || handlerRequestID == "" || record["request_id"] != handlerRequestID {
		t.Fatalf("incorrect production router diagnostic: %#v", record)
	}
}

type synchronizedAuditBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	wrote  chan struct{}
}

func (w *synchronizedAuditBuffer) Write(data []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(data)
	w.mu.Unlock()
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func (w *synchronizedAuditBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func TestRequestAbortObservationHTTP2CommittedResponse(t *testing.T) {
	t.Run("in-memory", func(t *testing.T) { exerciseCommittedAbort(t, false, true) })
	t.Run("loopback", func(t *testing.T) { exerciseCommittedAbort(t, true, true) })
}

func TestRequestAbortObservationHTTP1CommittedResponse(t *testing.T) {
	t.Run("in-memory", func(t *testing.T) { exerciseCommittedAbort(t, false, false) })
	t.Run("loopback", func(t *testing.T) { exerciseCommittedAbort(t, true, false) })
}

// Exercise both HTTP versions over TLS in memory and, when available, TCP.
func exerciseCommittedAbort(t *testing.T, loopback, http2 bool) {
	t.Helper()
	var listener net.Listener
	if loopback {
		var err error
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("local loopback listener is restricted: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	captured := &synchronizedAuditBuffer{wrote: make(chan struct{}, 4)}
	logger.SetOutput(captured)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	e := New()
	e.GET("/h2-abort/:token", func(c *echo.Context) error {
		if err := c.String(http.StatusAccepted, "partial response"); err != nil {
			return err
		}
		c.Response().(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	var server *httptest.Server
	requestURL := "https://example.com/h2-abort/private-token"
	if loopback {
		server = &httptest.Server{Listener: listener, Config: &http.Server{Handler: e, ErrorLog: utils.NewHTTPDiagnosticLogger(logger)}, EnableHTTP2: http2}
		server.StartTLS()
		requestURL = server.URL + "/h2-abort/private-token"
	} else {
		server = httptest.NewTestServer(t, e)
		server.EnableHTTP2 = http2
		server.Config.ErrorLog = utils.NewHTTPDiagnosticLogger(logger)
	}
	defer server.Close()
	resp, err := server.Client().Get(requestURL)
	if err != nil {
		t.Fatal(err)
	}
	expectedVersion := 1
	if http2 {
		expectedVersion = 2
	}
	if resp.ProtoMajor != expectedVersion || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected committed response: %s %d", resp.Proto, resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body) // The intentionally reset stream may return an error.
	_ = resp.Body.Close()
	select {
	case <-captured.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("abort diagnostic was not written")
	}
	logs := captured.String()
	if strings.Contains(logs, "private-token") {
		t.Fatal("abort diagnostic exposed request token")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(logs), &record); err != nil {
		t.Fatalf("expected exactly one abort diagnostic: %v", err)
	}
	if record["event"] != "http.request_aborted" || record["level"] != "warning" || record["route"] != "/h2-abort/:token" || record["response_committed"] != true {
		t.Fatalf("unexpected HTTP abort diagnostic: %#v", record)
	}
	if _, exists := record["status"]; exists {
		t.Fatal("unconfirmed status was recorded for an aborted response")
	}
}

func TestRequestPanicPreservesHTTP2Connection(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	logger := log.StandardLogger()
	oldOut, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	captured := &synchronizedAuditBuffer{wrote: make(chan struct{}, 8)}
	logger.SetOutput(captured)
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	type connKey struct{}
	var count atomic.Uint64
	connections := make(chan uint64, 2)
	e := New()
	e.GET("/h2-panic/:token", func(c *echo.Context) error {
		connections <- c.Request().Context().Value(connKey{}).(uint64)
		if err := c.String(http.StatusAccepted, "partial response"); err != nil {
			return err
		}
		c.Response().(http.Flusher).Flush()
		panic("private-panic-value")
	})
	e.GET("/h2-success", func(c *echo.Context) error {
		connections <- c.Request().Context().Value(connKey{}).(uint64)
		return c.NoContent(http.StatusNoContent)
	})
	server := httptest.NewTestServer(t, nil)
	server.EnableHTTP2 = true
	server.Config.Handler = e // Preserve the actual net/http panic handler.
	server.Config.ErrorLog = utils.NewHTTPDiagnosticLogger(logger)
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, count.Add(1))
	}
	defer server.Close()
	client := server.Client()
	first, err := client.Get("https://example.com/h2-panic/private-token")
	if err != nil {
		t.Fatal(err)
	}
	if first.ProtoMajor != 2 || first.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected first response: %s %d", first.Proto, first.StatusCode)
	}
	_, _ = io.ReadAll(first.Body) // A reset stream may stop the response body.
	_ = first.Body.Close()
	second, err := client.Get("https://example.com/h2-success")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if second.ProtoMajor != 2 || second.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected second response: %s %d", second.Proto, second.StatusCode)
	}
	firstConn, secondConn := <-connections, <-connections
	if firstConn != secondConn {
		t.Fatalf("HTTP/2 requests used different connections: %d, %d", firstConn, secondConn)
	}
	deadline := time.After(5 * time.Second)
	for {
		logs := captured.String()
		if strings.Contains(logs, "private-token") || strings.Contains(logs, "private-panic-value") {
			t.Fatal("diagnostics exposed a request token or panic value")
		}
		var panicRecords, serverPanicRecords, successfulRecords int
		for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) != nil {
				continue
			}
			switch record["event"] {
			case "http.request_panic":
				panicRecords++
				if _, exists := record["status"]; exists {
					t.Fatal("unconfirmed HTTP status was recorded for panic")
				}
			case "http2.handler_panic":
				serverPanicRecords++
			case "http.request":
				if record["route"] == "/h2-success" && record["status"] == float64(http.StatusNoContent) {
					successfulRecords++
				}
			}
		}
		if panicRecords == 1 && serverPanicRecords == 1 && successfulRecords == 1 {
			break
		}
		select {
		case <-captured.wrote:
		case <-deadline:
			t.Fatalf("missing HTTP/2 events: panic=%d server=%d success=%d", panicRecords, serverPanicRecords, successfulRecords)
		}
	}
}

func TestRequestAbortObservationPreservesReturnedErrors(t *testing.T) {
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	returned := errors.New("returned error")
	err := observeRequestAbort(func(*echo.Context) error { return returned })(c)
	if err != returned {
		t.Fatalf("returned error changed: %v", err)
	}
}

type panicLogWriter struct{}

func (panicLogWriter) Write([]byte) (int, error) { panic("logger failed") }

func TestRequestAbortObservationPreservesPanicWhenLoggingFails(t *testing.T) {
	logger := log.StandardLogger()
	oldOut := logger.Out
	logger.SetOutput(panicLogWriter{})
	t.Cleanup(func() { logger.SetOutput(oldOut) })
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	original := errors.New("original panic")
	value, panicked := captureRequestPanic(func() {
		_ = observeRequestAbort(func(*echo.Context) error { panic(original) })(c)
	})
	if !panicked || value != original {
		t.Fatalf("logger failure changed the original panic: %#v", value)
	}
}
