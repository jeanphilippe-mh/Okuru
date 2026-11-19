package utils

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func writeWatchdogCertificate(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func independentWatchdogCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"},
		DNSNames: []string{"*.example.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestServiceWatchdogVerifiedTransport(t *testing.T) {
	var answer atomic.Value
	answer.Store(`{"status":"alive"}`)
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" || r.Method != http.MethodGet || r.ProtoMajor != 2 {
			t.Errorf("wrong probe: %s %s %s", r.Method, r.URL.Path, r.Proto)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		io.WriteString(w, answer.Load().(string))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "cert.pem")
	p := watchdogProbe{address: server.Listener.Addr().String(), certificate: path}
	defer p.close()
	check := func(want watchdogState) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if got := p.check(ctx); got != want {
			t.Fatalf("state = %q, want %q", got, want)
		}
	}
	check(watchdogCertificate) // No usable local trust file, but the listener is up.
	writeWatchdogCertificate(t, path, independentWatchdogCertificate(t))
	check(watchdogCertificate) // Reachable, but the peer has another identity.
	writeWatchdogCertificate(t, path, server.Certificate().Raw)
	check(watchdogAlive)
	count := connections.Load()
	check(watchdogAlive)
	if connections.Load() != count {
		t.Fatal("the verified HTTP/2 connection wasn't reused")
	}
	for _, body := range []string{`{"status":"unavailable"}`, `{"status":"alive"} {}`, strings.Repeat(" ", 257)} {
		answer.Store(body)
		check(watchdogUnreachable)
	}
	p.close()
	server.Close()
	check(watchdogUnreachable)
	p.client = nil
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	check(watchdogUnreachable) // Certificate faults must not conceal loss of the listener.
}

func TestServiceWatchdogRefusesUnresponsiveHandler(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	p := watchdogProbe{address: server.Listener.Addr().String(), certificate: filepath.Join(t.TempDir(), "cert.pem")}
	defer p.close()
	for _, scenario := range []string{"malformed", "wrong", "verified"} {
		t.Run(scenario, func(t *testing.T) {
			switch scenario {
			case "malformed":
				if err := os.WriteFile(p.certificate, []byte("invalid PEM"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong":
				writeWatchdogCertificate(t, p.certificate, independentWatchdogCertificate(t))
			case "verified":
				writeWatchdogCertificate(t, p.certificate, server.Certificate().Raw)
			}
			before := requests.Load()
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			defer cancel()
			if got := p.check(ctx); got != watchdogUnreachable || requests.Load() != before+1 {
				t.Fatalf("hung handler: state %q, handled %d new requests", got, requests.Load()-before)
			}
		})
	}
}

func TestServiceWatchdogDegradedLiveness(t *testing.T) {
	var mode atomic.Value
	mode.Store("ok")
	var redirected atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			redirected.Add(1)
			return
		}
		if r.Method != http.MethodGet || r.ProtoMajor != 2 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 ||
			r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" || r.ContentLength != 0 {
			t.Error("unexpected diagnostic request")
		}
		w.Header().Set("Content-Type", "application/json")
		switch mode.Load().(string) {
		case "ok":
			io.WriteString(w, `{"status":"alive"}`)
		case "redirect":
			http.Redirect(w, r, "/private", http.StatusFound)
		default:
			io.WriteString(w, `{"status":"wrong"}`)
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	p := watchdogProbe{address: server.Listener.Addr().String(), certificate: filepath.Join(t.TempDir(), "cert.pem")}
	defer p.close()
	if err := os.WriteFile(p.certificate, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		mode string
		want watchdogState
	}{
		{"ok", watchdogCertificate}, {"redirect", watchdogUnreachable}, {"bad", watchdogUnreachable}, {"ok", watchdogCertificate},
	} {
		mode.Store(step.mode)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got := p.check(ctx)
		cancel()
		if got != step.want || redirected.Load() != 0 {
			t.Fatalf("%s: state %q, redirects %d", step.mode, got, redirected.Load())
		}
	}
}

func TestServiceWatchdogDegradedStalledTLS(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err == nil {
			accepted <- conn
		}
		close(accepted)
	}()
	p := watchdogProbe{address: l.Addr().String(), certificate: filepath.Join(t.TempDir(), "missing")}
	defer p.close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	got := p.check(ctx)
	l.Close()
	conn := <-accepted
	if conn == nil {
		t.Fatal("client did not open the local TCP connection")
	}
	conn.Close()
	if got != watchdogUnreachable {
		t.Fatalf("silent TCP listener returned %q", got)
	}
}

func TestServiceWatchdogStartupAndTransientFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		var state atomic.Value
		state.Store(watchdogUnreachable)
		var messages []string
		go runServiceWatchdog(ctx, 90*time.Second, func(context.Context) watchdogState {
			return state.Load().(watchdogState)
		}, func(message string) {
			messages = append(messages, message)
		})
		time.Sleep(35 * time.Second)
		synctest.Wait()
		if len(messages) != 3 {
			t.Fatalf("30s startup grace: %v", messages)
		}
		time.Sleep(90 * time.Second)
		synctest.Wait()
		if len(messages) != 3 {
			t.Fatal("startup grace was extended")
		}

		for _, step := range []struct {
			state     watchdogState
			heartbeat bool
		}{
			{watchdogAlive, true}, {watchdogUnreachable, false}, {watchdogAlive, true},
			{watchdogCertificate, true}, {watchdogUnreachable, false},
		} {
			state.Store(step.state)
			time.Sleep(10 * time.Second)
			synctest.Wait()
			last := messages[len(messages)-1]
			if strings.Contains(last, "WATCHDOG=1") != step.heartbeat || !strings.Contains(last, "STATUS="+string(step.state)) {
				t.Fatalf("state %q: notification %q", step.state, last)
			}
		}
	})
}

func TestServiceWatchdogSystemdNotifications(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd unixgram transport")
	}
	// Keep the socket path short enough for Darwin's sockaddr_un as well.
	dir, err := os.MkdirTemp("/tmp", "okuru-wd-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"alive"}`)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	oldPort := APP_PORT
	APP_PORT = port
	defer func() { APP_PORT = oldPort }()
	t.Chdir(dir)
	writeWatchdogCertificate(t, "cert.pem", server.Certificate().Raw)
	t.Setenv("NOTIFY_SOCKET", socket)
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("WATCHDOG_USEC", "200000")
	stop := startServiceWatchdog()
	defer stop()
	next := func(timeout time.Duration) (string, error) {
		if err := listener.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1024)
		n, _, err := listener.ReadFromUnix(b)
		return string(b[:n]), err
	}
	message, err := next(time.Second)
	if err != nil || !strings.Contains(message, "WATCHDOG=1") || !strings.Contains(message, "STATUS="+string(watchdogAlive)) {
		t.Fatalf("initial datagram %q, %v", message, err)
	}
	server.Close()
	for {
		message, err = next(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(message, "STATUS="+string(watchdogUnreachable)) {
			break
		}
	}
	if strings.Contains(message, "WATCHDOG=1") {
		t.Fatal("lost origin still acknowledged")
	}
	if message, err = next(250 * time.Millisecond); err == nil {
		t.Fatalf("continued notifications after origin loss: %q", message)
	}
}
