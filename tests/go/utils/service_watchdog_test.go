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

func newWatchdogCertificate(t *testing.T, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"},
		DNSNames: []string{"*.example.invalid"}, NotBefore: notAfter.Add(-2 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestServiceWatchdogVerifiedTransport(t *testing.T) {
	var answer atomic.Value
	answer.Store(`{"status":"alive"}`)
	notAfter := time.Now().Add(time.Hour)
	first, rotated := newWatchdogCertificate(t, notAfter), newWatchdogCertificate(t, notAfter)
	var served atomic.Pointer[tls.Certificate]
	served.Store(first)
	var connections, requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/ping" || r.Method != http.MethodGet || r.ProtoMajor != 2 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			t.Errorf("wrong probe: %s %s %s", r.Method, r.URL.Path, r.Proto)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" || r.ContentLength != 0 {
			t.Error("health probe carried credentials, a query string or a request body")
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
	server.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return served.Load(), nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "cert.pem")
	p := watchdogProbe{address: server.Listener.Addr().String(), certificate: path}
	defer p.close()
	check := func(want watchdogState) {
		t.Helper()
		before := requests.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if got := p.check(ctx); got != want {
			t.Fatalf("state = %q, want %q", got, want)
		}
		if want == watchdogCertificate && requests.Load() != before {
			t.Fatal("certificate failure sent an HTTP request to the handler")
		}
	}
	check(watchdogCertificate)
	if err := os.WriteFile(path, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	check(watchdogCertificate)
	writeWatchdogCertificate(t, path, rotated.Certificate[0])
	check(watchdogCertificate)
	writeWatchdogCertificate(t, path, first.Certificate[0])
	check(watchdogAlive)
	count := connections.Load()
	check(watchdogAlive)
	if connections.Load() != count {
		t.Fatal("the verified HTTP/2 connection wasn't reused")
	}
	// Replacing the trust file must invalidate a previously verified connection.
	writeWatchdogCertificate(t, path, rotated.Certificate[0])
	check(watchdogCertificate)
	served.Store(rotated)
	check(watchdogAlive)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	check(watchdogCertificate)
	writeWatchdogCertificate(t, path, rotated.Certificate[0])
	check(watchdogAlive)

	expired := newWatchdogCertificate(t, time.Now().Add(-time.Hour))
	served.Store(expired)
	writeWatchdogCertificate(t, path, expired.Certificate[0])
	check(watchdogCertificate)
	served.Store(rotated)
	writeWatchdogCertificate(t, path, rotated.Certificate[0])
	check(watchdogAlive)

	for _, body := range []string{`{"status":"unavailable"}`, `{"status":"alive"} {}`, strings.Repeat(" ", 257)} {
		answer.Store(body)
		check(watchdogUnreachable)
	}
	p.close()
	server.Close()
	check(watchdogUnreachable)
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
	writeWatchdogCertificate(t, p.certificate, server.Certificate().Raw)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := p.check(ctx); got != watchdogUnreachable || requests.Load() != 1 {
		t.Fatalf("hung verified handler: state %q, handled %d requests", got, requests.Load())
	}
}

func TestServiceWatchdogRefusesRedirect(t *testing.T) {
	var probes, redirected atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			probes.Add(1)
			http.Redirect(w, r, "/private", http.StatusFound)
			return
		}
		redirected.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"alive"}`)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	p := watchdogProbe{address: server.Listener.Addr().String(), certificate: filepath.Join(t.TempDir(), "cert.pem")}
	defer p.close()
	writeWatchdogCertificate(t, p.certificate, server.Certificate().Raw)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got := p.check(ctx); got != watchdogUnreachable || probes.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("redirect: state %q, probes %d, followed %d", got, probes.Load(), redirected.Load())
	}
}

func TestServiceWatchdogRequiresHTTP2(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"alive"}`)
	}))
	defer server.Close()
	p := watchdogProbe{address: server.Listener.Addr().String(), certificate: filepath.Join(t.TempDir(), "cert.pem")}
	defer p.close()
	writeWatchdogCertificate(t, p.certificate, server.Certificate().Raw)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got := p.check(ctx); got != watchdogUnreachable {
		t.Fatalf("HTTP/1.1-only server: state %q", got)
	}
}

func TestServiceWatchdogRefusesStalledTLS(t *testing.T) {
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
	p := watchdogProbe{address: l.Addr().String(), certificate: filepath.Join(t.TempDir(), "cert.pem")}
	writeWatchdogCertificate(t, p.certificate, newWatchdogCertificate(t, time.Now().Add(time.Hour)).Certificate[0])
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
		state.Store(watchdogCertificate)
		var messages []string
		go runServiceWatchdog(ctx, 90*time.Second, func(context.Context) watchdogState {
			return state.Load().(watchdogState)
		}, func(message string) {
			messages = append(messages, message)
		})
		time.Sleep(35 * time.Second)
		synctest.Wait()
		if len(messages) != 3 || !strings.Contains(messages[0], "STATUS="+string(watchdogCertificate)) {
			t.Fatalf("30s startup grace: %v", messages)
		}
		for _, message := range messages {
			if !strings.Contains(message, "WATCHDOG=1") {
				t.Fatalf("startup grace omitted heartbeat: %q", message)
			}
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
			{watchdogCertificate, false}, {watchdogUnreachable, false}, {watchdogAlive, true},
		} {
			before := len(messages)
			state.Store(step.state)
			time.Sleep(10 * time.Second)
			synctest.Wait()
			if len(messages) != before+1 {
				t.Fatalf("state %q: new notifications %v", step.state, messages[before:])
			}
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
