package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Only the logging supervisor (systemd's MainPID) sends service notifications.
// systemd owns the deadline, including when this process or its child deadlocks.
func startServiceWatchdog() context.CancelFunc {
	socket := os.Getenv("NOTIFY_SOCKET")
	window, err := time.ParseDuration(os.Getenv("WATCHDOG_USEC") + "us")
	pid := os.Getenv("WATCHDOG_PID")
	if socket == "" || err != nil || window <= 0 || (pid != "" && pid != strconv.Itoa(os.Getpid())) {
		return func() {}
	}
	probe := watchdogProbe{address: net.JoinHostPort("127.0.0.1", APP_PORT), certificate: "cert.pem"}
	ctx, stop := context.WithCancel(context.Background())
	go func() {
		defer probe.close()
		runServiceWatchdog(ctx, window, probe.check, func(message string) {
			// sd_notify supports both filesystem and Linux abstract (@name) sockets.
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "unixgram", socket)
			if err != nil {
				return
			}
			defer conn.Close()
			if conn.SetWriteDeadline(time.Now().Add(time.Second)) == nil {
				_, _ = io.WriteString(conn, message)
			}
		})
	}()
	return stop
}

type watchdogState string

const (
	watchdogAlive       watchdogState = "Echo /ping is responding over verified HTTP/2"
	watchdogUnreachable watchdogState = "Echo /ping is unreachable or returned an invalid response"
	watchdogCertificate watchdogState = "Cannot verify the TLS certificate for local /ping"
)

func runServiceWatchdog(ctx context.Context, window time.Duration, check func(context.Context) watchdogState, notify func(string)) {
	period := min(10*time.Second, window/4)
	startupUntil := time.Now().Add(min(30*time.Second, window/2))
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	var previous watchdogState
	for {
		probeCtx, cancel := context.WithTimeout(ctx, min(period, 3*time.Second))
		state := check(probeCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if state == watchdogAlive {
			startupUntil = time.Time{}
		}
		var fields []string
		if state == watchdogAlive || time.Now().Before(startupUntil) {
			fields = append(fields, "WATCHDOG=1")
		}
		if state != previous {
			fields = append(fields, "STATUS="+string(state))
			previous = state
		}
		if len(fields) > 0 {
			notify(strings.Join(fields, "\n"))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type watchdogProbe struct {
	address, certificate string
	client               *http.Client
	leaf                 *x509.Certificate
}

var errWatchdogCertificateChanged = errors.New("local TLS certificate changed")
var errWatchdogReply = errors.New("invalid local liveness response")

func (p *watchdogProbe) close() {
	if p.client != nil {
		p.client.CloseIdleConnections()
		p.client = nil
		p.leaf = nil
	}
}

func (p *watchdogProbe) clientForOrigin() (*http.Client, error) {
	data, err := os.ReadFile(p.certificate)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid local TLS certificate")
	}
	// Keep the HTTP/2 connection only while the configured identity is current.
	if p.client != nil && bytes.Equal(block.Bytes, p.leaf.Raw) {
		now := time.Now()
		if now.Before(p.leaf.NotBefore) || now.After(p.leaf.NotAfter) {
			return nil, errors.New("local TLS certificate is outside its validity period")
		}
		return p.client, nil
	}
	p.close()
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Both the expected leaf and its name come from the local origin
	// configuration. Never trust a certificate or hostname proposed by a peer.
	var name string
	switch {
	case len(leaf.DNSNames) > 0:
		name = leaf.DNSNames[0]
		if strings.HasPrefix(name, "*.") {
			name = "okuru" + name[1:]
		}
	case len(leaf.IPAddresses) > 0:
		name = leaf.IPAddresses[0].String()
	default:
		return nil, errors.New("local TLS certificate has no subject alternative name")
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	p.leaf = leaf
	p.client = p.localClient(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name,
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 || !bytes.Equal(s.PeerCertificates[0].Raw, leaf.Raw) {
				return errWatchdogCertificateChanged
			}
			return nil
		},
	})
	return p.client, nil
}

func (p *watchdogProbe) localClient(config *tls.Config) *http.Client {
	var dialer net.Dialer
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		Protocols: protocols, TLSClientConfig: config,
		DisableCompression: true, MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Enforce this at the socket boundary as well as in the fixed URL.
			address, err := netip.ParseAddrPort(p.address)
			if err != nil || !address.Addr().IsLoopback() {
				return nil, errors.New("watchdog destination is not a loopback IP")
			}
			return dialer.DialContext(ctx, "tcp", address.String())
		},
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (p *watchdogProbe) check(ctx context.Context) watchdogState {
	client, err := p.clientForOrigin()
	if err != nil {
		p.close()
		return watchdogCertificate
	}
	err = p.readLiveness(ctx, client)
	if err == nil {
		return watchdogAlive
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) || errors.Is(err, errWatchdogCertificateChanged) {
		p.close()
		return watchdogCertificate
	}
	return watchdogUnreachable
}

func (p *watchdogProbe) readLiveness(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+p.address+"/ping", nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.TLS == nil || res.ProtoMajor != 2 || res.StatusCode != http.StatusOK {
		return errWatchdogReply
	}
	// A reused HTTP/2 connection does not repeat the TLS validity check.
	if time.Now().After(res.TLS.PeerCertificates[0].NotAfter) {
		return errWatchdogCertificateChanged
	}
	typ, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return errWatchdogReply
	}
	const maxResponse = 256
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	var reply struct{ Status string }
	if err != nil || len(body) > maxResponse || json.Unmarshal(body, &reply) != nil || reply.Status != "alive" {
		return errWatchdogReply
	}
	return nil
}
