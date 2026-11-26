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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
)

const redisTLSExamplePassword = "redis-transport-test-password"

type redisTLSFixture struct {
	listener *net.TCPListener
	config   *tls.Config
	caFile   string
}

func newRedisTLSFixture(t *testing.T) redisTLSFixture {
	t.Helper()
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Okuru Redis test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
	}
	return redisTLSFixture{listener: listener, config: config, caFile: caFile}
}

func (fixture redisTLSFixture) accept() (*tls.Conn, error) {
	deadline := time.Now().Add(5 * time.Second)
	if err := fixture.listener.SetDeadline(deadline); err != nil {
		return nil, err
	}
	conn, err := fixture.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tls.Server(conn, fixture.config), nil
}

func (fixture redisTLSFixture) serveRedis(database string) error {
	conn, err := fixture.accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}
	reader := redis.NewConn(conn, time.Second, time.Second)
	for _, step := range []struct {
		command []string
		reply   string
	}{
		{[]string{"AUTH", redisTLSExamplePassword}, "+OK\r\n"},
		{[]string{"SELECT", database}, "+OK\r\n"},
		{[]string{"PING"}, "+PONG\r\n"},
	} {
		command, err := redis.Strings(reader.Receive())
		if err != nil || !slices.Equal(command, step.command) {
			return fmt.Errorf("expected %s after TLS authentication: %v", step.command[0], err)
		}
		if _, err := io.WriteString(conn, step.reply); err != nil {
			return err
		}
	}
	return nil
}

func TestRedisApplicationConnectionsUseVerifiedTLS(t *testing.T) {
	poolTestConfig(t)
	fixture := newRedisTLSFixture(t)
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_FILE", fixture.caFile)
	t.Setenv("OKURU_SHORTLINK_REDIS_DB", "12")
	t.Cleanup(func() { _ = CloseShortLinkPool() })
	REDIS_HOST, REDIS_PASSWORD, REDIS_DB = "localhost", redisTLSExamplePassword, "11"
	_, REDIS_PORT, _ = net.SplitHostPort(fixture.listener.Addr().String())

	for _, tc := range []struct {
		name, database string
		dial           func(context.Context) (redis.Conn, error)
	}{
		{"main pool", "11", NewPool().GetContext},
		{"short link pool", "12", func(ctx context.Context) (redis.Conn, error) {
			pool, err := shortPool()
			if err != nil {
				return nil, err
			}
			return pool.GetContext(ctx)
		}},
		{"archive cleanup", "11", func(ctx context.Context) (redis.Conn, error) {
			return cleanupConnection(ctx, time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := make(chan error, 1)
			go func() { server <- fixture.serveRedis(tc.database) }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := tc.dial(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			pong, err := redis.String(redis.DoContext(conn, ctx, "PING"))
			if err != nil || pong != "PONG" {
				t.Fatalf("PING = %q, %v", pong, err)
			}
			if err := <-server; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRedisTLSRejectsUnverifiedPeers(t *testing.T) {
	fixture := newRedisTLSFixture(t)
	_, port, _ := net.SplitHostPort(fixture.listener.Addr().String())
	for _, tc := range []struct {
		name, host, caFile string
		nameMustMismatch   bool
	}{
		{name: "untrusted authority", host: "localhost"},
		{name: "hostname mismatch", host: "127.0.0.1", caFile: fixture.caFile, nameMustMismatch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := make(chan error, 1)
			go func() {
				conn, err := fixture.accept()
				if err == nil {
					defer conn.Close()
					err = conn.Handshake()
				}
				server <- err
			}()
			config := redisPoolConfig{host: tc.host, port: port, database: "0", password: redisTLSExamplePassword, tlsMode: "true", tlsCAFile: tc.caFile}
			client, err := config.dial(context.Background(), time.Second, time.Second)
			if client != nil {
				_ = client.Close()
				t.Fatal("an unverified Redis peer must never establish an application connection")
			}
			var verifyError *tls.CertificateVerificationError
			if !errors.As(err, &verifyError) {
				t.Fatalf("expected a TLS certificate verification error, got %v", err)
			}
			var hostnameError x509.HostnameError
			if tc.nameMustMismatch && !errors.As(err, &hostnameError) {
				t.Fatalf("expected a TLS hostname mismatch, got %v", err)
			}
			if err := <-server; err == nil {
				t.Fatal("the connection unexpectedly completed the TLS handshake")
			}
		})
	}
}
