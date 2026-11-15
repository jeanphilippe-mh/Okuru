package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// Exercise the actual server configuration without relying on a network port.
// The classical case also verifies compatibility with clients lacking ML-KEM.
func TestServerTLSHybridAndClassicalNegotiation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	for _, group := range []tls.CurveID{tls.X25519MLKEM768, tls.X25519} {
		t.Run(group.String(), func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()
			deadline := time.Now().Add(5 * time.Second)
			_ = serverConn.SetDeadline(deadline)
			_ = clientConn.SetDeadline(deadline)
			config := newServerTLSConfig()
			config.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
			server := tls.Server(serverConn, config)
			client := tls.Client(clientConn, &tls.Config{
				MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				NextProtos: []string{"h2"}, ServerName: "localhost", RootCAs: roots,
				CurvePreferences: []tls.CurveID{group},
			})
			serverResult := make(chan error, 1)
			go func() { serverResult <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client TLS handshake failed: %v", err)
			}
			if err := <-serverResult; err != nil {
				t.Fatalf("server TLS handshake failed: %v", err)
			}
			state := client.ConnectionState()
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || state.CurveID != group {
				t.Fatalf("unexpected TLS negotiation: version=%x ALPN=%q group=%v", state.Version, state.NegotiatedProtocol, state.CurveID)
			}
		})
	}

	t.Run("reject TLS 1.2", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()
		deadline := time.Now().Add(5 * time.Second)
		_ = serverConn.SetDeadline(deadline)
		_ = clientConn.SetDeadline(deadline)
		config := newServerTLSConfig()
		config.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
		server := tls.Server(serverConn, config)
		client := tls.Client(clientConn, &tls.Config{
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			ServerName: "localhost", RootCAs: roots,
		})
		serverResult := make(chan error, 1)
		go func() { serverResult <- server.Handshake() }()
		if err := client.Handshake(); err == nil {
			t.Fatal("TLS 1.2 client unexpectedly connected")
		}
		if err := <-serverResult; err == nil {
			t.Fatal("server unexpectedly accepted TLS 1.2")
		}
	})
}
