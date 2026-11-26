package utils

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedisTransportPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, host, port, mode, caFile string
		wantLocalhost                  bool
		wantServerName, wantError      string
	}{
		{name: "default localhost", host: "localhost", port: "6379", wantLocalhost: true},
		{name: "absolute localhost", host: "LOCALHOST.", port: "6379", wantLocalhost: true},
		{name: "IPv4 loopback", host: "127.0.0.1", port: "6379", mode: "false"},
		{name: "IPv6 loopback", host: "::1", port: "6379"},
		{name: "mapped loopback", host: "::ffff:127.0.0.1", port: "6379"},
		{name: "remote hostname", host: "redis.internal", port: "6379", wantError: "TLS is required"},
		{name: "private address", host: "192.0.2.20", port: "6379", mode: "false", wantError: "TLS is required"},
		{name: "non-loopback IPv6", host: "2001:db8::20", port: "6379", wantError: "TLS is required"},
		{name: "remote TLS", host: "redis.internal.", port: "6380", mode: "true", wantServerName: "redis.internal"},
		{name: "remote IP TLS", host: "2001:db8::20", port: "6380", mode: "true", wantServerName: "2001:db8::20"},
		{name: "local TLS", host: "localhost", port: "6380", mode: "true", wantLocalhost: true, wantServerName: "localhost"},
		{name: "invalid mode", host: "localhost", port: "6379", mode: "tru", wantError: "must be true or false"},
		{name: "CA without TLS", host: "localhost", port: "6379", caFile: "unused.pem", wantError: "requires Redis TLS"},
		{name: "invalid hostname", host: "redis://localhost", port: "6379", wantError: "Invalid Redis host"},
		{name: "invalid port", host: "localhost", port: "65536", wantError: "Invalid Redis port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := redisPoolConfig{host: tc.host, port: tc.port, tlsMode: tc.mode, tlsCAFile: tc.caFile}
			transport, err := config.transport()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("transport error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil || transport.localhost != tc.wantLocalhost {
				t.Fatalf("transport = %+v, error = %v", transport, err)
			}
			if tc.wantServerName == "" {
				if transport.tls != nil {
					t.Fatal("loopback plaintext should not configure TLS")
				}
				return
			}
			if transport.tls == nil || transport.tls.ServerName != tc.wantServerName || transport.tls.MinVersion != tls.VersionTLS12 || transport.tls.InsecureSkipVerify || transport.tls.RootCAs != nil {
				t.Fatal("TLS must authenticate the expected endpoint using platform trust")
			}
		})
	}
}

func TestRedisTransportInvalidCAFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	config := redisPoolConfig{host: "redis.internal", port: "6380", tlsMode: "true", tlsCAFile: path}
	if _, err := config.transport(); err == nil || !strings.Contains(err.Error(), "Unable to read") {
		t.Fatalf("missing CA file error = %v", err)
	}
	if err := os.WriteFile(path, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.transport(); err == nil || !strings.Contains(err.Error(), "contains no PEM certificates") {
		t.Fatalf("malformed CA file error = %v", err)
	}
}
