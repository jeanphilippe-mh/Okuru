package utils

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIdentityOnlyTrustsConfiguredProxyChain(t *testing.T) {
	tests := []struct {
		name, trusted, peer, forwarded, want string
		invalid                              bool
	}{
		{name: "direct ignores forged header", peer: "198.51.100.5:1234", forwarded: "203.0.113.9", want: "198.51.100.5"},
		{name: "proxy without header shares peer identity", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", want: "127.0.0.1"},
		{name: "one trusted proxy", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", forwarded: "203.0.113.9", want: "203.0.113.9"},
		{name: "attacker prefix ignored", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", forwarded: "192.0.2.7, 203.0.113.9", want: "203.0.113.9"},
		{name: "multiple trusted proxies", trusted: "127.0.0.1/32,10.0.0.0/8", peer: "127.0.0.1:1234", forwarded: "192.0.2.7, 203.0.113.9, 10.2.3.4", want: "203.0.113.9"},
		{name: "mapped IPv4", peer: "[::ffff:192.0.2.8]:1234", want: "192.0.2.8"},
		{name: "IPv6 shares prefix", peer: "[2001:db8:1234:5678::42]:1234", want: "2001:db8:1234:5678::/64"},
		{name: "invalid forwarded", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", forwarded: "invalid, 203.0.113.9", invalid: true},
		{name: "empty forwarded", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", forwarded: " ", invalid: true},
		{name: "too many hops", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", forwarded: strings.Repeat("192.0.2.1,", 16) + "192.0.2.2", invalid: true},
		{name: "universal proxy rejected", trusted: "0.0.0.0/0", peer: "127.0.0.1:1234", invalid: true},
		{name: "bad proxy config", trusted: "localhost", peer: "127.0.0.1:1234", invalid: true},
		{name: "invalid peer", peer: "not-a-peer", invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", tt.trusted)
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			got, err := ClientIdentity(r)
			if tt.invalid {
				if err == nil {
					t.Fatalf("ClientIdentity() = %q, want error", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ClientIdentity() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestClientIdentityHandlesMultipleForwardedHeaders(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "127.0.0.1/32, 10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Add("X-Forwarded-For", "192.0.2.9")
	r.Header.Add("X-Forwarded-For", "203.0.113.4, 10.0.0.1")
	got, err := ClientIdentity(r)
	if err != nil || got != "203.0.113.4" {
		t.Fatalf("ClientIdentity() = %q, %v", got, err)
	}
}

func TestSharedClientIdentityRecognizesProxyAndCarrierNetworks(t *testing.T) {
	for _, identity := range []string{"127.0.0.1", "10.2.3.4", "192.168.0.7", "100.64.3.5", "::/64", "fd00:1234::/64", "invalid"} {
		if !SharedClientIdentity(identity) {
			t.Errorf("%q was not considered potentially shared", identity)
		}
	}
	for _, identity := range []string{"198.51.100.7", "2001:db8:1234::/64"} {
		if SharedClientIdentity(identity) {
			t.Errorf("%q unexpectedly considered shared", identity)
		}
	}
}
