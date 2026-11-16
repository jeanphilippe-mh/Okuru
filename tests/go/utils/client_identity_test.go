package utils

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

type clientIdentityRoundTripper func(*http.Request) (*http.Response, error)

func (f clientIdentityRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestAuditDoesNotGeolocateTrustedPublicProxyWithoutForwarding(t *testing.T) {
	if err := ConfigureGeoIPCountry("../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseGeoIPCountry() })
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	r.RemoteAddr = "81.2.69.160:1234"
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "81.2.69.160/32")
	fields := AuditRequestFields(echo.New().NewContext(r, httptest.NewRecorder()))
	if fields["peer_ip"] != "81.2.69.160" || fields["client_ip"] != nil || fields["client_ip_source"] != "unavailable" || fields["client_country_status"] != GeoIPAddressUnavailable || fields["client_country_code"] != nil {
		t.Fatalf("proxy was incorrectly attributed to a visitor: %v", fields)
	}
	if identity, err := ClientIdentity(r); err != nil || identity != "81.2.69.160" {
		t.Fatalf("admission fallback changed: %q, %v", identity, err)
	}

	// The same network peer is a direct client when it has not been
	// configured as a proxy, so its estimated country remains available.
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	direct := AuditRequestFields(echo.New().NewContext(r, httptest.NewRecorder()))
	if direct["client_ip"] != "81.2.69.160" || direct["client_ip_source"] != "peer" || direct["client_country_status"] != GeoIPFound || direct["client_country_code"] != "GB" {
		t.Fatalf("direct client was incorrectly treated as an unavailable proxy: %v", direct)
	}
}

// Simulate a direct reverse proxy, independently appending the remote address
// as Apache's mod_proxy_http2 does. The optional deletion models an Apache
// vhost removing all inbound X-Forwarded-For values before it proxies a request.
// No listening socket or production proxy is used by this test.
func TestClientIdentityAtDirectProxyBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, proxyClient, backendPeer, trusted string
		inbound                                 []string
		clean                                   bool
		wantClient, wantAdmission               string
		wantShared, invalid                     bool
	}{
		{
			name: "IPv4 removes spoofed inbound header", proxyClient: "203.0.113.7:1234", backendPeer: "127.0.0.1:4443", trusted: "127.0.0.1/32",
			inbound: []string{"198.51.100.90, 192.0.2.1", "192.0.2.2"}, clean: true,
			wantClient: "203.0.113.7", wantAdmission: "203.0.113.7",
		},
		{
			name: "IPv4 appended peer wins over forged prefix", proxyClient: "203.0.113.8:1234", backendPeer: "127.0.0.1:4443", trusted: "127.0.0.1/32",
			inbound:    []string{"198.51.100.90, 192.0.2.1"},
			wantClient: "203.0.113.8", wantAdmission: "203.0.113.8",
		},
		{
			name: "IPv6 remote retains address and uses admission bucket", proxyClient: "[2001:db8:cafe:31::1234]:1234", backendPeer: "127.0.0.1:4443", trusted: "127.0.0.1/32",
			inbound: []string{"2001:db8:ffff::1"}, clean: true,
			wantClient: "2001:db8:cafe:31::1234", wantAdmission: "2001:db8:cafe:31::/64",
		},
		{
			name: "trusted IPv6 loopback proxy", proxyClient: "203.0.113.9:1234", backendPeer: "[::1]:4443", trusted: "::1/128",
			inbound: []string{"198.51.100.90"}, clean: true,
			wantClient: "203.0.113.9", wantAdmission: "203.0.113.9",
		},
		{
			name: "LAN visitor remains a shared admission identity", proxyClient: "192.168.1.18:1234", backendPeer: "127.0.0.1:4443", trusted: "127.0.0.1/32",
			inbound: []string{"198.51.100.90"}, clean: true,
			wantClient: "192.168.1.18", wantAdmission: "192.168.1.18", wantShared: true,
		},
		{
			name: "malformed unsanitized prefix fails closed", proxyClient: "203.0.113.10:1234", backendPeer: "127.0.0.1:4443", trusted: "127.0.0.1/32",
			inbound: []string{"attacker-controlled invalid value"}, invalid: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", tc.trusted)
			var address ClientAddress
			var identity string
			var addressErr, identityErr error
			proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "https", Host: "okuru-backend.test"})
			proxy.Transport = clientIdentityRoundTripper(func(outbound *http.Request) (*http.Response, error) {
				// On a real backend connection the Go server sees Apache as
				// RemoteAddr; a custom transport has no real socket to set it.
				outbound.RemoteAddr = tc.backendPeer
				address, addressErr = ResolveClientAddress(outbound)
				identity, identityErr = ClientIdentity(outbound)
				return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: outbound}, nil
			})
			r := httptest.NewRequest(http.MethodGet, "https://share.example.test/", nil)
			r.RemoteAddr = tc.proxyClient
			for _, value := range tc.inbound {
				r.Header.Add("X-Forwarded-For", value)
			}
			if tc.clean {
				r.Header.Del("X-Forwarded-For")
			}
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("proxy status = %d", w.Code)
			}
			if tc.invalid {
				if !errors.Is(addressErr, ErrClientIdentity) || !errors.Is(identityErr, ErrClientIdentity) || address.ClientIP != "" || address.Source != "unavailable" {
					t.Fatalf("malformed forwarding was accepted: address=%+v addressErr=%v identityErr=%v", address, addressErr, identityErr)
				}
				return
			}
			if addressErr != nil || identityErr != nil || address.ClientIP != tc.wantClient || address.Source != "forwarded" || identity != tc.wantAdmission || SharedClientIdentity(identity) != tc.wantShared {
				t.Fatalf("unexpected identity: address=%+v addressErr=%v admission=%q admissionErr=%v", address, addressErr, identity, identityErr)
			}
		})
	}
}

// Loopback is a network address, not proof that Apache initiated a request.
// A different local process can connect directly and supply its own header;
// this test records the trust boundary rather than treating it as authentication.
func TestTrustedLoopbackDoesNotAuthenticateProxyProcess(t *testing.T) {
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
	r := httptest.NewRequest(http.MethodGet, "https://backend.example.test/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.77")
	got, err := ResolveClientAddress(r)
	if err != nil || got.ClientIP != "198.51.100.77" || got.Source != "forwarded" {
		t.Fatalf("documented local-process trust boundary changed: %+v, %v", got, err)
	}
}

func TestResolveClientAddressRespectsProxyBoundary(t *testing.T) {
	tests := []struct {
		name, trusted, peer, forwarded string
		want                           ClientAddress
		invalid                        bool
	}{
		{
			name: "direct client ignores spoofed forwarding", peer: "198.51.100.5:1234", forwarded: "203.0.113.9",
			want: ClientAddress{ClientIP: "198.51.100.5", PeerIP: "198.51.100.5", Source: "peer"},
		},
		{
			name: "trusted peer without forwarding", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234",
			want: ClientAddress{PeerIP: "127.0.0.1", Source: "unavailable"},
		},
		{
			name: "trusted public proxy without forwarding is not visitor", trusted: "81.2.69.160/32", peer: "81.2.69.160:1234",
			want: ClientAddress{PeerIP: "81.2.69.160", Source: "unavailable"},
		},
		{
			name: "trusted IPv6 proxy without forwarding is not visitor", trusted: "2001:218::1/128", peer: "[2001:218::1]:1234",
			want: ClientAddress{PeerIP: "2001:218::1", Source: "unavailable"},
		},
		{
			name: "untrusted direct public peer remains client", peer: "81.2.69.160:1234",
			want: ClientAddress{ClientIP: "81.2.69.160", PeerIP: "81.2.69.160", Source: "peer"},
		},
		{
			name: "trusted proxy selects nearest untrusted hop", trusted: "127.0.0.1/32,10.0.0.0/8", peer: "127.0.0.1:1234", forwarded: "192.0.2.7, 203.0.113.9, 10.2.3.4",
			want: ClientAddress{ClientIP: "203.0.113.9", PeerIP: "127.0.0.1", Source: "forwarded"},
		},
		{
			name: "IPv6 remains full in logs", peer: "[2001:db8:1234:5678::42]:1234",
			want: ClientAddress{ClientIP: "2001:db8:1234:5678::42", PeerIP: "2001:db8:1234:5678::42", Source: "peer"},
		},
		{
			name: "mapped IPv4 canonicalized", peer: "[::ffff:192.0.2.8]:1234",
			want: ClientAddress{ClientIP: "192.0.2.8", PeerIP: "192.0.2.8", Source: "peer"},
		},
		{
			name: "malformed forwarded chain retains only validated peer", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", forwarded: "invalid, 203.0.113.9",
			want: ClientAddress{PeerIP: "127.0.0.1", Source: "unavailable"}, invalid: true,
		},
		{
			name: "invalid trusted configuration retains only peer", trusted: "0.0.0.0/0", peer: "127.0.0.1:1234", forwarded: "203.0.113.9",
			want: ClientAddress{PeerIP: "127.0.0.1", Source: "unavailable"}, invalid: true,
		},
		{
			name: "invalid peer is unavailable", peer: "not-a-peer", forwarded: "203.0.113.9",
			want: ClientAddress{Source: "unavailable"}, invalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", tt.trusted)
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			got, err := ResolveClientAddress(r)
			if got != tt.want {
				t.Fatalf("ResolveClientAddress() = %+v; want %+v", got, tt.want)
			}
			if tt.invalid && !errors.Is(err, ErrClientIdentity) {
				t.Fatalf("ResolveClientAddress() error = %v; want ErrClientIdentity", err)
			}
			if !tt.invalid && err != nil {
				t.Fatalf("ResolveClientAddress() error = %v", err)
			}
		})
	}
	if got, err := ResolveClientAddress(nil); got != (ClientAddress{Source: "unavailable"}) || !errors.Is(err, ErrClientIdentity) {
		t.Fatalf("ResolveClientAddress(nil) = %+v, %v", got, err)
	}
}

func TestClientIdentityOnlyTrustsConfiguredProxyChain(t *testing.T) {
	tests := []struct {
		name, trusted, peer, forwarded, want string
		invalid                              bool
	}{
		{name: "direct ignores forged header", peer: "198.51.100.5:1234", forwarded: "203.0.113.9", want: "198.51.100.5"},
		{name: "proxy without header shares peer identity", trusted: "127.0.0.1/32", peer: "127.0.0.1:1234", want: "127.0.0.1"},
		{name: "public proxy without header preserves admission fallback", trusted: "81.2.69.160/32", peer: "81.2.69.160:1234", want: "81.2.69.160"},
		{name: "IPv6 proxy without header preserves admission bucket", trusted: "2001:218::1/128", peer: "[2001:218::1]:1234", want: "2001:218::/64"},
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
