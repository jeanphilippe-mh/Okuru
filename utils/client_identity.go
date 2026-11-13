package utils

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// ErrClientIdentity indicates that an address or trusted-proxy configuration
// is invalid. Admission must fail closed rather than trust a client header.
var ErrClientIdentity = errors.New("Invalid client identity")

const maxForwardedAddressBytes = 1024
const maxForwardedHops = 16

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// ClientIdentity returns a canonical address for admission decisions.
// Forwarded headers are ignored unless the immediate peer is an explicitly
// trusted proxy. Trusted proxies must append the actual peer to X-Forwarded-For
// or replace that header with a value they generated themselves.
// IPv6 addresses share a /64 budget to limit trivial privacy-address rotation.
func ClientIdentity(r *http.Request) (string, error) {
	if r == nil {
		return "", ErrClientIdentity
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", ErrClientIdentity
	}
	peer, err := parseClientAddress(host)
	if err != nil {
		return "", err
	}
	trusted, err := trustedProxyPrefixes(os.Getenv("OKURU_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return "", err
	}
	if !isTrustedProxy(peer, trusted) {
		return clientAddressBucket(peer), nil
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return clientAddressBucket(peer), nil
	}
	forwarded := strings.Join(values, ",")
	if len(forwarded) == 0 || len(forwarded) > maxForwardedAddressBytes {
		return "", ErrClientIdentity
	}
	hops := strings.Split(forwarded, ",")
	if len(hops) > maxForwardedHops {
		return "", ErrClientIdentity
	}
	// Parse every hop, including ignored ones, so malformed attacker-supplied
	// prefixes cannot produce inconsistent interpretations between processes.
	addresses := make([]netip.Addr, len(hops))
	for i, hop := range hops {
		addresses[i], err = parseClientAddress(strings.TrimSpace(hop))
		if err != nil {
			return "", err
		}
	}
	for i := len(addresses) - 1; i >= 0; i-- {
		if !isTrustedProxy(addresses[i], trusted) || i == 0 {
			return clientAddressBucket(addresses[i]), nil
		}
	}
	return "", ErrClientIdentity
}

func parseClientAddress(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" || !address.IsValid() || address.IsUnspecified() {
		return netip.Addr{}, ErrClientIdentity
	}
	return address.Unmap(), nil
}

func trustedProxyPrefixes(raw string) ([]netip.Prefix, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 64 {
		return nil, ErrClientIdentity
	}
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || prefix.Addr().Zone() != "" || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return nil, ErrClientIdentity
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func isTrustedProxy(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func clientAddressBucket(address netip.Addr) string {
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String()
	}
	return address.String()
}

// SharedClientIdentity conservatively treats private, loopback and link-local
// addresses as potentially representing a reverse proxy or shared gateway.
// Without independently verified forwarding headers they must not receive a
// small per-visitor budget that one requester could exhaust for all users.
func SharedClientIdentity(identity string) bool {
	address, err := netip.ParseAddr(identity)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(identity)
		if prefixErr != nil {
			return true
		}
		address = prefix.Addr()
	}
	address = address.Unmap()
	return !address.IsValid() || address.IsUnspecified() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || carrierGradeNAT.Contains(address)
}
