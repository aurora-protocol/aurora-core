package relay

// Adversarial white-box coverage for the validation and no-network guard
// branches of relay/dns_upstream.go that the existing dns_upstream_test.go
// suite does not reach. dns_upstream.go is pure stdlib (context, fmt, net,
// netip, strconv, strings, time) — no crypto, no aurora-internal packages —
// and every branch below is driven with crafted address strings / contexts
// without any UDP socket.
//
// Constructor (NewUDPDNSMessageResolver):
//   - 22-24: the `TrimSpace(address)=="" || TrimSpace(address)!=address`
//     guard. The existing suite only passes non-empty, already-trimmed
//     addresses, so the "address is required" return is never reached. An
//     empty address exercises the first clause; a whitespace-padded address
//     exercises the second.
//   - 26-28: the net.SplitHostPort error return. The existing non-numeric
//     case ("resolver.example:53") parses host:port fine and fails later at
//     ParseAddr (line 30); an address with no port ("1.2.3.4") makes
//     SplitHostPort itself fail, reaching this branch.
//   - 35-37: the `port == 0 || ParseUint err` guard. Port 0 ("1.2.3.4:0")
//     and a non-numeric port ("1.2.3.4:abc") both reach "port is invalid".
//   - 39-41: the `endpoint.Is6() { network = "udp6" }` branch. The existing
//     happy-path test uses "::ffff:127.0.0.1", which Unmap() folds to an
//     IPv4-mapped address reported as udp4, so the true-IPv6 udp6 assignment
//     is never exercised. A real IPv6 literal ("[::1]:53") reaches it.
//
// ExchangeDNS (no-network guards only):
//   - 50-52: the `r == nil || r.address == "" || r.network == ""` guard. The
//     existing suite only calls ExchangeDNS on a resolver built via the
//     constructor, so the invalid-resolver guard is never reached. A
//     zero-value UDPDNSMessageResolver (empty address/network) hits it.
//   - 53-55: the `ctx == nil` guard. The existing suite always passes a
//     non-nil context.
//   - 56-58: the `ctx.Err() != nil` propagation. A pre-canceled context
//     returns context.Canceled here, before any dial.
//   - 59-61: the `len(query) == 0 || len(query) > maximumSocketDNSBytes`
//     guard. An empty query and an oversized (maximumSocketDNSBytes+1) query
//     both reach "query size is invalid".
//
// Out of scope (real network, post-dial — not coverable without a live UDP
// socket, and intentionally not exercised to keep this PR deterministic and
// network-free):
//   - 63-65: r.dialer.DialContext error.
//   - 67-68: context.AfterFunc deadline wiring (runs only after a successful
//     dial).
//   - 69-71: writeSocketBytes write error.
//   - 75-77: connection.Read error.
//   - 78-80: response-size validation (count == 0 || count > max).
//   The existing TestUDPDNSMessageResolverExchangesBoundedMessage covers the
//   happy dial/write/read path against a real loopback UDP server.
//
// The single new package-level helper, newTestResolver, is referenced by all
// three ExchangeDNS no-network tests (>= 2 references), so there is nothing
// for staticcheck U1000. No new types are introduced. The only network touched
// is the constructor's pure address parsing; ExchangeDNS is exercised solely
// through its pre-dial guards, so no socket is opened.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNewUDPDNSMessageResolverRejectsMalformedAddresses(t *testing.T) {
	cases := []struct {
		name    string
		address string
		wantSub string
	}{
		// 22-24: empty address exercises TrimSpace(address)=="" .
		{"empty", "", "address is required"},
		// 22-24: whitespace padding exercises TrimSpace(address)!=address.
		{"whitespace padded", " 1.2.3.4:53 ", "address is required"},
		// 26-28: no port makes net.SplitHostPort itself fail.
		{"missing port", "1.2.3.4", "address is invalid"},
		// 35-37: port 0 is rejected by the `port == 0` clause.
		{"port zero", "1.2.3.4:0", "port is invalid"},
		// 35-37: non-numeric port is rejected by the ParseUint clause.
		{"port non-numeric", "1.2.3.4:abc", "port is invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewUDPDNSMessageResolver(tc.address)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("NewUDPDNSMessageResolver(%q) err = %v, want substring %q", tc.address, err, tc.wantSub)
			}
		})
	}
}

func TestNewUDPDNSMessageResolverSelectsUDP6ForIPv6(t *testing.T) {
	// A real (non-mapped) IPv6 literal reaches the endpoint.Is6() branch
	// (line 39), selecting the udp6 network. The existing suite only builds
	// IPv4 or IPv4-mapped-IPv6 resolvers, which both report udp4 after Unmap.
	resolver, err := NewUDPDNSMessageResolver("[::1]:53")
	if err != nil {
		t.Fatalf("NewUDPDNSMessageResolver([::1]:53) err = %v, want nil", err)
	}
	if resolver.network != "udp6" {
		t.Fatalf("resolver network = %q, want udp6", resolver.network)
	}
	if resolver.address != "[::1]:53" {
		t.Fatalf("resolver address = %q, want [::1]:53", resolver.address)
	}
}

func newTestResolver(t *testing.T) *UDPDNSMessageResolver {
	t.Helper()
	resolver, err := NewUDPDNSMessageResolver("192.0.2.1:53")
	if err != nil {
		t.Fatalf("NewUDPDNSMessageResolver: %v", err)
	}
	return resolver
}

func TestExchangeDNSRejectsInvalidResolver(t *testing.T) {
	// A zero-value resolver has empty address/network, hitting the 50-52
	// guard before any context or query inspection.
	var zero UDPDNSMessageResolver
	_, err := zero.ExchangeDNS(context.Background(), []byte{0})
	if err == nil || !strings.Contains(err.Error(), "resolver is invalid") {
		t.Fatalf("zero.ExchangeDNS err = %v, want substring \"resolver is invalid\"", err)
	}
}

func TestExchangeDNSRejectsNilContext(t *testing.T) {
	resolver := newTestResolver(t)
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := resolver.ExchangeDNS(nil, []byte{0})
	if err == nil || !strings.Contains(err.Error(), "context is required") {
		t.Fatalf("ExchangeDNS(nil ctx) err = %v, want substring \"context is required\"", err)
	}
}

func TestExchangeDNSRejectsCanceledContext(t *testing.T) {
	resolver := newTestResolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolver.ExchangeDNS(ctx, []byte{0})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ExchangeDNS(canceled ctx) err = %v, want context.Canceled", err)
	}
}

func TestExchangeDNSRejectsInvalidQuerySize(t *testing.T) {
	resolver := newTestResolver(t)

	// 59-61: an empty query hits the `len(query) == 0` clause.
	if _, err := resolver.ExchangeDNS(context.Background(), nil); err == nil ||
		!strings.Contains(err.Error(), "query size is invalid") {
		t.Fatalf("ExchangeDNS(empty) err = %v, want substring \"query size is invalid\"", err)
	}

	// 59-61: an oversized query hits the `len(query) > maximumSocketDNSBytes`
	// clause. No dial occurs because the guard returns first.
	oversized := make([]byte, maximumSocketDNSBytes+1)
	if _, err := resolver.ExchangeDNS(context.Background(), oversized); err == nil ||
		!strings.Contains(err.Error(), "query size is invalid") {
		t.Fatalf("ExchangeDNS(oversized) err = %v, want substring \"query size is invalid\"", err)
	}
}
