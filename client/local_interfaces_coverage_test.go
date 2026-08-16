package client

// Adversarial coverage for client/local_interfaces.go (the SOCKS5 / HTTP-CONNECT
// local-interface parser). Most uncovered ranges are reachable malformed-input
// branches in the pure parser functions (HandleSOCKS5Greeting, socks5BindResponse,
// parseAuthority, parseSOCKS5RequestWithOptions, parseSOCKS5UDPHeader,
// parseSOCKS5Address) plus the method error branches that fire before any
// LocalProxy flow state is touched (OpenHTTPConnectRequest, OpenSOCKS5ConnectRequest,
// HandleSOCKS5UDPDatagramFrames).
//
// Dead by design (documented, not contrived):
//   - socks5BindResponse:160-161 (default "unsupported SOCKS5 bind target"):
//     localTarget (client.go:191) only ever returns TargetKindIPv4, TargetKindIPv6,
//     TargetKindDomainName, or an error. It can never return an unknown kind, so the
//     switch default in socks5BindResponse is unreachable for any bindHost that
//     survives the preceding localTarget call.
//
// Deferred (reachable only via fragile flow-expiry state engineering):
//   - HandleSOCKS5UDPDatagramFrames:129-131 (SendUDPWithOptions error): by the time
//     SendUDPWithOptions is reached, ensureSOCKS5UDPFlowFrame has guaranteed the flow
//     exists and is a UDP association, and the udpMode was already validated at
//     117-119. SendUDPWithOptions can only error on an unsupported udpMode (filtered),
//     an unavailable/non-UDP flow (both ruled out by the prior ensure call), or a
//     TTL/idle expiry racing between FlowState and AcceptDatagramWithOptions under a
//     jumped `now`. That last path is real but fragile and not worth the test hazard.
//
// Helper names are socks5-prefixed to avoid collisions with
// native_provisioning_trust_coverage_test.go (same package client).

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/transport"
)

const (
	socks5CoverageAtypIPv4   = 0x01
	socks5CoverageAtypDomain  = 0x03
	socks5CoverageAtypIPv6    = 0x04
	socks5CoverageCmdConnect  = 0x01
	socks5CoverageCmdUDPAssoc = 0x03
)

// socks5Greeting builds a SOCKS5 client greeting [VER, NMETHODS, METHODS...].
func socks5Greeting(methods ...byte) []byte {
	g := make([]byte, 0, 2+len(methods))
	g = append(g, 0x05, byte(len(methods)))
	g = append(g, methods...)
	return g
}

// socks5Request builds a SOCKS5 request [VER, CMD, RSV, ATYP, ADDR, PORT].
func socks5Request(cmd, atyp byte, addr []byte, port uint16) []byte {
	r := make([]byte, 0, 4+len(addr)+2)
	r = append(r, 0x05, cmd, 0x00, atyp)
	r = append(r, addr...)
	r = append(r, byte(port>>8), byte(port))
	return r
}

// socks5DomainAddr wraps a domain for the SOCKS5 domain address type [LEN, DOMAIN...].
func socks5DomainAddr(domain string) []byte {
	d := []byte(domain)
	return append([]byte{byte(len(d))}, d...)
}

// socks5Address builds an address-only buffer [ATYP, ADDR, PORT] for direct
// parseSOCKS5Address testing (offset 0).
func socks5Address(atyp byte, addr []byte, port uint16) []byte {
	a := make([]byte, 0, 1+len(addr)+2)
	a = append(a, atyp)
	a = append(a, addr...)
	a = append(a, byte(port>>8), byte(port))
	return a
}

// socks5CovUDPDatagram builds a SOCKS5 UDP request datagram
// [RSV, FRAG, ATYP, ADDR, PORT, PAYLOAD].
func socks5CovUDPDatagram(atyp byte, addr []byte, port uint16, payload []byte) []byte {
	d := make([]byte, 0, 4+len(addr)+2+len(payload))
	d = append(d, 0x00, 0x00, 0x00, atyp)
	d = append(d, addr...)
	d = append(d, byte(port>>8), byte(port))
	d = append(d, payload...)
	return d
}

func TestHandleSOCKS5GreetingRejectsMalformed(t *testing.T) {
	cases := []struct {
		name    string
		greeting []byte
	}{
		{"too short", []byte{0x05}},
		{"wrong version", []byte{0x04, 0x01, 0x00}},
		{"truncated methods", []byte{0x05, 0x02, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := HandleSOCKS5Greeting(tc.greeting); err == nil {
				t.Fatalf("HandleSOCKS5Greeting accepted malformed greeting %x", tc.greeting)
			}
		})
	}
}

// TestHandleSOCKS5GreetingSelectsNoAuth exercises the method-selection logic past the
// structural checks: a greeting offering no-auth selects it (success), while a greeting
// offering only non-no-auth methods yields the no-acceptable-methods response+error.
// Both cases are built with the socks5Greeting helper, which keeps the byte framing
// correct and exercises the well-formed happy path of the parser.
func TestHandleSOCKS5GreetingSelectsNoAuth(t *testing.T) {
	t.Run("no auth offered", func(t *testing.T) {
		resp, err := HandleSOCKS5Greeting(socks5Greeting(socksNoAuth))
		if err != nil {
			t.Fatalf("HandleSOCKS5Greeting(no-auth) returned err: %v", err)
		}
		if want := []byte{socksVersion5, socksNoAuth}; !bytes.Equal(resp, want) {
			t.Fatalf("HandleSOCKS5Greeting(no-auth) = %x, want %x", resp, want)
		}
	})
	t.Run("no auth unavailable", func(t *testing.T) {
		// Only username/password (0x01) is offered; no-auth is absent.
		resp, err := HandleSOCKS5Greeting(socks5Greeting(0x01))
		if err == nil {
			t.Fatal("HandleSOCKS5Greeting accepted a greeting without no-auth")
		}
		if want := []byte{socksVersion5, socksNoAcceptable}; !bytes.Equal(resp, want) {
			t.Fatalf("HandleSOCKS5Greeting(no-auth-absent) = %x, want %x", resp, want)
		}
	})
}

func TestSocks5BindResponseRejectsInvalidBind(t *testing.T) {
	t.Run("zero port", func(t *testing.T) {
		if _, err := socks5BindResponse("127.0.0.1", 0); err == nil {
			t.Fatal("socks5BindResponse accepted zero bind port")
		}
	})
	t.Run("invalid host", func(t *testing.T) {
		if _, err := socks5BindResponse("bad/host", 80); err == nil {
			t.Fatal("socks5BindResponse accepted invalid bind host")
		}
	})
	t.Run("domain too long", func(t *testing.T) {
		if _, err := socks5BindResponse(strings.Repeat("a", 256), 80); err == nil {
			t.Fatal("socks5BindResponse accepted an overlong bind domain")
		}
	})
}

func TestSocks5BindResponseEncodesIPv6AndDomain(t *testing.T) {
	t.Run("ipv6", func(t *testing.T) {
		response, err := socks5BindResponse("::1", 80)
		if err != nil {
			t.Fatal(err)
		}
		if response[3] != socks5CoverageAtypIPv6 || response[len(response)-2] != 0 || response[len(response)-1] != 80 {
			t.Fatalf("unexpected IPv6 bind response: %x", response)
		}
	})
	t.Run("domain", func(t *testing.T) {
		response, err := socks5BindResponse("example.com", 80)
		if err != nil {
			t.Fatal(err)
		}
		if response[3] != socks5CoverageAtypDomain || response[4] != 11 || string(response[5:16]) != "example.com" ||
			response[len(response)-2] != 0 || response[len(response)-1] != 80 {
			t.Fatalf("unexpected domain bind response: %x", response)
		}
	})
}

func TestHandleSOCKS5UDPAssociateRequestRejectsMalformed(t *testing.T) {
	t.Run("invalid request", func(t *testing.T) {
		// len < 4 -> parseSOCKS5RequestWithOptions error
		if _, err := HandleSOCKS5UDPAssociateRequest([]byte{0x05, 0x03}, "127.0.0.1", 1081); err == nil {
			t.Fatal("HandleSOCKS5UDPAssociateRequest accepted an invalid request")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		req := socks5Request(socks5CoverageCmdUDPAssoc, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 0)
		req = append(req, 0xff)
		if _, err := HandleSOCKS5UDPAssociateRequest(req, "127.0.0.1", 1081); err == nil {
			t.Fatal("HandleSOCKS5UDPAssociateRequest accepted trailing bytes")
		}
	})
	t.Run("zero bind port", func(t *testing.T) {
		req := socks5Request(socks5CoverageCmdUDPAssoc, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 0)
		if _, err := HandleSOCKS5UDPAssociateRequest(req, "127.0.0.1", 0); err == nil {
			t.Fatal("HandleSOCKS5UDPAssociateRequest accepted a zero bind port")
		}
	})
	t.Run("invalid bind host", func(t *testing.T) {
		req := socks5Request(socks5CoverageCmdUDPAssoc, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 0)
		if _, err := HandleSOCKS5UDPAssociateRequest(req, "bad/host", 1081); err == nil {
			t.Fatal("HandleSOCKS5UDPAssociateRequest accepted an invalid bind host")
		}
	})
}

func TestParseAuthorityRejectsMalformed(t *testing.T) {
	cases := []struct {
		name      string
		authority string
	}{
		{"missing port", "example"},
		{"non-numeric port", "example:abc"},
		{"zero port", "example:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseAuthority(tc.authority); err == nil {
				t.Fatalf("parseAuthority accepted malformed authority %q", tc.authority)
			}
		})
	}
}

func TestParseSOCKS5RequestWithOptionsRejectsMalformed(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5RequestWithOptions([]byte{0x05, 0x01}, socks5CoverageCmdConnect, false); err == nil {
			t.Fatal("parseSOCKS5RequestWithOptions accepted a too-short request")
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		req := socks5Request(socks5CoverageCmdConnect, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80)
		req[0] = 0x04
		if _, _, _, err := parseSOCKS5RequestWithOptions(req, socks5CoverageCmdConnect, false); err == nil {
			t.Fatal("parseSOCKS5RequestWithOptions accepted a wrong SOCKS version")
		}
	})
	t.Run("wrong command", func(t *testing.T) {
		req := socks5Request(0x02, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80)
		if _, _, _, err := parseSOCKS5RequestWithOptions(req, socks5CoverageCmdConnect, false); err == nil {
			t.Fatal("parseSOCKS5RequestWithOptions accepted an unsupported command")
		}
	})
	t.Run("reserved byte", func(t *testing.T) {
		req := socks5Request(socks5CoverageCmdConnect, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80)
		req[2] = 0x01
		if _, _, _, err := parseSOCKS5RequestWithOptions(req, socks5CoverageCmdConnect, false); err == nil {
			t.Fatal("parseSOCKS5RequestWithOptions accepted a non-zero reserved byte")
		}
	})
}

func TestParseSOCKS5UDPHeaderRejectsMalformed(t *testing.T) {
	if _, _, _, err := parseSOCKS5UDPHeader([]byte{0x01, 0x00, 0x00, 0x01}); err == nil {
		t.Fatal("parseSOCKS5UDPHeader accepted a non-zero RSV byte")
	}
}

func TestParseSOCKS5AddressRejectsMalformed(t *testing.T) {
	t.Run("missing address type", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5Address([]byte{}, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted an empty buffer")
		}
	})
	t.Run("truncated ipv4", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5Address([]byte{socks5CoverageAtypIPv4}, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted a truncated IPv4 address")
		}
	})
	t.Run("truncated domain length", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5Address([]byte{socks5CoverageAtypDomain}, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted a truncated domain length")
		}
	})
	t.Run("zero domain size", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5Address([]byte{socks5CoverageAtypDomain, 0x00, 0x00, 0x50}, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted a zero-length domain")
		}
	})
	t.Run("truncated ipv6", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5Address([]byte{socks5CoverageAtypIPv6}, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted a truncated IPv6 address")
		}
	})
	t.Run("unsupported address type", func(t *testing.T) {
		if _, _, _, err := parseSOCKS5Address([]byte{0x09, 0x00, 0x50}, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted an unsupported address type")
		}
	})
	t.Run("zero port", func(t *testing.T) {
		addr := socks5Address(socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 0)
		if _, _, _, err := parseSOCKS5Address(addr, 0, false); err == nil {
			t.Fatal("parseSOCKS5Address accepted a zero target port")
		}
	})
}

func TestParseSOCKS5AddressAcceptsIPv6AndZeroPortWhenAllowed(t *testing.T) {
	t.Run("ipv6", func(t *testing.T) {
		addr := socks5Address(socks5CoverageAtypIPv6, make([]byte, 16), 80)
		host, port, end, err := parseSOCKS5Address(addr, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		if host != "::" || port != 80 || end != 19 {
			t.Fatalf("unexpected IPv6 parse: host=%q port=%d end=%d", host, port, end)
		}
	})
	t.Run("zero port allowed", func(t *testing.T) {
		addr := socks5Address(socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 0)
		if _, port, _, err := parseSOCKS5Address(addr, 0, true); err != nil || port != 0 {
			t.Fatalf("parseSOCKS5Address rejected zero port when allowZeroPort=true: err=%v port=%d", err, port)
		}
	})
}

func TestLocalProxyOpenHTTPConnectRequestRejectsMalformed(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		p := NewLocalProxy()
		if _, err := p.OpenHTTPConnectRequest(1, []byte("not-an-http-request")); err == nil {
			t.Fatal("OpenHTTPConnectRequest accepted malformed input")
		}
	})
	t.Run("missing port", func(t *testing.T) {
		p := NewLocalProxy()
		if _, err := p.OpenHTTPConnectRequest(1, []byte("CONNECT example HTTP/1.1\r\nHost: example\r\n\r\n")); err == nil {
			t.Fatal("OpenHTTPConnectRequest accepted a CONNECT authority without a port")
		}
	})
	t.Run("invalid target host", func(t *testing.T) {
		// The CONNECT authority ":80" has an empty host but a valid port, so
		// parseAuthority accepts it (SplitHostPort(":80") -> host="", port=80). The
		// empty host then fails localTarget inside OpenTCP, before any flow state is
		// created.
		p := NewLocalProxy()
		if _, err := p.OpenHTTPConnectRequest(1, []byte("CONNECT :80 HTTP/1.1\r\nHost: :80\r\n\r\n")); err == nil {
			t.Fatal("OpenHTTPConnectRequest accepted an invalid target host")
		}
		if p.HasFlow(1) {
			t.Fatal("rejected HTTP CONNECT request left a flow behind")
		}
	})
}

func TestLocalProxyOpenSOCKS5ConnectRequestRejectsMalformed(t *testing.T) {
	t.Run("invalid request", func(t *testing.T) {
		p := NewLocalProxy()
		if _, err := p.OpenSOCKS5ConnectRequest(1, []byte{0x05, 0x01}); err == nil {
			t.Fatal("OpenSOCKS5ConnectRequest accepted an invalid request")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		p := NewLocalProxy()
		req := socks5Request(socks5CoverageCmdConnect, socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80)
		req = append(req, 0xff)
		if _, err := p.OpenSOCKS5ConnectRequest(1, req); err == nil {
			t.Fatal("OpenSOCKS5ConnectRequest accepted trailing bytes")
		}
	})
	t.Run("invalid target host", func(t *testing.T) {
		// A SOCKS5 domain target "bad/host" parses cleanly, but localTarget rejects
		// the "/" so OpenTCP errors before any flow state is created.
		p := NewLocalProxy()
		req := socks5Request(socks5CoverageCmdConnect, socks5CoverageAtypDomain, socks5DomainAddr("bad/host"), 80)
		if _, err := p.OpenSOCKS5ConnectRequest(1, req); err == nil {
			t.Fatal("OpenSOCKS5ConnectRequest accepted an invalid target host")
		}
		if p.HasFlow(1) {
			t.Fatal("rejected SOCKS5 CONNECT request left a flow behind")
		}
	})
}

func TestLocalProxyHandleSOCKS5UDPDatagramFramesRejectsMalformed(t *testing.T) {
	t.Run("unsupported udp mode", func(t *testing.T) {
		p := NewLocalProxy()
		packet := socks5CovUDPDatagram(socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80, []byte("payload"))
		if _, err := p.HandleSOCKS5UDPDatagramFrames(1, packet, 100, transport.UDPMode(99)); err == nil {
			t.Fatal("HandleSOCKS5UDPDatagramFrames accepted an unsupported UDP mode")
		}
	})
	t.Run("invalid udp header", func(t *testing.T) {
		p := NewLocalProxy()
		if _, err := p.HandleSOCKS5UDPDatagramFrames(1, []byte{0x01, 0x00, 0x00, 0x01}, 100, transport.UDPNativeDatagram); err == nil {
			t.Fatal("HandleSOCKS5UDPDatagramFrames accepted a malformed UDP header")
		}
	})
	t.Run("invalid target host opens no flow", func(t *testing.T) {
		// Fresh flow: FlowState miss -> OpenUDPExplicitFrame -> localTarget("bad/host")
		// rejects the "/" so ensureSOCKS5UDPFlowFrame errors before any flow is opened.
		p := NewLocalProxy()
		packet := socks5CovUDPDatagram(socks5CoverageAtypDomain, socks5DomainAddr("bad/host"), 80, []byte("payload"))
		if _, err := p.HandleSOCKS5UDPDatagramFrames(2, packet, 100, transport.UDPNativeDatagram); err == nil {
			t.Fatal("HandleSOCKS5UDPDatagramFrames accepted an invalid target host")
		}
		if p.HasFlow(2) {
			t.Fatal("rejected SOCKS5 UDP datagram left a flow behind")
		}
	})
}

func TestLocalProxyHandleSOCKS5UDPDatagramFramesRejectsTargetChangeOnEstablishedFlow(t *testing.T) {
	t.Run("target changed", func(t *testing.T) {
		p := NewLocalProxy()
		first := socks5CovUDPDatagram(socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80, []byte("payload"))
		if frames, err := p.HandleSOCKS5UDPDatagramFrames(3, first, 100, transport.UDPNativeDatagram); err != nil || len(frames) != 2 {
			t.Fatalf("first datagram should open a UDP flow: err=%v frames=%d", err, len(frames))
		}
		// Second datagram to a different IPv4 target on the same flow: FlowState hits,
		// the target host mismatches, so ensureSOCKS5UDPFlowFrame reports a change.
		second := socks5CovUDPDatagram(socks5CoverageAtypIPv4, []byte{5, 6, 7, 8}, 80, []byte("again"))
		if _, err := p.HandleSOCKS5UDPDatagramFrames(3, second, 100, transport.UDPNativeDatagram); err == nil {
			t.Fatal("HandleSOCKS5UDPDatagramFrames accepted a changed UDP target on an established flow")
		}
	})
	t.Run("invalid target on established flow", func(t *testing.T) {
		p := NewLocalProxy()
		first := socks5CovUDPDatagram(socks5CoverageAtypIPv4, []byte{1, 2, 3, 4}, 80, []byte("payload"))
		if _, err := p.HandleSOCKS5UDPDatagramFrames(4, first, 100, transport.UDPNativeDatagram); err != nil {
			t.Fatal(err)
		}
		// Second datagram to an invalid domain target: FlowState hits, then localTarget
		// rejects "bad/host" before the target comparison.
		second := socks5CovUDPDatagram(socks5CoverageAtypDomain, socks5DomainAddr("bad/host"), 80, []byte("again"))
		if _, err := p.HandleSOCKS5UDPDatagramFrames(4, second, 100, transport.UDPNativeDatagram); err == nil {
			t.Fatal("HandleSOCKS5UDPDatagramFrames accepted an invalid target on an established flow")
		}
	})
}