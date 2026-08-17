package client

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards in client/tcp_proxy_runtime.go. Each guard exists so a caller that
// passes a nil application — or holds a nil *udpProxyAssociation / passes a nil
// peer — does not panic or proceed into the proxy setup / peer-accept path: the
// function returns at its very first statement, before any field is
// dereferenced (application.ReadCarrier, a.mu, a.closed, a.peer) or any helper
// is called (normalizeTCPProxyRuntimeOptions, NewLocalProxy). The existing
// client tests only ever drive a populated application along the live TCP
// proxy path and real UDP peers, so the nil guards stayed count-0 even though
// each is plainly reachable.
//
//   - :124 NewTCPProxyRuntime(application *session.Application, options TCPProxyRuntimeOptions)
//     application == nil -> (nil, "client: TCP proxy application is required")
//     (the application==nil guard fires before normalizeTCPProxyRuntimeOptions
//     / NewLocalProxy / the flows map allocation; no proxy state is built)
//   - :1119 (*udpProxyAssociation).acceptPeer(peer *net.UDPAddr) bool
//     a == nil || peer == nil -> false (the || short-circuits on the nil-a side
//     when called on a nil receiver, and on the nil-peer side when called with a
//     nil peer; fires before a.mu.Lock / the closed / peer / peerIP / peerPort
//     reads)
//
// These are nil-ARGUMENT (constructor) and nil-RECEIVER / nil-ARGUMENT
// (acceptPeer) first-statement guards. Neither takes a context, so there is no
// SA1012 surface. No network connection is opened — the nil guards return
// before any proxy state is built or any peer address is read. The test is
// in-package (package client) because udpProxyAssociation is unexported
// (NewTCPProxyRuntime and TCPProxyRuntimeOptions are exported but their nil
// path is exercised here alongside the unexported receiver).
//
// This test file adds only TestXxx entry points and uses existing
// exported/unexported in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestNewTCPProxyRuntimeNilArgumentGuard(t *testing.T) {
	// 124: NewTCPProxyRuntime(nil, ...) returns the required-application error
	// and a nil runtime. The application==nil guard fires before
	// normalizeTCPProxyRuntimeOptions / NewLocalProxy, so no proxy state is
	// built.
	runtime, err := NewTCPProxyRuntime(nil, TCPProxyRuntimeOptions{})
	if err == nil {
		t.Fatal("NewTCPProxyRuntime(nil,...) err = nil, want non-nil (:124 should reject)")
	} else if !strings.Contains(err.Error(), "TCP proxy application is required") {
		t.Fatalf("NewTCPProxyRuntime(nil,...) err = %q, want substring \"TCP proxy application is required\" (:124)", err.Error())
	}
	if runtime != nil {
		t.Fatalf("NewTCPProxyRuntime(nil,...) runtime = %v, want nil (:124)", runtime)
	}
}

func TestUDPProxyAssociationAcceptPeerNilGuards(t *testing.T) {
	// 1119: acceptPeer returns false at its first statement when the receiver is
	// nil OR the peer is nil, before touching a.mu / a.closed / a.peer. Two
	// calls exercise both nil sides of the || short-circuit.

	// nil receiver (a == nil side); peer is nil too but the a==nil side fires.
	var a *udpProxyAssociation
	if a.acceptPeer(nil) {
		t.Fatal("nil.acceptPeer(nil) = true, want false (:1119 a==nil should reject)")
	}

	// nil peer (peer == nil side) with a non-nil zero-value receiver; the a!=nil
	// side is false so the peer==nil side is evaluated and fires.
	if (&udpProxyAssociation{}).acceptPeer(nil) {
		t.Fatal("acceptPeer(nil) = true, want false (:1119 peer==nil should reject)")
	}
}
