package client

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across client/tcp_proxy_runtime.go. Each guard exists so a caller that
// holds a nil *TCPProxyRuntime / *tcpProxyFlow / *udpProxyAssociation — or passes
// a nil flow / nil association — does not panic or proceed past an uninitialised
// state: the method returns at its very first statement, before any field is
// dereferenced (r.mu, r.closed, r.options, r.listeners, flow.mu, a.closeOnce) or
// any context method is called (ctx.Err). The existing client tests only ever
// drive a fully-built TCPProxyRuntime along the live local-proxy path, so the
// nil guards stayed count-0 even though each is plainly reachable.
//
// These are nil-RECEIVER / nil-ARGUMENT guards. Every method that takes a context
// is driven with context.Background (never a nil context literal), so there is no
// SA1012 surface: the nil-RECEIVER guards fire before the context is ever read,
// and the nil-ARGUMENT ctx guards (:186/:235/:337, the SECOND statement) are out
// of scope here and left uncovered. No network, no goroutine, no crypto — each
// call returns at the first statement. The test is in-package because tcpProxyFlow,
// udpProxyAssociation, and the serve/read/send/add/remove helpers are unexported.
//
// Nil-RECEIVER on nil *TCPProxyRuntime:
//   - :181 Serve(ctx, listener)              r == nil -> "client: nil TCP proxy runtime"
//     (ctx=Background; the r==nil guard fires before the ctx==nil/listener==nil guards)
//   - :230 HandleFrameBlock(ctx, block)      r == nil -> "client: nil TCP proxy runtime"
//     (ctx=Background; r==nil fires before ctx==nil at 235)
//   - :275 Close()                           r == nil -> nil
//   - :332 serveConnection(ctx, connection)  r == nil -> "client: nil TCP proxy runtime"
//     (UNEXPORTED; ctx=Background; r==nil fires before ctx==nil at 337)
//
// Nil-ARGUMENT on a non-nil &TCPProxyRuntime{} (the guard fires before r is derefed):
//   - :630 readLocalFlow(ctx, reader, flow)   flow == nil
//     -> "client: TCP proxy flow is unavailable" (UNEXPORTED; ctx=Background)
//   - :913 sendLocalFlowClose(ctx, flow)      flow == nil -> nil (UNEXPORTED; ctx=Background)
//   - :1075 addUDPAssociation(association)   association == nil
//     -> "client: SOCKS5 UDP association is required" (UNEXPORTED)
//   - :1091 removeUDPAssociation(association) association == nil -> no-op return
//     (UNEXPORTED; void; proven by absence of panic via a recover wrapper)
//
// Nil-RECEIVER on nil unexported types:
//   - :1164 (*udpProxyAssociation).close()   a == nil -> nil
//   - :1193 (*tcpProxyFlow).close()         f == nil -> nil
//   - :1219 (*tcpProxyFlow).drainAndClose() f == nil -> nil
//
// This test file adds only TestXxx entry points and uses existing exported (plus
// unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestTCPProxyRuntimeNilReceiverGuards(t *testing.T) {
	// 181/230/275/332: a nil *TCPProxyRuntime returns at the first statement of
	// Serve / HandleFrameBlock / Close / serveConnection rather than
	// dereferencing r.mu / r.closed / r.closeOnce. Every ctx-taking method is
	// driven with context.Background so the nil-receiver guard fires before the
	// context is read (no SA1012).
	var r *TCPProxyRuntime
	ctx := context.Background()

	// 181: Serve returns "nil TCP proxy runtime".
	if err := r.Serve(ctx, nil); err == nil {
		t.Fatal("nil.Serve err = nil, want non-nil (:181 should reject)")
	} else if !strings.Contains(err.Error(), "nil TCP proxy runtime") {
		t.Fatalf("nil.Serve err = %q, want substring \"nil TCP proxy runtime\" (:181)", err.Error())
	}

	// 230: HandleFrameBlock returns "nil TCP proxy runtime".
	if err := r.HandleFrameBlock(ctx, protocol.FrameBlock{}); err == nil {
		t.Fatal("nil.HandleFrameBlock err = nil, want non-nil (:230 should reject)")
	} else if !strings.Contains(err.Error(), "nil TCP proxy runtime") {
		t.Fatalf("nil.HandleFrameBlock err = %q, want substring \"nil TCP proxy runtime\" (:230)", err.Error())
	}

	// 275: Close returns nil.
	if err := r.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:275 should return nil)", err)
	}

	// 332: serveConnection (unexported) returns "nil TCP proxy runtime".
	if err := r.serveConnection(ctx, nil); err == nil {
		t.Fatal("nil.serveConnection err = nil, want non-nil (:332 should reject)")
	} else if !strings.Contains(err.Error(), "nil TCP proxy runtime") {
		t.Fatalf("nil.serveConnection err = %q, want substring \"nil TCP proxy runtime\" (:332)", err.Error())
	}
}

func TestTCPProxyRuntimeNilArgumentGuards(t *testing.T) {
	// 630/913/1075/1091: a non-nil &TCPProxyRuntime{} receiver rejects a nil flow
	// / nil association at the first statement of the unexported helpers, before
	// any runtime field is touched. ctx=Background so there is no SA1012 surface.
	r := &TCPProxyRuntime{}
	ctx := context.Background()

	// 630: readLocalFlow returns "TCP proxy flow is unavailable".
	if err := r.readLocalFlow(ctx, nil, nil); err == nil {
		t.Fatal("readLocalFlow(nil flow) err = nil, want non-nil (:630 should reject)")
	} else if !strings.Contains(err.Error(), "flow is unavailable") {
		t.Fatalf("readLocalFlow(nil flow) err = %q, want substring \"flow is unavailable\" (:630)", err.Error())
	}

	// 913: sendLocalFlowClose returns nil.
	if err := r.sendLocalFlowClose(ctx, nil); err != nil {
		t.Fatalf("sendLocalFlowClose(nil flow) err = %v, want nil (:913 should return nil)", err)
	}

	// 1075: addUDPAssociation returns "SOCKS5 UDP association is required".
	if err := r.addUDPAssociation(nil); err == nil {
		t.Fatal("addUDPAssociation(nil association) err = nil, want non-nil (:1075 should reject)")
	} else if !strings.Contains(err.Error(), "SOCKS5 UDP association is required") {
		t.Fatalf("addUDPAssociation(nil association) err = %q, want substring \"SOCKS5 UDP association is required\" (:1075)", err.Error())
	}

	// 1091: removeUDPAssociation is void; proven by absence of panic. A zero
	// &TCPProxyRuntime{} is safe because the association==nil guard fires first,
	// before r.mu / r.udpLinks are touched.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("removeUDPAssociation(nil association) panicked = %v, want no-op return (:1091 should guard the nil association)", rec)
			}
		}()
		r.removeUDPAssociation(nil)
	}()
}

func TestTCPProxyFlowAndUDPAssociationNilReceiverGuards(t *testing.T) {
	// 1164/1193/1219: a nil *udpProxyAssociation / *tcpProxyFlow returns at the
	// first statement of close / drainAndClose rather than dereferencing
	// a.closeOnce / f.mu / f.done.
	var a *udpProxyAssociation
	if err := a.close(); err != nil {
		t.Fatalf("nil.(*udpProxyAssociation).close err = %v, want nil (:1164 should return nil)", err)
	}

	var f *tcpProxyFlow
	if err := f.close(); err != nil {
		t.Fatalf("nil.(*tcpProxyFlow).close err = %v, want nil (:1193 should return nil)", err)
	}

	if err := f.drainAndClose(); err != nil {
		t.Fatalf("nil.(*tcpProxyFlow).drainAndClose err = %v, want nil (:1219 should return nil)", err)
	}
}
