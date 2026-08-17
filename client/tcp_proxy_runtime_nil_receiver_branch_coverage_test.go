package client

// Adversarial white-box coverage for the 11 count-0 first-statement
// nil-safety guards in client/tcp_proxy_runtime.go. Each guard exists so a
// caller that holds a nil *TCPProxyRuntime / passes a nil *tcpProxyFlow /
// *udpProxyAssociation / holds a nil *udpProxyAssociation / *tcpProxyFlow
// receiver does not panic or proceed into the live proxy path: the method
// returns at its very first statement, before any field is dereferenced
// (r.closeOnce, r.mu, r.options, flow.mu, flow.localCloseSent, a.closeOnce,
// r.closed) or any helper / closer / lock runs. The existing client tests only
// ever drive a populated runtime / live flow / live association along the TCP
// and UDP proxy paths, so the nil guards stayed count-0 even though each is
// plainly reachable.
//
//   - :181 (*TCPProxyRuntime).Serve(ctx, listener)  r == nil -> "client: nil
//     TCP proxy runtime" (fires before the ctx==nil guard / r.options)
//   - :230 (*TCPProxyRuntime).HandleFrameBlock(ctx, block)  r == nil ->
//     "client: nil TCP proxy runtime" (fires before the ctx==nil guard /
//     r.options)
//   - :275 (*TCPProxyRuntime).Close()  r == nil -> nil (fires before
//     r.closeOnce.Do / r.mu.Lock)
//   - :332 (*TCPProxyRuntime).serveConnection(ctx, connection)  r == nil ->
//     "client: nil TCP proxy runtime" (fires before the ctx==nil guard /
//     connection.Close)
//   - :630 (*TCPProxyRuntime).readLocalFlow(ctx, reader, flow)  flow == nil ->
//     "client: TCP proxy flow is unavailable" (fires before
//     r.options.ReadBufferBytes / the buffer allocation)
//   - :913 (*TCPProxyRuntime).sendLocalFlowClose(ctx, flow)  flow == nil -> nil
//     (fires before flow.mu.Lock / flow.localCloseSent)
//   - :1075 (*TCPProxyRuntime).addUDPAssociation(association)  association ==
//     nil -> "client: SOCKS5 UDP association is required" (fires before
//     r.mu.Lock)
//   - :1091 (*TCPProxyRuntime).removeUDPAssociation(association)
//     association == nil -> void no-op (fires before r.mu.Lock / r.closed)
//   - :1164 (*udpProxyAssociation).close()  a == nil -> nil (fires before
//     a.closeOnce.Do / a.mu)
//   - :1193 (*tcpProxyFlow).close()  f == nil -> nil (fires before
//     f.closeOnce.Do / f.mu)
//   - :1219 (*tcpProxyFlow).drainAndClose()  f == nil -> nil (fires before
//     f.mu.Lock)
//
// These are nil-RECEIVER (:181/:230/:275/:332/:1164/:1193/:1219) and
// nil-ARGUMENT (:630/:913/:1075/:1091) first-statement guards. None of the
// guards exercised here is the ctx==nil guard (those are separate, later
// statements on :184/:233/:335 and are intentionally left uncovered), so the
// test passes context.Background() and there is no SA1012 surface. No
// network, no goroutine, no listener, no connection — each guard returns
// before any field, lock, or closer is touched, so this test is pure and
// cannot perturb the timing-sensitive TCP/UDP proxy integration tests in the
// package. The test is in-package (package client) because the zeroer and
// flow / association helpers are unexported.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestTCPProxyRuntimeNilReceiverGuards(t *testing.T) {
	// 181/230/275/332: a nil *TCPProxyRuntime returns at the first statement of
	// Serve / HandleFrameBlock / Close / serveConnection rather than
	// dereferencing r.closeOnce / r.mu / r.options. Each guard fires before
	// the separate ctx==nil guard on the methods that take a context.
	var r *TCPProxyRuntime

	// 181: Serve returns "client: nil TCP proxy runtime"; the r==nil guard
	// fires before the ctx==nil guard, so a non-nil context is safe.
	if err := r.Serve(context.Background(), nil); err == nil {
		t.Fatal("nil.Serve() err = nil, want non-nil (:181 should reject)")
	} else if !strings.Contains(err.Error(), "nil TCP proxy runtime") {
		t.Fatalf("nil.Serve() err = %q, want substring \"nil TCP proxy runtime\" (:181)", err.Error())
	}

	// 230: HandleFrameBlock returns "client: nil TCP proxy runtime"; the
	// r==nil guard fires before the ctx==nil guard. The block is never read,
	// so a zero protocol.FrameBlock is safe.
	if err := r.HandleFrameBlock(context.Background(), protocol.FrameBlock{}); err == nil {
		t.Fatal("nil.HandleFrameBlock() err = nil, want non-nil (:230 should reject)")
	} else if !strings.Contains(err.Error(), "nil TCP proxy runtime") {
		t.Fatalf("nil.HandleFrameBlock() err = %q, want substring \"nil TCP proxy runtime\" (:230)", err.Error())
	}

	// 275: Close returns nil; the r==nil guard fires before r.closeOnce.Do.
	if err := r.Close(); err != nil {
		t.Fatalf("nil.Close() err = %v, want nil (:275)", err)
	}

	// 332: serveConnection returns "client: nil TCP proxy runtime"; the
	// r==nil guard fires before the ctx==nil guard / connection.Close.
	if err := r.serveConnection(context.Background(), nil); err == nil {
		t.Fatal("nil.serveConnection() err = nil, want non-nil (:332 should reject)")
	} else if !strings.Contains(err.Error(), "nil TCP proxy runtime") {
		t.Fatalf("nil.serveConnection() err = %q, want substring \"nil TCP proxy runtime\" (:332)", err.Error())
	}
}

func TestTCPProxyRuntimeNilArgumentGuards(t *testing.T) {
	// 630/913/1075/1091: a valid *TCPProxyRuntime receiver with a nil flow /
	// association argument returns at the first statement rather than
	// dereferencing r.options / flow.mu / r.mu. A zero-value runtime is safe
	// because each guard returns before any field is read.
	r := &TCPProxyRuntime{}

	// 630: readLocalFlow returns "client: TCP proxy flow is unavailable"; the
	// flow==nil guard fires before r.options.ReadBufferBytes. The reader is
	// never read, so nil is safe.
	if err := r.readLocalFlow(context.Background(), nil, nil); err == nil {
		t.Fatal("readLocalFlow(nil flow) err = nil, want non-nil (:630 should reject)")
	} else if !strings.Contains(err.Error(), "TCP proxy flow is unavailable") {
		t.Fatalf("readLocalFlow(nil flow) err = %q, want substring \"TCP proxy flow is unavailable\" (:630)", err.Error())
	}

	// 913: sendLocalFlowClose returns nil; the flow==nil guard fires before
	// flow.mu.Lock.
	if err := r.sendLocalFlowClose(context.Background(), nil); err != nil {
		t.Fatalf("sendLocalFlowClose(nil flow) err = %v, want nil (:913)", err)
	}

	// 1075: addUDPAssociation returns "client: SOCKS5 UDP association is
	// required"; the association==nil guard fires before r.mu.Lock.
	if err := r.addUDPAssociation(nil); err == nil {
		t.Fatal("addUDPAssociation(nil) err = nil, want non-nil (:1075 should reject)")
	} else if !strings.Contains(err.Error(), "SOCKS5 UDP association is required") {
		t.Fatalf("addUDPAssociation(nil) err = %q, want substring \"SOCKS5 UDP association is required\" (:1075)", err.Error())
	}

	// 1091: removeUDPAssociation is void; the association==nil guard fires
	// before r.mu.Lock. No-panic proof.
	r.removeUDPAssociation(nil)
}

func TestTCPProxyFlowNilReceiverGuards(t *testing.T) {
	// 1164/1193/1219: a nil *udpProxyAssociation / *tcpProxyFlow returns at the
	// first statement of close / close / drainAndClose rather than
	// dereferencing a.closeOnce / f.closeOnce / f.mu.

	// 1164: udpProxyAssociation.close returns nil; the a==nil guard fires
	// before a.closeOnce.Do.
	var a *udpProxyAssociation
	if err := a.close(); err != nil {
		t.Fatalf("nil.udpProxyAssociation.close() err = %v, want nil (:1164)", err)
	}

	// 1193/1219: tcpProxyFlow.close / drainAndClose return nil; the f==nil
	// guard fires before f.closeOnce.Do / f.mu.Lock.
	var f *tcpProxyFlow
	if err := f.close(); err != nil {
		t.Fatalf("nil.tcpProxyFlow.close() err = %v, want nil (:1193)", err)
	}
	if err := f.drainAndClose(); err != nil {
		t.Fatalf("nil.tcpProxyFlow.drainAndClose() err = %v, want nil (:1219)", err)
	}
}
