package client

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across client/packet_adapter.go. Each guard exists so a caller that
// holds a nil *PacketAdapter — or passes a nil application / nil flow mapping —
// does not panic or proceed past an uninitialised state: the method returns at
// its very first statement, before any field is dereferenced (a.mu, a.closed,
// a.localPackets, a.flowsByTuple, a.proxy) or any context method is called
// (ctx.Err). The existing client tests only ever drive a fully-built PacketAdapter
// bound to a live session.Application, so the nil guards stayed count-0 even
// though each is plainly reachable.
//
// These are nil-RECEIVER / nil-ARGUMENT guards. Every method that takes a context
// is driven with context.Background (never a nil context literal), so there is no
// SA1012 surface: the nil-RECEIVER guards fire before the context is ever read, and
// the nil-ARGUMENT ctx guards (:292/:404/:438, the SECOND statement) are out of
// scope here and left uncovered. No network, no goroutine, no crypto — each call
// returns at the first statement. The two unexported nil-arg guards
// (closeLocalFlowLocked:870, removeFlowLocked:957) require an in-package test.
//
//   - :213 NewPacketAdapter(application, options)        application == nil
//     -> nil, "client: packet adapter application is required" (exported constructor;
//     a nil *session.Application is the only argument needed)
//   - :254 PacketAdapter.Close                            a == nil -> no-op return
//     (void; proven by absence of panic via a recover wrapper)
//   - :289 PacketAdapter.Ingress(ctx, encoded, now)       a == nil
//     -> "client: packet adapter is nil" (ctx=Background; the a==nil guard fires
//     before the ctx==nil guard at 292, so the context is never read)
//   - :383 PacketAdapter.NextEncryptedPacket(ctx)         a == nil
//     -> nil, "client: packet adapter application is unavailable" (ctx=Background)
//   - :401 PacketAdapter.HandleEncryptedPacket(ctx,...)   a == nil
//     -> nil, "client: packet adapter application is unavailable" (ctx=Background)
//   - :435 PacketAdapter.HandleFrameBlocks(ctx,...)       a == nil
//     -> nil, "client: packet adapter application is unavailable" (ctx=Background)
//   - :474 PacketAdapter.DrainLocalPackets()               a == nil -> nil
//   - :486 PacketAdapter.FlowCount()                      a == nil -> 0
//   - :870 PacketAdapter.closeLocalFlowLocked(ctx,mapping,now,fin)  mapping == nil
//     -> "client: packet adapter flow is unavailable" (UNEXPORTED -> in-package;
//     non-nil &PacketAdapter{} receiver; ctx=Background; the mapping==nil guard
//     fires before any flow field is touched)
//   - :957 PacketAdapter.removeFlowLocked(mapping)         mapping == nil -> no-op return
//     (UNEXPORTED -> in-package; void; proven by absence of panic via a recover
//     wrapper; a zero &PacketAdapter{} is safe because the guard fires first)
//
// This test file adds only TestXxx entry points and uses existing exported (plus
// two unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewPacketAdapterRejectsNilApplication(t *testing.T) {
	// 213: the constructor rejects a nil application at its first statement with
	// "application is required", before normalizePacketAdapterOptions runs.
	adapter, err := NewPacketAdapter(nil, PacketAdapterOptions{})
	if err == nil {
		t.Fatal("NewPacketAdapter(nil application) err = nil, want non-nil (:213 should reject)")
	}
	if !strings.Contains(err.Error(), "application is required") {
		t.Fatalf("NewPacketAdapter(nil application) err = %q, want substring \"application is required\" (:213)", err.Error())
	}
	if adapter != nil {
		t.Fatalf("NewPacketAdapter(nil application) adapter = %v, want nil (:213)", adapter)
	}
}

func TestPacketAdapterNilReceiverGuards(t *testing.T) {
	// 254/289/383/401/435/474/486: a nil *PacketAdapter returns at the first
	// statement of each method rather than dereferencing a.mu / a.closed /
	// a.localPackets. Every ctx-taking method is driven with context.Background
	// so the nil-receiver guard fires before the context is read (no SA1012).
	var a *PacketAdapter
	ctx := context.Background()

	// 254: Close is void; proven by absence of panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.Close panicked = %v, want no-op return (:254 should guard the nil receiver)", r)
			}
		}()
		a.Close()
	}()

	// 289: Ingress returns "packet adapter is nil".
	if err := a.Ingress(ctx, nil, time.Time{}); err == nil {
		t.Fatal("nil.Ingress err = nil, want non-nil (:289 should reject)")
	} else if !strings.Contains(err.Error(), "packet adapter is nil") {
		t.Fatalf("nil.Ingress err = %q, want substring \"packet adapter is nil\" (:289)", err.Error())
	}

	// 383: NextEncryptedPacket returns "application is unavailable".
	pkt, err := a.NextEncryptedPacket(ctx)
	if err == nil {
		t.Fatal("nil.NextEncryptedPacket err = nil, want non-nil (:383 should reject)")
	} else if !strings.Contains(err.Error(), "application is unavailable") {
		t.Fatalf("nil.NextEncryptedPacket err = %q, want substring \"application is unavailable\" (:383)", err.Error())
	}
	if pkt != nil {
		t.Fatalf("nil.NextEncryptedPacket pkt = %v, want nil (:383)", pkt)
	}

	// 401: HandleEncryptedPacket returns "application is unavailable".
	out, err := a.HandleEncryptedPacket(ctx, nil, time.Time{})
	if err == nil {
		t.Fatal("nil.HandleEncryptedPacket err = nil, want non-nil (:401 should reject)")
	} else if !strings.Contains(err.Error(), "application is unavailable") {
		t.Fatalf("nil.HandleEncryptedPacket err = %q, want substring \"application is unavailable\" (:401)", err.Error())
	}
	if out != nil {
		t.Fatalf("nil.HandleEncryptedPacket out = %v, want nil (:401)", out)
	}

	// 435: HandleFrameBlocks returns "application is unavailable".
	out, err = a.HandleFrameBlocks(ctx, nil, time.Time{})
	if err == nil {
		t.Fatal("nil.HandleFrameBlocks err = nil, want non-nil (:435 should reject)")
	} else if !strings.Contains(err.Error(), "application is unavailable") {
		t.Fatalf("nil.HandleFrameBlocks err = %q, want substring \"application is unavailable\" (:435)", err.Error())
	}
	if out != nil {
		t.Fatalf("nil.HandleFrameBlocks out = %v, want nil (:435)", out)
	}

	// 474: DrainLocalPackets returns nil.
	if pkts := a.DrainLocalPackets(); pkts != nil {
		t.Fatalf("nil.DrainLocalPackets = %v, want nil (:474)", pkts)
	}

	// 486: FlowCount returns 0.
	if n := a.FlowCount(); n != 0 {
		t.Fatalf("nil.FlowCount = %d, want 0 (:486)", n)
	}
}

func TestPacketAdapterNilArgumentGuards(t *testing.T) {
	// 870/957: a non-nil &PacketAdapter{} receiver rejects a nil flow mapping at
	// the first statement of the two unexported helpers, before any flow field is
	// touched. ctx=Background so there is no SA1012 surface.
	a := &PacketAdapter{}
	ctx := context.Background()

	// 870: closeLocalFlowLocked returns "flow is unavailable".
	if err := a.closeLocalFlowLocked(ctx, nil, time.Time{}, false); err == nil {
		t.Fatal("closeLocalFlowLocked(nil mapping) err = nil, want non-nil (:870 should reject)")
	} else if !strings.Contains(err.Error(), "flow is unavailable") {
		t.Fatalf("closeLocalFlowLocked(nil mapping) err = %q, want substring \"flow is unavailable\" (:870)", err.Error())
	}

	// 957: removeFlowLocked is void; proven by absence of panic. A zero
	// &PacketAdapter{} is safe because the mapping==nil guard fires first, before
	// a.flowsByTuple / a.proxy are touched.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("removeFlowLocked(nil mapping) panicked = %v, want no-op return (:957 should guard the nil mapping)", r)
			}
		}()
		a.removeFlowLocked(nil)
	}()
}
