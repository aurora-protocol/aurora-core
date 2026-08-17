package client

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across client/packet_tun_runtime.go. Each guard exists so a caller
// that holds a nil *PacketTUNRuntime does not panic or proceed into the live
// capture / frame-pumping loop: the method returns at its very first statement,
// before any field is dereferenced (r.isClosed reads r.done, r.adapter, r.device)
// or any context method is called (ctx.Err) or any goroutine is spawned. The
// existing client tests only ever drive a fully-built PacketTUNRuntime bound to
// a real packet device, so the nil-receiver guards stayed count-0 even though
// each is plainly reachable.
//
// These are nil-RECEIVER guards. Serve and HandleFrameBlock take a context and
// are driven with context.Background (never a nil context literal), so there is
// no SA1012 surface: the r==nil guard fires before the context is ever read. The
// second-statement ctx==nil guards (:81 Serve, :136 HandleFrameBlock) are
// intentionally left uncovered — they are not first-statement nil-safety guards
// and covering them would require passing a nil context (SA1012). No network,
// no goroutine, no crypto — each call returns at the first statement. All
// referenced symbols are exported, but the test is in-package for consistency
// with the rest of the client nil-safety coverage family.
//
//   - :78  (*PacketTUNRuntime).Serve(ctx)              r == nil
//     -> "client: nil packet TUN runtime" (ctx=Background; the r==nil guard fires
//     before the ctx==nil guard at 81, so the context is never read)
//   - :133 (*PacketTUNRuntime).HandleFrameBlock(ctx, block)  r == nil
//     -> "client: nil packet TUN runtime" (ctx=Background; r==nil fires before
//     the ctx==nil guard at 136)
//   - :187 (*PacketTUNRuntime).Close()               r == nil -> nil
//
// This test file adds only TestXxx entry points and uses existing exported
// symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestPacketTUNRuntimeNilReceiverGuards(t *testing.T) {
	// 78/133/187: a nil *PacketTUNRuntime returns at the first statement of
	// Serve / HandleFrameBlock / Close rather than dereferencing r.done /
	// r.adapter / r.device. Every ctx-taking method is driven with
	// context.Background so the nil-receiver guard fires before the context is
	// read (no SA1012).
	var r *PacketTUNRuntime
	ctx := context.Background()

	// 78: Serve returns "nil packet TUN runtime".
	if err := r.Serve(ctx); err == nil {
		t.Fatal("nil.Serve err = nil, want non-nil (:78 should reject)")
	} else if !strings.Contains(err.Error(), "nil packet TUN runtime") {
		t.Fatalf("nil.Serve err = %q, want substring \"nil packet TUN runtime\" (:78)", err.Error())
	}

	// 133: HandleFrameBlock returns "nil packet TUN runtime".
	if err := r.HandleFrameBlock(ctx, protocol.FrameBlock{}); err == nil {
		t.Fatal("nil.HandleFrameBlock err = nil, want non-nil (:133 should reject)")
	} else if !strings.Contains(err.Error(), "nil packet TUN runtime") {
		t.Fatalf("nil.HandleFrameBlock err = %q, want substring \"nil packet TUN runtime\" (:133)", err.Error())
	}

	// 187: Close returns nil.
	if err := r.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:187 should return nil)", err)
	}
}
