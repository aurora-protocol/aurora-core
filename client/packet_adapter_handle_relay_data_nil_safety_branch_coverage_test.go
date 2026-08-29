package client

// Adversarial white-box coverage for the count-0 nil-safety guard in
// (*PacketAdapter).handleRelayDataLocked: the unknown-flow branch of the
// compound :776 guard.
//
//   - packet_adapter.go:798 (*PacketAdapter).handleRelayDataLocked
//     mapping == nil -> drop the frame (nil packets, nil error) for a flow the
//     adapter already retired; a live mapping whose peerClosed is set still
//     reports an error (the relay may not send data after its own close).
//
// The existing client tests drive handleRelayDataLocked only on a fully-built
// adapter with an installed flow (a real packetAdapterFlow with peerClosed
// reachable), so the unknown-flow nil clause stayed count-0 even though it is
// plainly reachable with an empty adapter.
//
// Proof: (&PacketAdapter{}).handleRelayDataLocked(protocol.AuroraFrame{FlowID: 1}, time.Unix(1_700_000_000, 0))
// — the nil flowsByID map returns nil at :799, so the retired-flow branch drops
// the frame without touching mapping.peerClosed (which would panic on nil). The
// peerClosed clause is proved separately with an installed flow.
//
// No context is involved, so there is no SA1012 surface. No network, no goroutine,
// no file IO — the guard returns before any conn / packet build is touched.
// handleRelayDataLocked is a "Locked"-suffix method (the caller conventionally
// holds a.mu), but the nil-mapping path returns at :801 before any state is read
// or mutated, so calling it on a zero-value PacketAdapter without holding the
// lock is safe and does not deadlock. In-package (package client) because
// handleRelayDataLocked is unexported.
//
// This test file adds only a TestXxx entry point and references existing
// in-package (PacketAdapter, handleRelayDataLocked) symbols, the exported
// protocol.AuroraFrame type, and the standard library strings / testing
// packages, so it adds no U1000 surface.

import (
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestPacketAdapterHandleRelayDataLockedUnknownFlowGuard(t *testing.T) {
	// 800: an empty flowsByID map returns nil for an unknown FlowID; mapping == nil
	// takes the retired-flow branch and drops the frame without dereferencing
	// mapping.peerClosed (which would panic on nil).
	packets, err := (&PacketAdapter{}).handleRelayDataLocked(protocol.AuroraFrame{FlowID: 1}, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("handleRelayDataLocked(unknown flow) err = %v, want nil (retired-flow drop)", err)
	}
	if packets != nil {
		t.Fatalf("handleRelayDataLocked(unknown flow) packets = %v, want nil", packets)
	}
}

func TestPacketAdapterHandleRelayDataLockedPeerClosedGuard(t *testing.T) {
	// The second clause stays terminal: a live mapping the relay has already
	// closed must not accept more data.
	a := &PacketAdapter{flowsByID: map[uint64]*packetAdapterFlow{
		1: {flowID: 1, kind: flow.FlowKindTCPStream, peerClosed: true},
	}}
	_, err := a.handleRelayDataLocked(protocol.AuroraFrame{FlowID: 1}, time.Unix(1_700_000_000, 0))
	if err == nil {
		t.Fatal("handleRelayDataLocked(peer-closed flow) err = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "after the relay closed the flow") {
		t.Fatalf("peer-closed err = %q, want \"...after the relay closed the flow\"", err.Error())
	}
}
