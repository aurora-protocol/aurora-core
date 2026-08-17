package client

// Adversarial white-box coverage for the count-0 nil-safety guard in
// (*PacketAdapter).handleRelayDataLocked: the unknown-flow branch of the
// compound :776 guard.
//
//   - packet_adapter.go:776 (*PacketAdapter).handleRelayDataLocked
//     mapping == nil || mapping.peerClosed -> "client: packet adapter received
//     data for unknown flow" (the first clause; an empty/nil flowsByID map returns
//     nil for an unknown FlowID, so mapping == nil short-circuits the compound
//     guard before mapping.peerClosed is dereferenced).
//
// The existing client tests drive handleRelayDataLocked only on a fully-built
// adapter with an installed flow (a real packetAdapterFlow with peerClosed
// reachable), so the unknown-flow nil clause stayed count-0 even though it is
// plainly reachable with an empty adapter.
//
// Proof: (&PacketAdapter{}).handleRelayDataLocked(protocol.AuroraFrame{FlowID: 1})
// — the nil flowsByID map returns nil at :775; mapping == nil short-circuits :776
// before mapping.peerClosed; :777 returns the unique error.
//
// No context is involved, so there is no SA1012 surface. No network, no goroutine,
// no file IO — the guard returns before any conn / packet build is touched.
// handleRelayDataLocked is a "Locked"-suffix method (the caller conventionally
// holds a.mu), but the nil-mapping path returns at :777 before any state is read
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

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestPacketAdapterHandleRelayDataLockedUnknownFlowGuard(t *testing.T) {
	// 776: an empty flowsByID map returns nil for an unknown FlowID; mapping == nil
	// short-circuits the compound :776 guard before mapping.peerClosed (nil
	// deref panic); :777 returns "data for unknown flow".
	_, err := (&PacketAdapter{}).handleRelayDataLocked(protocol.AuroraFrame{FlowID: 1})
	if err == nil {
		t.Fatal("handleRelayDataLocked(unknown flow) err = nil, want non-nil (:777)")
	}
	if !strings.Contains(err.Error(), "data for unknown flow") {
		t.Fatalf("unknown-flow err = %q, want \"...data for unknown flow\" (:777)", err.Error())
	}
}