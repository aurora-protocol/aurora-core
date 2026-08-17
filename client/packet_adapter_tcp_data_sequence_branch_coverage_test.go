package client

// Adversarial white-box coverage for the count-0 TCP-data sequence guards of
// PacketAdapter.ingressTCPLocked (client/packet_adapter.go:540-548). Once a flow
// is established (a SYN opened it, mapping.clientNextSequence = SYN.sequence+1),
// a non-SYN data packet reaches :534 (mapping present, kind TCPStream, not
// closed) and :537 (not RST), then :540 checks the sequence:
//
//   - :540 if packet.tcp.sequence != mapping.clientNextSequence
//     - :541 if tcpSequenceBefore(packet.tcp.sequence, mapping.clientNextSequence)
//       -> the data is a RETRANSMIT / duplicate (sequence already consumed); the
//          adapter replays the current ACK (:542 makeTCPPacketLocked ACK,
//          :546 enqueueLocalPacketLocked) without re-forwarding to the relay.
//     - :548 otherwise -> the data is OUT OF ORDER (sequence ahead of the expected
//        next sequence) and is rejected ("received out-of-order TCP data").
//
// Coverage targets (baseline measured on main; bodies COUNT 0 while the :540
// condition was already evaluated by the happy-path data packet, which always
// sends the exact expected sequence so :540 is false-checked):
//   - packet_adapter.go:540.55,541.73 0  — `if sequence != clientNextSequence`
//   - packet_adapter.go:541.73,543.18 0  — `if tcpSequenceBefore(...)` retransmit body
//   - packet_adapter.go:546.4,546.47 0   — ACK-replay enqueue return
//   - packet_adapter.go:548.3,548.77 0   — out-of-order error return
//
// Deliberately NOT covered (dead-by-design-ish, deferred like the :491
// makeTCPPacket-error guard in the sibling retransmitted-SYN file):
//   - packet_adapter.go:543.18,545.5 0  — `if err != nil { return err }` after
//     :542 makeTCPPacketLocked; only fires if makeTCPPacket itself errors (random
//     reader exhausted or packet exceeds MaxPacketBytes), which a working adapter
//     with a generous random buffer never hits on this small ACK. Not a pillar.
//
// The :540-548 bodies are COUNT 0 because the existing adapter tests only ever
// send data packets with the EXACT expected sequence (101) — the happy path
// (TestPacketAdapterOpensTCPAndForwardsStreamData) — so :540 is false-checked and
// neither the retransmit (:541/:546) nor out-of-order (:548) branch is taken. The
// retransmitted-SYN vein (:486) was covered separately by the sibling file
// packet_adapter_retransmitted_syn_branch_coverage_test.go; this file covers the
// post-open DATA sequence guards — no overlap.
//
// Reuses the existing adapter harness — packetAdapterApplications +
// NewPacketAdapter + packetAdapterTCPv4 + packetAdapterParseTCPv4 (the same
// builder/parser TestPacketAdapterOpensTCPAndForwardsStreamData uses). The first
// SYN establishes the flow (mapping.clientNextSequence = 101); a subsequent
// non-SYN data packet with a behind/ahead sequence hits :540. The retransmit
// (:541/:546) and out-of-order (:548) paths both return BEFORE :551
// (proxy.SendTCP) / :517 (QueueFrames), so no relay-side interaction is needed
// (the relay application is wired only to satisfy the first SYN's OpenTCP frame).
//
// In-package (package client) because ingressTCPLocked and the packetAdapter*
// helpers are unexported. No real network. No nil-context literal (a real
// context.Background() is supplied) -> no SA1012 surface. This file adds only
// TestXxx entry points and references existing in-package helpers + stdlib
// bytes/context/strings/testing/time and the transport package already imported
// by packet_adapter_test.go, so it adds no U1000 surface.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/transport"
)

// packetAdapterEstablishedTCPFlow builds an adapter, opens one TCP flow with a
// SYN (sequence 100) for a fixed tuple, and drains the synthetic SYN-ACK so the
// data-sequence tests start from a clean local-packet buffer. The flow's mapping
// has clientNextSequence = 101.
func packetAdapterEstablishedTCPFlow(t *testing.T) *PacketAdapter {
	t.Helper()
	clientApplication, relayApplication := packetAdapterApplications(t)
	t.Cleanup(func() { _ = clientApplication.Close() })
	t.Cleanup(func() { _ = relayApplication.Close() })
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		// Generous random buffer: the first SYN reads serverSequence + flow ID;
		// readUint32Locked fails the SYN if the reader is exhausted.
		Random: bytes.NewReader(make([]byte, 512)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x02, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("initial SYN Ingress err = %v, want nil (flow must open before :540 is reachable)", err)
	}
	adapter.DrainLocalPackets()
	return adapter
}

func TestPacketAdapterReplaysAckForRetransmittedTCPData(t *testing.T) {
	// :540 sequence != clientNextSequence + :541 tcpSequenceBefore true + :543/:546
	// ACK replay: a data packet whose sequence (100) is BEFORE the flow's expected
	// next sequence (101) is a retransmit/duplicate. The adapter replays the current
	// ACK (:542/:546) without re-forwarding to the relay. Returns nil + one local
	// ACK packet.
	adapter := packetAdapterEstablishedTCPFlow(t)
	now := time.Unix(1_700_000_000, 0)
	// ACK-only (0x10), sequence 100 (a retransmit of the pre-SYN-ACK state),
	// empty payload; :537 RST check skipped, :540 100 != 101 -> :541 before -> :546.
	retransmit := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x10, nil)
	if err := adapter.Ingress(context.Background(), retransmit, now); err != nil {
		t.Fatalf("retransmitted data Ingress err = %v, want nil (:541/:546 should replay ACK)", err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("retransmitted data returned %d local packets, want one ACK (:546)", len(localPackets))
	}
	ack := packetAdapterParseTCPv4(t, localPackets[0])
	if ack.flags != 0x10 {
		t.Fatalf("retransmit ACK flags = %#x, want 0x10 (ACK) (:542)", ack.flags)
	}
	if ack.acknowledgment != 101 {
		t.Fatalf("retransmit ACK acknowledgment = %d, want 101 (clientNextSequence) (:542)", ack.acknowledgment)
	}
}

func TestPacketAdapterRejectsOutOfOrderTCPData(t *testing.T) {
	// :540 sequence != clientNextSequence + :548 out-of-order: a data packet whose
	// sequence (200) is AHEAD of the flow's expected next sequence (101) is not a
	// retransmit (tcpSequenceBefore(200, 101) is false), so the :541 replay branch
	// is skipped and :548 rejects it before any relay forwarding.
	adapter := packetAdapterEstablishedTCPFlow(t)
	now := time.Unix(1_700_000_000, 0)
	outOfOrder := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 200, 0, 0x10, nil)
	err := adapter.Ingress(context.Background(), outOfOrder, now)
	if err == nil {
		t.Fatal("out-of-order data Ingress err = nil, want non-nil (:548 should reject)")
	}
	if !strings.Contains(err.Error(), "out-of-order") {
		t.Fatalf("out-of-order err = %q, want substring \"out-of-order\" (:548)", err.Error())
	}
	if packets := adapter.DrainLocalPackets(); len(packets) != 0 {
		t.Fatalf("out-of-order data enqueued %d local packets, want 0 (:548 rejects before replay)", len(packets))
	}
}
