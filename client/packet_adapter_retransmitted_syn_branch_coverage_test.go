package client

// Adversarial white-box coverage for the count-0 retransmitted-SYN handling of
// PacketAdapter.ingressTCPLocked (client/packet_adapter.go:486-494). After a SYN
// has opened a flow for a tuple, a SECOND SYN for the same tuple re-enters the
// SYN block (:482) but now flowsByTuple[tuple] is non-nil (:481), so the :486
// `if mapping != nil` guard fires instead of the flow-creation path (:496-532).
// The :486 body splits on whether the retransmitted SYN's sequence matches the
// flow's expected clientNextSequence:
//
//   - :487 if mapping.clientNextSequence != packet.tcp.sequence+1
//     -> a retransmitted SYN whose sequence does NOT match the existing flow is a
//        protocol error ("TCP SYN does not match existing packet flow", :488).
//   - :490/:494 otherwise -> the retransmitted SYN matches (the client is
//        re-sending the original SYN, e.g. a lost SYN-ACK); the adapter replays
//        the SYN-ACK (:490 makeTCPPacketLocked SYN|ACK, :494 enqueueLocalPacket).
//
// Coverage targets (baseline measured on main; bodies COUNT 0 while the :486
// condition was already evaluated):
//   - packet_adapter.go:486.21,487.59 0   — `if mapping != nil` (re-SYN with existing flow)
//   - packet_adapter.go:487.59,489.5 0    — sequence-mismatch error body (:488)
//   - packet_adapter.go:490.4,491.18 0   — SYN-ACK replay makeTCPPacket assignment
//   - packet_adapter.go:494.4,494.47 0    — SYN-ACK replay enqueue return
//
// The :486 body is COUNT 0 because the existing adapter tests only ever send a
// SYN ONCE (TestPacketAdapterOpensTCPAndForwardsStreamData sends one SYN then
// switches to data packets); no test sends a second SYN for an already-open flow,
// so :486 is true-checked only by the data-packet path's unrelated :534 mapping==nil
// case. The :534 unknown-flow guard was covered separately (sibling file
// packet_adapter_unknown_flow_branch_coverage_test.go); this file covers the
// :486 retransmitted-SYN vein.
//
// Reuses the existing adapter harness — packetAdapterApplications +
// NewPacketAdapter + packetAdapterTCPv4 + packetAdapterParseTCPv4 (the same
// builder/parser TestPacketAdapterOpensTCPAndForwardsStreamData uses). The first
// SYN establishes the flow (mapping.clientNextSequence = SYN.sequence+1 = 101);
// the second SYN re-enters :482 and hits :486. NewPacketAdapter auto-wires
// proxy: NewLocalProxy() (packet_adapter.go:230), so the first SYN's
// OpenTCPFromFakeIPFrame + QueueFrames succeed with no extra setup. The re-SYN
// path (:486-494) does NOT touch the proxy — it only reads mapping fields and
// enqueues a local packet — so the second SYN needs no relay-side interaction.
//
// In-package (package client) because ingressTCPLocked and the packetAdapter*
// helpers are unexported. No real network. No nil-context literal (a real
// context.Background() is supplied). This file adds only TestXxx entry points
// and references existing in-package helpers + stdlib bytes/context/strings/
// testing/time and the transport package already imported by
// packet_adapter_test.go, so it adds no U1000 surface.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/transport"
)

// packetAdapterRetransmittedSynAdapter builds an adapter and opens one TCP flow
// with a SYN (sequence 100) for a fixed tuple, draining the synthetic SYN-ACK so
// the retransmitted-SYN tests start from a clean local-packet buffer. The flow's
// mapping has clientNextSequence = 101.
func packetAdapterRetransmittedSynAdapter(t *testing.T) *PacketAdapter {
	t.Helper()
	clientApplication, relayApplication := packetAdapterApplications(t)
	t.Cleanup(func() { _ = clientApplication.Close() })
	t.Cleanup(func() { _ = relayApplication.Close() })
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		// Plenty of random bytes for the first SYN (serverSequence + flow ID) and
		// the retransmitted SYN's SYN-ACK replay; readUint32Locked fails the SYN if
		// the reader is exhausted, so use a generous buffer.
		Random: bytes.NewReader(make([]byte, 512)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x02, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("initial SYN Ingress err = %v, want nil (flow must open before :486 is reachable)", err)
	}
	adapter.DrainLocalPackets()
	return adapter
}

func TestPacketAdapterReplaysSynAckForRetransmittedSyn(t *testing.T) {
	// :486 mapping != nil + :490/:494 SYN-ACK replay: a retransmitted SYN with the
	// SAME sequence as the original (100) matches the flow's clientNextSequence
	// (101 == 100+1), so the :487 mismatch check is skipped and the adapter replays
	// the SYN-ACK (:490) and enqueues it (:494) instead of re-opening the flow.
	adapter := packetAdapterRetransmittedSynAdapter(t)
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x02, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("retransmitted SYN (matching) Ingress err = %v, want nil (:486 should replay SYN-ACK)", err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("retransmitted SYN returned %d local packets, want one SYN-ACK (:490/:494)", len(localPackets))
	}
	synAck := packetAdapterParseTCPv4(t, localPackets[0])
	if synAck.flags != 0x12 {
		t.Fatalf("retransmitted SYN-ACK flags = %#x, want 0x12 (SYN|ACK) (:490)", synAck.flags)
	}
	if synAck.acknowledgment != 101 {
		t.Fatalf("retransmitted SYN-ACK acknowledgment = %d, want 101 (clientNextSequence) (:490)", synAck.acknowledgment)
	}
}

func TestPacketAdapterRejectsRetransmittedSynWithMismatchedSequence(t *testing.T) {
	// :486 mapping != nil + :487/:488 sequence-mismatch: a retransmitted SYN whose
	// sequence does NOT match the flow's clientNextSequence (101 != 200+1=201) is a
	// protocol error — the :487 guard fires and rejects before any SYN-ACK replay.
	adapter := packetAdapterRetransmittedSynAdapter(t)
	now := time.Unix(1_700_000_000, 0)
	mismatched := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 200, 0, 0x02, nil)
	err := adapter.Ingress(context.Background(), mismatched, now)
	if err == nil {
		t.Fatal("retransmitted SYN (mismatched sequence) Ingress err = nil, want non-nil (:487/:488 should reject)")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched-SYN err = %q, want substring \"does not match\" (:488)", err.Error())
	}
	if packets := adapter.DrainLocalPackets(); len(packets) != 0 {
		t.Fatalf("mismatched SYN enqueued %d local packets, want 0 (:488 rejects before replay)", len(packets))
	}
}
