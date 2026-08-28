package client

// Adversarial white-box coverage for the count-0 TCP FIN handling of
// PacketAdapter.ingressTCPLocked (client/packet_adapter.go:582-601). Once a flow
// is established (a SYN opened it, mapping.clientNextSequence = 101), a non-SYN
// data packet whose sequence matches clientNextSequence skips :564 (sequence
// match) and reaches the forwarding block (:574-582). :582 checks the FIN flag:
//
//   - :582 fin := packet.tcp.flags&tcpFlagFIN != 0; if fin { ... }
//     - :584 frame, err := protocol.NewFlowCloseFrame(FlowClose{... FinalSequenceHint: seq+payload+1})
//     - :588 frames = append(frames, frame)
//     - :590 len(frames) != 0 -> :594 QueueFrames(forward the close frame)
//     - :598 if fin { :599 clientNextSequence++; :600 localClosed = true; :601 proxy.Close }
//     - :603/:607 emit the final ACK
//
// Coverage targets (baseline measured on main after #343/#344; bodies COUNT 0
// while the :582 condition was already evaluated by the happy-path data packet,
// which sends data WITHOUT the FIN flag so fin is false-checked):
//   - packet_adapter.go:583.9,585.17 0  — NewFlowCloseFrame call (the if-fin body)
//   - packet_adapter.go:588.3,588.33 0  — append the close frame to frames
//   - packet_adapter.go:598.10,602.4 0  — post-queue fin block (seq++/localClosed/Close)
//
// Deliberately NOT covered (deferred, like the :566/:508 makeTCPPacket-error
// guards in the sibling files): the two error-return guards that only fire when
// the frame builders themselves error:
//   - packet_adapter.go:585.17,587.4 0  — `if err != nil { return err }` after
//     :584 NewFlowCloseFrame; only fires on an invalid FlowClose (bad CloseCode),
//     which CloseNormal never produces. Not a pillar.
//   - packet_adapter.go:604.17,606.4 0  — `if err != nil { return err }` after
//     :603 makeTCPPacketLocked (final ACK); same deferred makeTCPPacket-error guard.
//
// The :583-601 bodies were COUNT 0 at the baseline because the adapter tests
// only ever sent data packets WITHOUT the FIN flag
// (TestPacketAdapterOpensTCPAndForwardsStreamData forwards payload data then
// tears down out-of-band); no test sent a clean in-band FIN, so :582 was
// false-checked and the :583/:588/:598 FIN bodies were never taken. The
// retransmitted-SYN (:504) and data-sequence (:564-572) veins were covered by
// the sibling files #343 and #344; this file covers the FIN close vein — no
// overlap.
//
// Reuses the established-flow helper defined by the sibling #344 file
// (packetAdapterEstablishedTCPFlow: builds an adapter, opens one TCP flow with a
// SYN sequence 100, drains the SYN-ACK; mapping.clientNextSequence = 101). A
// subsequent data packet with the FIN flag set and the EXACT expected sequence
// (101) skips :564 and reaches :582. NewPacketAdapter auto-wires proxy:
// NewLocalProxy() (packet_adapter.go:236) and packetAdapterApplications wires the
// relay application, so :594 QueueFrames (forwarding the close frame) succeeds
// with no extra setup. Empty payload keeps the FIN path isolated (skips :576
// SendTCP, which is already covered by the happy path).
//
// In-package (package client) because ingressTCPLocked and the packetAdapter*
// helpers are unexported. No real network. No nil-context literal (a real
// context.Background() is supplied) -> no SA1012 surface. This file adds only a
// TestXxx entry point and references the existing in-package helper + stdlib
// context/testing/time, so it adds no U1000 surface.

import (
	"context"
	"testing"
	"time"
)

func TestPacketAdapterClosesLocalFlowForTCPFin(t *testing.T) {
	// :583/:588/:598 — a data packet with the FIN flag set and the EXACT expected
	// sequence (101) is a clean in-band connection close: the adapter builds a
	// FlowCloseFrame (:584), appends it (:588), forwards via QueueFrames (:594),
	// then marks the flow closed (:599/:600) and emits a final ACK (:603/:607).
	adapter := packetAdapterEstablishedTCPFlow(t)
	now := time.Unix(1_700_000_000, 0)
	// FIN (0x01), sequence 101 (== clientNextSequence), empty payload -> :564 false
	// (sequence matches), :575 payload skipped, :582 fin=true, :584 NewFlowCloseFrame,
	// :588 append, :590 frames!=0, :594 QueueFrames, :598 fin -> :599/:600/:601,
	// :603 final ACK, :607 enqueue. Returns nil.
	fin := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 101, 0, 0x01, nil)
	if err := adapter.Ingress(context.Background(), fin, now); err != nil {
		t.Fatalf("FIN data Ingress err = %v, want nil (:583/:588/:598 should close flow cleanly)", err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("FIN data returned %d local packets, want one final ACK (:607)", len(localPackets))
	}
	ack := packetAdapterParseTCPv4(t, localPackets[0])
	if ack.flags != 0x10 {
		t.Fatalf("FIN ACK flags = %#x, want 0x10 (ACK) (:603)", ack.flags)
	}
	if ack.acknowledgment != 102 {
		t.Fatalf("FIN ACK acknowledgment = %d, want 102 (clientNextSequence 101 +1 for the FIN) (:599)", ack.acknowledgment)
	}
	// :600 localClosed: a subsequent non-SYN packet for the same flow now hits the
	// :552 guard (mapping present but localClosed) and is DROPPED — half-close ACKs
	// are routine kernel traffic and must not fail the session. The drop still
	// proves the FIN closed the flow: nothing is forwarded or answered.
	more := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 102, 0, 0x10, nil)
	if err := adapter.Ingress(context.Background(), more, now); err != nil {
		t.Fatalf("post-FIN packet err = %v, want nil (:552 localClosed should drop)", err)
	}
	if packets := adapter.DrainLocalPackets(); len(packets) != 0 {
		t.Fatalf("post-FIN packet enqueued %d local packets, want 0 (:552 drops)", len(packets))
	}
}
