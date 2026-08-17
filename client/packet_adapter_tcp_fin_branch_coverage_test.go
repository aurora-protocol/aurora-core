package client

// Adversarial white-box coverage for the count-0 TCP FIN handling of
// PacketAdapter.ingressTCPLocked (client/packet_adapter.go:558-577). Once a flow
// is established (a SYN opened it, mapping.clientNextSequence = 101), a non-SYN
// data packet whose sequence matches clientNextSequence skips :540 (sequence
// match) and reaches the forwarding block (:550-558). :558 checks the FIN flag:
//
//   - :558 fin := packet.tcp.flags&tcpFlagFIN != 0; if fin { ... }
//     - :560 frame, err := protocol.NewFlowCloseFrame(FlowClose{... FinalSequenceHint: seq+payload+1})
//     - :564 frames = append(frames, frame)
//     - :566 len(frames) != 0 -> :570 QueueFrames(forward the close frame)
//     - :574 if fin { :575 clientNextSequence++; :576 localClosed = true; :577 proxy.Close }
//     - :579/:583 emit the final ACK
//
// Coverage targets (baseline measured on main after #343/#344; bodies COUNT 0
// while the :558 condition was already evaluated by the happy-path data packet,
// which sends data WITHOUT the FIN flag so fin is false-checked):
//   - packet_adapter.go:559.9,561.17 0  — NewFlowCloseFrame call (the if-fin body)
//   - packet_adapter.go:564.3,564.33 0  — append the close frame to frames
//   - packet_adapter.go:574.10,578.4 0  — post-queue fin block (seq++/localClosed/Close)
//
// Deliberately NOT covered (deferred, like the :543/:491 makeTCPPacket-error guards
// in the sibling files): the two error-return guards that only fire when the
// frame builders themselves error:
//   - packet_adapter.go:561.17,563.4 0  — `if err != nil { return err }` after
//     :560 NewFlowCloseFrame; only fires on an invalid FlowClose (bad CloseCode),
//     which CloseNormal never produces. Not a pillar.
//   - packet_adapter.go:580.17,582.4 0  — `if err != nil { return err }` after
//     :579 makeTCPPacketLocked (final ACK); same deferred makeTCPPacket-error guard.
//
// The :558-577 bodies are COUNT 0 because the existing adapter tests only ever
// send data packets WITHOUT the FIN flag (TestPacketAdapterOpensTCPAndForwardsStreamData
// forwards payload data then tears down out-of-band); no test sends a clean
// in-band FIN, so :558 is false-checked and the :559/:564/:574 FIN bodies are
// never taken. The retransmitted-SYN (:486) and data-sequence (:540-548) veins
// were covered by the sibling files #343 and #344; this file covers the FIN
// close vein — no overlap.
//
// Reuses the established-flow helper defined by the sibling #344 file
// (packetAdapterEstablishedTCPFlow: builds an adapter, opens one TCP flow with a
// SYN sequence 100, drains the SYN-ACK; mapping.clientNextSequence = 101). A
// subsequent data packet with the FIN flag set and the EXACT expected sequence
// (101) skips :540 and reaches :558. NewPacketAdapter auto-wires proxy:
// NewLocalProxy() (packet_adapter.go:230) and packetAdapterApplications wires the
// relay application, so :570 QueueFrames (forwarding the close frame) succeeds
// with no extra setup. Empty payload keeps the FIN path isolated (skips :551
// SendTCP, which is already covered by the happy path).
//
// In-package (package client) because ingressTCPLocked and the packetAdapter*
// helpers are unexported. No real network. No nil-context literal (a real
// context.Background() is supplied) -> no SA1012 surface. This file adds only a
// TestXxx entry point and references the existing in-package helper + stdlib
// context/strings/testing/time, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPacketAdapterClosesLocalFlowForTCPFin(t *testing.T) {
	// :559/:564/:574 — a data packet with the FIN flag set and the EXACT expected
	// sequence (101) is a clean in-band connection close: the adapter builds a
	// FlowCloseFrame (:560), appends it (:564), forwards via QueueFrames (:570),
	// then marks the flow closed (:575/:576) and emits a final ACK (:579/:583).
	adapter := packetAdapterEstablishedTCPFlow(t)
	now := time.Unix(1_700_000_000, 0)
	// FIN (0x01), sequence 101 (== clientNextSequence), empty payload -> :540 false
	// (sequence matches), :551 payload skipped, :558 fin=true, :560 NewFlowCloseFrame,
	// :564 append, :566 frames!=0, :570 QueueFrames, :574 fin -> :575/:576/:577,
	// :579 final ACK, :583 enqueue. Returns nil.
	fin := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 101, 0, 0x01, nil)
	if err := adapter.Ingress(context.Background(), fin, now); err != nil {
		t.Fatalf("FIN data Ingress err = %v, want nil (:559/:564/:574 should close flow cleanly)", err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("FIN data returned %d local packets, want one final ACK (:583)", len(localPackets))
	}
	ack := packetAdapterParseTCPv4(t, localPackets[0])
	if ack.flags != 0x10 {
		t.Fatalf("FIN ACK flags = %#x, want 0x10 (ACK) (:579)", ack.flags)
	}
	if ack.acknowledgment != 102 {
		t.Fatalf("FIN ACK acknowledgment = %d, want 102 (clientNextSequence 101 +1 for the FIN) (:575)", ack.acknowledgment)
	}
	// :576 localClosed: a subsequent data packet for the same flow must now be
	// rejected by the :534 localClosed guard (proving the FIN actually closed the
	// flow, not just forwarded a frame).
	more := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 102, 0, 0x10, nil)
	err := adapter.Ingress(context.Background(), more, now)
	if err == nil || !strings.Contains(err.Error(), "unknown flow") {
		t.Fatalf("post-FIN data err = %v, want non-nil containing \"unknown flow\" (:576 localClosed should reject)", err)
	}
}
