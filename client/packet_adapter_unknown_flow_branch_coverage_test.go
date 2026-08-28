package client

// Adversarial white-box coverage for the unknown-flow TCP guard of
// PacketAdapter.ingressTCPLocked (client/packet_adapter.go:552). After the
// SYN-handling block (:500-550), a non-SYN TCP packet looks up its tuple in
// flowsByTuple (:499); when no live flow exists (no mapping, wrong kind, or
// localClosed) the guard DROPS the packet instead of failing the session.
//
// Rationale for drop-not-kill: the guard fires for routine kernel traffic —
// the final ACK of a clean close handshake arrives after the adapter removed
// the flow, late retransmits arrive after teardown, and half-close ACKs arrive
// after the local FIN. No flow state exists to desync, so dropping cannot
// corrupt anything; a genuine kernel/adapter divergence still surfaces as a
// sequence mismatch on a live flow (:572 out-of-order stays terminal).
//
// Reuses the existing adapter harness — packetAdapterApplications +
// NewPacketAdapter + packetAdapterTCPv4 (the same builder
// TestPacketAdapterOpensTCPAndForwardsStreamData uses). In-package (package
// client) because ingressTCPLocked and the packetAdapter* helpers are
// unexported. No real network. This file adds only TestXxx entry points and
// references existing in-package helpers + stdlib
// bytes/context/testing/time and the protocol/transport packages already
// imported by packet_adapter_test.go, so it adds no U1000 surface.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/transport"
)

func TestPacketAdapterDropsTCPDataForUnknownFlow(t *testing.T) {
	// :552 mapping == nil: a non-SYN TCP packet (ACK-only) for a tuple with no prior
	// SYN is dropped — no error, no flow state, no local packets.
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x41}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	ack := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 200, 0x10, nil)
	if err := adapter.Ingress(context.Background(), ack, now); err != nil {
		t.Fatalf("Ingress(ACK, no prior flow) err = %v, want nil (unknown-tuple drop)", err)
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("unknown-tuple drop allocated adapter state")
	}
}

func TestPacketAdapterDropsTCPCloseHandshakeTrailingPackets(t *testing.T) {
	// Full clean close against a real kernel stack: SYN opens the flow, the kernel
	// FINs (localClosed), the relay answers with a normal FlowClose (adapter queues
	// FIN|ACK and REMOVES the flow), and the kernel's RFC 793 final ACK of that FIN
	// then arrives with mapping == nil. Before the drop-not-kill guard this trailing
	// ACK terminated the tunnel on every clean close.
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := [4]byte{10, 0, 0, 2}
	target := [4]byte{93, 184, 216, 34}

	syn := packetAdapterTCPv4(t, source, target, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("SYN: %v", err)
	}
	synthetic := packetAdapterParseTCPv4(t, adapter.DrainLocalPackets()[0])
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Kernel FIN (sequence 101 == clientNextSequence after the SYN).
	fin := packetAdapterTCPv4(t, source, target, 50000, 443, 101, synthetic.sequence+1, tcpFlagFIN|tcpFlagACK, nil)
	if err := adapter.Ingress(context.Background(), fin, now); err != nil {
		t.Fatalf("kernel FIN: %v", err)
	}
	adapter.DrainLocalPackets()
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Relay answers the close; the adapter queues FIN|ACK for the kernel and
	// removes the flow.
	closeFrame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 1, CloseCode: protocol.CloseNormal, FinalSequenceHintPresent: true, FinalSequenceHint: 101})
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{closeFrame}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := relayApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	packets, err := adapter.HandleEncryptedPacket(context.Background(), encrypted, now)
	if err != nil {
		t.Fatalf("relay close: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("relay close returned %d local packets, want one FIN|ACK", len(packets))
	}
	finAck := packetAdapterParseTCPv4(t, packets[0])
	if finAck.flags != tcpFlagFIN|tcpFlagACK {
		t.Fatalf("relay close flags = 0x%x, want FIN|ACK", finAck.flags)
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("flow survived the mutual close: %d", adapter.FlowCount())
	}

	// The kernel's final ACK of the adapter's FIN, and a late retransmitted
	// data segment for the dead tuple, must both drop without an error.
	finalACK := packetAdapterTCPv4(t, source, target, 50000, 443, 102, finAck.sequence+1, tcpFlagACK, nil)
	if err := adapter.Ingress(context.Background(), finalACK, now); err != nil {
		t.Fatalf("final close-handshake ACK err = %v, want nil (drop, not kill)", err)
	}
	late := packetAdapterTCPv4(t, source, target, 50000, 443, 101, finAck.sequence+1, tcpFlagACK, []byte("late"))
	if err := adapter.Ingress(context.Background(), late, now); err != nil {
		t.Fatalf("late retransmit to closed tuple err = %v, want nil (drop, not kill)", err)
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("trailing close-handshake packets allocated adapter state")
	}

	// A new SYN for the same tuple must open a fresh flow (no tombstone
	// poisoning): one SYN/ACK locally, one encrypted open frame, one flow.
	reopened := packetAdapterTCPv4(t, source, target, 50000, 443, 300, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), reopened, now); err != nil {
		t.Fatalf("SYN reopen after close: %v", err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("reopened flow count = %d, want 1", adapter.FlowCount())
	}
	responses := adapter.DrainLocalPackets()
	if len(responses) != 1 {
		t.Fatalf("reopen returned %d local packets, want one SYN/ACK", len(responses))
	}
	if response := packetAdapterParseTCPv4(t, responses[0]); response.flags != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("reopen response flags = 0x%x, want SYN|ACK", response.flags)
	}
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatalf("reopened flow queued no encrypted open frame: %v", err)
	}
}
