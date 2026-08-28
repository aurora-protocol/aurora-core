package client

// Coverage for transient queue-backpressure handling of PacketAdapter.Ingress.
// Backpressure is by definition transient: the session's bounded outbound queue
// (session.ErrBackpressure from Application.QueueFrames) or the adapter's
// bounded local-packet buffer is full. The packet must be DROPPED (nil error)
// and the session must survive — the kernel retransmits TCP and UDP loss is
// acceptable. Before this contract, PacketTUNRuntime.Serve returned the error
// and killed the tunnel, while the native ABI mapped it to CONFLICT (a drop on
// Android). Both origins are covered: the session queue (SYN path QueueFrames)
// and the adapter-local buffer (enqueueLocalPacketLocked guard).
//
// Reuses the existing harness — packetAdapterApplications (Limits:
// MaxQueuedPackets 8, ControlReservedPackets 2, so six data packets fill the
// queue) + NewPacketAdapter + packetAdapterTCPv4. In-package (package client)
// because the packetAdapter* helpers are unexported. No real network.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/transport"
)

func TestPacketAdapterDropsSYNOnSessionQueueBackpressure(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 512)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := [4]byte{10, 0, 0, 2}
	target := [4]byte{93, 184, 216, 34}

	// Fill the session's bounded outbound queue: MaxQueuedPackets 8 minus
	// ControlReservedPackets 2 leaves room for six data packets.
	for port := uint16(50000); port < 50006; port++ {
		syn := packetAdapterTCPv4(t, source, target, port, 443, 100, 0, tcpFlagSYN, nil)
		if err := adapter.Ingress(context.Background(), syn, now); err != nil {
			t.Fatalf("SYN %d ingress: %v", port, err)
		}
		adapter.DrainLocalPackets()
	}
	if adapter.FlowCount() != 6 {
		t.Fatalf("flows after queue fill = %d, want 6", adapter.FlowCount())
	}

	// The next SYN hits session.ErrBackpressure from QueueFrames: it must drop,
	// allocating no flow and answering no SYN/ACK.
	syn := packetAdapterTCPv4(t, source, target, 50006, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("backpressured SYN err = %v, want nil (drop, not kill)", err)
	}
	if adapter.FlowCount() != 6 {
		t.Fatalf("backpressured SYN left flow count = %d, want 6", adapter.FlowCount())
	}
	if packets := adapter.DrainLocalPackets(); len(packets) != 0 {
		t.Fatalf("backpressured SYN enqueued %d local packets, want 0", len(packets))
	}

	// After the queue drains, the kernel's retransmitted SYN opens the flow.
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("retransmitted SYN after queue drain: %v", err)
	}
	if adapter.FlowCount() != 7 {
		t.Fatalf("retransmitted SYN left flow count = %d, want 7", adapter.FlowCount())
	}
	if packets := adapter.DrainLocalPackets(); len(packets) != 1 {
		t.Fatalf("retransmitted SYN returned %d local packets, want one SYN/ACK", len(packets))
	}
}

func TestPacketAdapterDropsSYNOnLocalPacketBackpressure(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:        8,
		MaxPacketBytes:  1500,
		MaxLocalPackets: 1,
		UDPMode:         transport.UDPOverStreamFallback,
		Random:          bytes.NewReader(make([]byte, 512)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := [4]byte{10, 0, 0, 2}
	target := [4]byte{93, 184, 216, 34}

	// MaxLocalPackets 1: the first SYN's SYN/ACK fills the adapter-local buffer.
	first := packetAdapterTCPv4(t, source, target, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), first, now); err != nil {
		t.Fatalf("first SYN ingress: %v", err)
	}
	// The second SYN hits session.ErrBackpressure from the adapter-local guard
	// and must drop without failing the session.
	second := packetAdapterTCPv4(t, source, target, 50001, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), second, now); err != nil {
		t.Fatalf("backpressured SYN err = %v, want nil (drop, not kill)", err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("backpressured SYN left flow count = %d, want 1", adapter.FlowCount())
	}

	// After the buffer drains, the retransmitted SYN opens the flow.
	if packets := adapter.DrainLocalPackets(); len(packets) != 1 {
		t.Fatalf("drained %d local packets, want the first SYN/ACK", len(packets))
	}
	if err := adapter.Ingress(context.Background(), second, now); err != nil {
		t.Fatalf("retransmitted SYN after buffer drain: %v", err)
	}
	if adapter.FlowCount() != 2 {
		t.Fatalf("retransmitted SYN left flow count = %d, want 2", adapter.FlowCount())
	}
}
