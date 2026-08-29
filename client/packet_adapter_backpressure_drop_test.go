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

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
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

func TestPacketAdapterRetriesExpiredUDPClosesAfterSessionBackpressure(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	source := [4]byte{10, 0, 0, 2}
	target := [4]byte{93, 184, 216, 34}

	// Six data packets fill the application queue after its two reserved control
	// slots. All six UDP associations then become idle together.
	for port := uint16(50000); port < 50006; port++ {
		packet := packetAdapterUDPv4(t, source, target, port, 443, []byte("datagram"))
		if err := adapter.Ingress(context.Background(), packet, start); err != nil {
			t.Fatalf("UDP ingress %d: %v", port, err)
		}
	}
	expiredAt := start.Add(defaultPacketAdapterUDPIdleLifetime)
	trigger := packetAdapterUDPv4(t, source, target, 50006, 443, []byte("trigger"))
	if err := adapter.Ingress(context.Background(), trigger, expiredAt); err != nil {
		t.Fatalf("expiry under backpressure: %v", err)
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("expired UDP flow count = %d, want zero", adapter.FlowCount())
	}
	adapter.mu.Lock()
	pending := len(adapter.pendingFlowCloses)
	adapter.mu.Unlock()
	if pending != 6 {
		t.Fatalf("pending UDP closes = %d, want 6", pending)
	}

	// Free one packet slot. The next ingress retries and queues the close block;
	// its own datagram is then dropped because the queue is full again.
	encrypted, err := clientApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relayApplication.HandlePacket(context.Background(), expiredAt, encrypted); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Ingress(context.Background(), trigger, expiredAt.Add(time.Second)); err != nil {
		t.Fatalf("expiry close retry: %v", err)
	}
	adapter.mu.Lock()
	pending = len(adapter.pendingFlowCloses)
	adapter.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending UDP closes after retry = %d, want zero", pending)
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("backpressured trigger created %d flows, want zero", adapter.FlowCount())
	}

	closeFrames := 0
	for range 6 {
		encrypted, err := clientApplication.NextPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		blocks, err := relayApplication.HandlePacket(context.Background(), expiredAt.Add(time.Second), encrypted)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range blocks {
			for _, frame := range block.Frames {
				if frame.FrameType == registry.FrameFlowClose {
					closeFrames++
				}
			}
		}
	}
	if closeFrames != 6 {
		t.Fatalf("queued UDP close frames = %d, want 6", closeFrames)
	}
	if _, err := clientApplication.TryNextPacket(); err != session.ErrNoPacket {
		t.Fatalf("packet after UDP close retry = %v, want no packet", err)
	}
}
