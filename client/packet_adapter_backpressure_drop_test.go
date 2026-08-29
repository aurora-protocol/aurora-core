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
	"errors"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
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

func TestPacketAdapterDoesNotRefreshUDPIdleTimeOnSessionBackpressure(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       2,
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
	udp := packetAdapterUDPv4(t, source, target, 50000, 443, []byte("datagram"))
	if err := adapter.Ingress(context.Background(), udp, start); err != nil {
		t.Fatal(err)
	}

	// The UDP open occupies one of the application's six non-reserved queue
	// slots. Fill the other five so another datagram is dropped.
	for index := uint64(0); index < 5; index++ {
		frame, err := protocol.NewStreamDataFrame(100+index, []byte("fill"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := clientApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
			t.Fatalf("fill application queue at %d: %v", index, err)
		}
	}
	if got := clientApplication.Stats().QueuedPackets; got != 6 {
		t.Fatalf("queued packets = %d, want full data capacity 6", got)
	}

	// Stay inside the proxy flow's shorter idle window so the datagram reaches
	// QueueFrames and is dropped there, rather than reopening the association.
	droppedAt := start.Add(29 * time.Second)
	if err := adapter.Ingress(context.Background(), udp, droppedAt); err != nil {
		t.Fatalf("backpressured UDP ingress = %v, want nil drop", err)
	}
	adapter.mu.Lock()
	var lastActivity time.Time
	for _, mapping := range adapter.flowsByID {
		lastActivity = mapping.lastActivity
	}
	adapter.mu.Unlock()
	if !lastActivity.Equal(start) {
		t.Fatalf("dropped UDP datagram refreshed idle time to %v, want %v", lastActivity, start)
	}

	// At the original deadline a different datagram triggers the sweep. Its
	// pending close cannot enter the still-full queue, but local reclamation is
	// already committed and must free the flow slot.
	trigger := packetAdapterUDPv4(t, source, target, 50001, 443, []byte("trigger"))
	if err := adapter.Ingress(context.Background(), trigger, start.Add(defaultPacketAdapterUDPIdleLifetime)); err != nil {
		t.Fatalf("expiry trigger under backpressure: %v", err)
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("dropped UDP traffic retained %d idle flows, want zero", adapter.FlowCount())
	}
	adapter.mu.Lock()
	pendingCloses := len(adapter.pendingFlowCloses)
	adapter.mu.Unlock()
	if pendingCloses != 1 {
		t.Fatalf("pending close count = %d, want one reclaimed association", pendingCloses)
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

func TestPacketAdapterRetainsLocalResetOnSessionBackpressure(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 128)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := [4]byte{10, 0, 0, 2}
	target := [4]byte{93, 184, 216, 34}
	var firstFlowID uint64
	var firstSynthetic packetAdapterTestTCP

	// Six opens fill the session data queue. Keep the first flow's synthetic
	// sequence so its local RST models a real kernel response.
	for port := uint16(50000); port < 50006; port++ {
		syn := packetAdapterTCPv4(t, source, target, port, 443, 100, 0, tcpFlagSYN, nil)
		if err := adapter.Ingress(context.Background(), syn, now); err != nil {
			t.Fatalf("SYN %d ingress: %v", port, err)
		}
		packets := adapter.DrainLocalPackets()
		if len(packets) != 1 {
			t.Fatalf("SYN %d returned %d packets, want one", port, len(packets))
		}
		if port == 50000 {
			firstSynthetic = packetAdapterParseTCPv4(t, packets[0])
			adapter.mu.Lock()
			for flowID := range adapter.flowsByID {
				firstFlowID = flowID
			}
			adapter.mu.Unlock()
		}
	}
	if firstFlowID == 0 {
		t.Fatal("first TCP flow has no flow ID")
	}

	rst := packetAdapterTCPv4(t, source, target, 50000, 443, 101, firstSynthetic.sequence+1, tcpFlagRST|tcpFlagACK, nil)
	if err := adapter.Ingress(context.Background(), rst, now); err != nil {
		t.Fatalf("backpressured local RST: %v", err)
	}
	if adapter.FlowCount() != 5 {
		t.Fatalf("flow count after local RST = %d, want dead tuple retired", adapter.FlowCount())
	}
	adapter.mu.Lock()
	if len(adapter.pendingFlowCloses) != 1 {
		adapter.mu.Unlock()
		t.Fatalf("pending reset closes = %d, want one", len(adapter.pendingFlowCloses))
	}
	pendingPayload := adapter.pendingFlowCloses[0].Payload
	reader := wire.NewReader(pendingPayload)
	pendingClose := protocol.DecodeFlowClose(reader)
	adapter.mu.Unlock()
	if reader.Err() != nil || !reader.EOF() || pendingClose.FlowID != firstFlowID || pendingClose.CloseCode != protocol.CloseResetByPeer {
		t.Fatalf("pending reset close = %+v, decode error %v", pendingClose, reader.Err())
	}
	if allPacketAdapterBytesZero(pendingPayload) {
		t.Fatal("pending reset payload was zeroed before it was queued")
	}

	// The carrier writer first drains one full-queue packet, then its next call
	// uses the freed slot for the retained close. No new local ingress is needed
	// to release the relay-side socket.
	closeFrames := 0
	for packetIndex := range 7 {
		encrypted, err := adapter.NextEncryptedPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if packetIndex == 0 {
			adapter.mu.Lock()
			pending := len(adapter.pendingFlowCloses)
			adapter.mu.Unlock()
			if pending != 1 || allPacketAdapterBytesZero(pendingPayload) {
				t.Fatalf("reset close after first drain: pending=%d zeroed=%v, want retained", pending, allPacketAdapterBytesZero(pendingPayload))
			}
		}
		if packetIndex == 1 {
			adapter.mu.Lock()
			pending := len(adapter.pendingFlowCloses)
			adapter.mu.Unlock()
			if pending != 0 || !allPacketAdapterBytesZero(pendingPayload) {
				t.Fatalf("reset close after writer retry: pending=%d zeroed=%v, want queued and zeroed", pending, allPacketAdapterBytesZero(pendingPayload))
			}
		}
		blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range blocks {
			for _, frame := range block.Frames {
				if frame.FrameType != registry.FrameFlowClose {
					continue
				}
				closeFrames++
				decoded := protocol.DecodeFlowClose(wire.NewReader(frame.Payload))
				if decoded.FlowID != firstFlowID || decoded.CloseCode != protocol.CloseResetByPeer {
					t.Fatalf("queued reset close = %+v", decoded)
				}
			}
		}
	}
	if closeFrames != 1 {
		t.Fatalf("queued reset closes = %d, want one", closeFrames)
	}
	if adapter.FlowCount() != 5 {
		t.Fatalf("flow count after reset drain = %d, want 5", adapter.FlowCount())
	}

	// With the dead tuple gone and the close delivered, the local stack can
	// immediately reuse the same four-tuple for a fresh connection.
	reused := packetAdapterTCPv4(t, source, target, 50000, 443, 300, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), reused, now); err != nil {
		t.Fatalf("reused tuple SYN: %v", err)
	}
	if adapter.FlowCount() != 6 {
		t.Fatalf("flow count after tuple reuse = %d, want 6", adapter.FlowCount())
	}
}

func TestPacketAdapterSplitsOversizedPendingFlowCloses(t *testing.T) {
	clientApplication, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
		Limits:          session.Limits{MaxQueuedPackets: 8, MaxQueuedBytes: 24 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       maximumPacketAdapterFlows,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 8)),
	})
	if err != nil {
		t.Fatal(err)
	}

	frames := make([]protocol.AuroraFrame, 0, maximumPacketAdapterFlows)
	var firstPayload, lastPayload []byte
	for flowID := uint64(1); flowID <= maximumPacketAdapterFlows; flowID++ {
		frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
			FlowID:    flowID,
			CloseCode: protocol.CloseIdleTimeout,
		})
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
		if flowID == 1 {
			firstPayload = frame.Payload
		}
		lastPayload = frame.Payload
	}
	adapter.mu.Lock()
	adapter.pendingFlowCloses = frames
	err = adapter.queuePendingFlowClosesLocked(context.Background())
	pending := len(adapter.pendingFlowCloses)
	adapter.mu.Unlock()
	if !errors.Is(err, session.ErrBackpressure) {
		t.Fatalf("oversized close queue error = %v, want backpressure after partial progress", err)
	}
	stats := clientApplication.Stats()
	if stats.QueuedPackets == 0 || pending <= 0 || pending >= maximumPacketAdapterFlows {
		t.Fatalf("oversized close progress: queued=%d pending=%d, want both nonzero", stats.QueuedPackets, pending)
	}
	if !allPacketAdapterBytesZero(firstPayload) {
		t.Fatal("successfully queued close payload was not zeroed")
	}
	if allPacketAdapterBytesZero(lastPayload) {
		t.Fatal("unqueued close payload was zeroed before ownership was released")
	}

	adapter.Close()
	if !allPacketAdapterBytesZero(lastPayload) {
		t.Fatal("adapter close did not zero retained close payload")
	}
}

func allPacketAdapterBytesZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}
