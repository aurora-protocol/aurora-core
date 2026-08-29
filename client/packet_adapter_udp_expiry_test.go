package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
)

// A UDP conversation has no close handshake, so nothing retires its adapter
// mapping the way a TCP FIN/RST does. Without an idle sweep the mirror table
// grows until the adapter refuses every new flow, which on a real device turns
// a few minutes of DNS and QUIC traffic into a tunnel that admits nothing.
func TestPacketAdapterExpiresIdleUDPAssociations(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       4,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x58}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, []byte("datagram"))
	if err := adapter.Ingress(context.Background(), udp, start); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("flow count = %d, want one UDP association", adapter.FlowCount())
	}
	adapter.mu.Lock()
	var firstFlowID uint64
	for flowID := range adapter.flowsByID {
		firstFlowID = flowID
	}
	adapter.mu.Unlock()
	if firstFlowID == 0 {
		t.Fatal("first UDP association has no flow ID")
	}

	// Still inside the idle window: the association must survive.
	early := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50001, 443, []byte("datagram"))
	if err := adapter.Ingress(context.Background(), early, start.Add(defaultPacketAdapterUDPIdleLifetime-time.Second)); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 2 {
		t.Fatalf("flow count = %d, want both associations before the idle window elapses", adapter.FlowCount())
	}
	adapter.mu.Lock()
	var secondFlowID uint64
	for flowID := range adapter.flowsByID {
		if flowID != firstFlowID {
			secondFlowID = flowID
		}
	}
	adapter.mu.Unlock()
	if secondFlowID == 0 {
		t.Fatal("second UDP association has no distinct flow ID")
	}

	// Past the idle window both earlier associations are reclaimed, leaving
	// only the association created by this packet.
	late := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50002, 443, []byte("datagram"))
	if err := adapter.Ingress(context.Background(), late, start.Add(2*defaultPacketAdapterUDPIdleLifetime)); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("flow count = %d, want idle UDP associations reclaimed", adapter.FlowCount())
	}

	// The first two packets opened the associations. The idle sweep queues one
	// ordered close block before the packet that opens the replacement flow.
	for range 2 {
		encrypted, err := clientApplication.NextPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relayApplication.HandlePacket(context.Background(), start, encrypted); err != nil {
			t.Fatal(err)
		}
	}
	expiredPacket, err := clientApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), start.Add(2*defaultPacketAdapterUDPIdleLifetime), expiredPacket)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 2 {
		t.Fatalf("expired UDP close block = %+v, want two frames", blocks)
	}
	wantFlowIDs := map[uint64]bool{firstFlowID: true, secondFlowID: true}
	for _, frame := range blocks[0].Frames {
		if frame.FrameType != registry.FrameFlowClose {
			t.Fatalf("expired UDP frame type = 0x%x, want FLOW_CLOSE", frame.FrameType)
		}
		reader := wire.NewReader(frame.Payload)
		close := protocol.DecodeFlowClose(reader)
		if reader.Err() != nil || !reader.EOF() {
			t.Fatalf("decode expired UDP FLOW_CLOSE: %v", reader.Err())
		}
		if !wantFlowIDs[close.FlowID] {
			t.Fatalf("expired UDP FLOW_CLOSE flow ID = %d, want one of %v", close.FlowID, wantFlowIDs)
		}
		delete(wantFlowIDs, close.FlowID)
		if close.CloseCode != protocol.CloseIdleTimeout {
			t.Fatalf("expired UDP FLOW_CLOSE code = %d, want idle timeout", close.CloseCode)
		}
	}
	if len(wantFlowIDs) != 0 {
		t.Fatalf("missing expired UDP FLOW_CLOSE frames for %v", wantFlowIDs)
	}
}

// An association carrying inbound-only traffic (a long download) must not be
// swept while the relay is still delivering datagrams on it.
func TestPacketAdapterKeepsUDPAssociationsCarryingRelayTraffic(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       4,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x59}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, []byte("datagram"))
	if err := adapter.Ingress(context.Background(), udp, start); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	var mapping *packetAdapterFlow
	for _, candidate := range adapter.flowsByID {
		mapping = candidate
	}
	adapter.mu.Unlock()
	if mapping == nil {
		t.Fatal("UDP association was not recorded")
	}

	// Relay traffic arriving late in the idle window refreshes the mapping.
	refreshed := start.Add(defaultPacketAdapterUDPIdleLifetime - time.Second)
	adapter.mu.Lock()
	mapping.lastActivity = refreshed
	adapter.mu.Unlock()

	probe := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50003, 443, []byte("datagram"))
	if err := adapter.Ingress(context.Background(), probe, refreshed.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 2 {
		t.Fatalf("flow count = %d, want the refreshed association retained", adapter.FlowCount())
	}
}

// A relay confirmation can be queued behind enough carrier traffic that the
// local association expires first. The adapter has already forgotten that flow,
// so the stale confirmation must be dropped rather than fail every live flow on
// the shared session.
func TestPacketAdapterDropsUDPTargetConfirmAfterAssociationExpiry(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       4,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPOverStreamFallback,
		Random:         bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0)
	first := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, []byte("first"))
	if err := adapter.Ingress(context.Background(), first, start); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	var expiredFlowID uint64
	for flowID := range adapter.flowsByID {
		expiredFlowID = flowID
	}
	adapter.mu.Unlock()
	if expiredFlowID == 0 {
		t.Fatal("UDP association was not recorded")
	}

	// Any later ingress runs the idle sweep before adding its own association.
	later := start.Add(defaultPacketAdapterUDPIdleLifetime)
	second := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50001, 443, []byte("second"))
	if err := adapter.Ingress(context.Background(), second, later); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	_, retained := adapter.flowsByID[expiredFlowID]
	adapter.mu.Unlock()
	if retained {
		t.Fatal("idle UDP association was not expired")
	}

	confirm, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           expiredFlowID,
		TargetKind:       0x01,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: make([]byte, 48),
		TTLSeconds:       60,
	})
	if err != nil {
		t.Fatal(err)
	}
	packets, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{confirm}}}, later)
	if err != nil {
		t.Fatalf("late UDP target confirmation ended the session: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("late UDP target confirmation produced %d local packets, want none", len(packets))
	}
}
