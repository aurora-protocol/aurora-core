package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/transport"
)

// A server-initiated close arrives as a relay FLOW_CLOSE before the kernel's
// own FIN. The relay close marks the mapping peerClosed and keeps it alive so
// the local half can still drain; the kernel FIN that follows completes the
// mutual close and must retire the mapping. Otherwise every server-closed
// connection (the common HTTP case) leaks an entry in flowsByTuple/flowsByID
// until the flow limit is reached, and the stale tuple poisons a later
// connection that reuses the same local port.
func TestPacketAdapterRetiresFlowWhenLocalFINFollowsRelayClose(t *testing.T) {
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
	adapter.DrainLocalPackets()
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The origin server closes first: the relay sends FLOW_CLOSE and the adapter
	// hands the kernel a FIN|ACK while keeping the half-open mapping.
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
	relayFIN := packetAdapterParseTCPv4(t, packets[0])
	if relayFIN.flags != tcpFlagFIN|tcpFlagACK {
		t.Fatalf("relay close flags = 0x%x, want FIN|ACK", relayFIN.flags)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("half-closed flow count = %d, want 1", adapter.FlowCount())
	}

	// The kernel answers with its own FIN, completing the mutual close.
	fin := packetAdapterTCPv4(t, source, target, 50000, 443, 101, relayFIN.sequence+1, tcpFlagFIN|tcpFlagACK, nil)
	if err := adapter.Ingress(context.Background(), fin, now); err != nil {
		t.Fatalf("kernel FIN after relay close: %v", err)
	}
	adapter.DrainLocalPackets()
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("flow survived the mutual close: %d", adapter.FlowCount())
	}

	// The local port is reusable, so a later connection with a fresh ISN must
	// open a new flow instead of colliding with the retired mapping.
	reopened := packetAdapterTCPv4(t, source, target, 50000, 443, 300, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), reopened, now); err != nil {
		t.Fatalf("SYN reopen after mutual close: %v", err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("reopened flow count = %d, want 1", adapter.FlowCount())
	}
	responses := adapter.DrainLocalPackets()
	if len(responses) != 1 {
		t.Fatalf("reopen returned %d local packets, want one SYN/ACK", len(responses))
	}
	if response := packetAdapterParseTCPv4(t, responses[0]); response.flags != tcpFlagSYN|tcpFlagACK || response.acknowledgment != 301 {
		t.Fatalf("reopen response = %+v, want SYN|ACK acking 301", response)
	}
}
