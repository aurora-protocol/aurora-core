package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/transport"
)

// A local RST retires the packet-adapter flow immediately and tells the relay.
// The relay answers with its own FLOW_CLOSE, and any data it had already put on
// the wire arrives afterwards. Both name a flow the adapter has forgotten, and
// both must drop: failing the frame block tears the whole tunnel down.
func TestPacketAdapterDropsRelayFramesAfterLocalReset(t *testing.T) {
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

	// The local application resets the connection: the adapter removes the flow
	// and queues FLOW_CLOSE for the relay.
	reset := packetAdapterTCPv4(t, source, target, 50000, 443, 101, synthetic.sequence+1, tcpFlagRST|tcpFlagACK, nil)
	if err := adapter.Ingress(context.Background(), reset, now); err != nil {
		t.Fatalf("local RST: %v", err)
	}
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("flow survived the local reset: %d", adapter.FlowCount())
	}

	// Relay data that was already in flight when the reset was sent.
	data, err := protocol.NewStreamDataFrame(1, []byte("in flight relay bytes"), 0)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{data}}}, now)
	if err != nil {
		t.Fatalf("relay data for reset flow err = %v, want nil (drop, not tunnel teardown)", err)
	}
	if len(packets) != 0 {
		t.Fatalf("relay data for reset flow produced %d local packets, want none", len(packets))
	}

	// The relay's answering FLOW_CLOSE for the same retired flow.
	closeFrame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 1, CloseCode: protocol.CloseNormal, FinalSequenceHintPresent: true, FinalSequenceHint: 101})
	if err != nil {
		t.Fatal(err)
	}
	packets, err = adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{closeFrame}}}, now)
	if err != nil {
		t.Fatalf("relay close for reset flow err = %v, want nil (drop, not tunnel teardown)", err)
	}
	if len(packets) != 0 {
		t.Fatalf("relay close for reset flow produced %d local packets, want none", len(packets))
	}
}
