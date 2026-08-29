package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/transport"
)

// A kernel with ECN enabled (net.ipv4.tcp_ecn=1) sets ECE|CWR on every outgoing
// SYN. The adapter cannot signal ECN support, but the connection must still
// open: it answers with a plain SYN|ACK, which is exactly how RFC 3168 declines
// ECN. Failing here would tear the tunnel down on the very first connection.
func TestPacketAdapterOpensFlowForECNNegotiatingSYN(t *testing.T) {
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
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN|tcpFlagECE|tcpFlagCWR, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("ECN-negotiating SYN err = %v, want nil", err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("ECN-negotiating SYN flow count = %d, want 1", adapter.FlowCount())
	}
	packets := adapter.DrainLocalPackets()
	if len(packets) != 1 {
		t.Fatalf("ECN-negotiating SYN returned %d local packets, want one SYN/ACK", len(packets))
	}
	response := packetAdapterParseTCPv4(t, packets[0])
	if response.flags != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("ECN-negotiating SYN response flags = 0x%x, want plain SYN|ACK (ECN declined)", response.flags)
	}
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatalf("ECN-negotiating SYN queued no encrypted open frame: %v", err)
	}
}

// Other well-formed SYN shapes the tunnel cannot serve — a TCP Fast Open SYN
// carrying data, or an inbound SYN|ACK — are dropped. The kernel retries a Fast
// Open SYN without its payload, so a drop costs a retransmit; failing would
// take every other flow down with it.
func TestPacketAdapterDropsUnservableSYNVariants(t *testing.T) {
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

	fastOpen := packetAdapterTCPv4(t, source, target, 50000, 443, 100, 0, tcpFlagSYN, []byte("fast open payload"))
	if err := adapter.Ingress(context.Background(), fastOpen, now); err != nil {
		t.Fatalf("Fast Open SYN err = %v, want nil (drop, not tunnel teardown)", err)
	}
	synAck := packetAdapterTCPv4(t, source, target, 50001, 443, 100, 200, tcpFlagSYN|tcpFlagACK, nil)
	if err := adapter.Ingress(context.Background(), synAck, now); err != nil {
		t.Fatalf("inbound SYN|ACK err = %v, want nil (drop, not tunnel teardown)", err)
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatalf("unservable SYN variants allocated adapter state: flows=%d", adapter.FlowCount())
	}
}
