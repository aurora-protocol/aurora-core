package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestPacketAdapterOpensTCPAndForwardsStreamData(t *testing.T) {
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
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x02, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("TCP SYN returned %d local packets, want one SYN-ACK", len(localPackets))
	}
	synAck := packetAdapterParseTCPv4(t, localPackets[0])
	if synAck.flags != 0x12 || synAck.sourcePort != 443 || synAck.destinationPort != 50000 || synAck.acknowledgment != 101 {
		t.Fatalf("unexpected synthetic SYN-ACK: %+v", synAck)
	}

	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("TCP SYN did not emit one FLOW_OPEN: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.FlowKind != 0x01 || open.LocalBindingMode != 0x03 || open.TargetPort != 443 || !bytes.Equal(open.TargetHost, []byte{93, 184, 216, 34}) {
		t.Fatalf("unexpected transparent TCP FLOW_OPEN: %+v", open)
	}

	payload := []byte("hello")
	data := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 101, synAck.sequence+1, 0x18, payload)
	if err := adapter.Ingress(context.Background(), data, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err = adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err = relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameStreamData || !bytes.Equal(blocks[0].Frames[0].Payload, payload) {
		t.Fatalf("TCP payload did not become STREAM_DATA: %+v", blocks)
	}
	response := []byte("world")
	frame, err := protocol.NewStreamDataFrame(blocks[0].Frames[0].FlowID, response, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err = relayApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	localPackets, err = adapter.HandleEncryptedPacket(context.Background(), encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(localPackets) != 1 {
		t.Fatalf("relay STREAM_DATA returned %d local packets", len(localPackets))
	}
	localData := packetAdapterParseTCPv4(t, localPackets[0])
	if localData.flags != tcpFlagACK|tcpFlagPSH || localData.sourcePort != 443 || localData.destinationPort != 50000 || !bytes.Equal(localData.payload, response) {
		t.Fatalf("unexpected relay TCP packet: %+v", localData)
	}
}

func TestPacketAdapterOpensUDPAndForwardsDatagrams(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, UDPMode: transport.UDPOverStreamFallback, Random: bytes.NewReader(bytes.Repeat([]byte{0x52}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{1, 1, 1, 1}, 40000, 443, []byte("ping"))
	if err := adapter.Ingress(context.Background(), udp, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 2 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen || blocks[0].Frames[1].FrameType != registry.FrameStreamData || !bytes.Equal(blocks[0].Frames[1].Payload, []byte("ping")) {
		t.Fatalf("UDP did not emit FLOW_OPEN and stream-fallback data: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.FlowKind != flow.FlowKindUDPAssociation || open.LocalBindingMode != flow.LocalBindingTUNPacketFlow {
		t.Fatalf("unexpected transparent UDP FLOW_OPEN: %+v", open)
	}
	frame, err := protocol.NewStreamDataFrame(open.FlowID, []byte("pong"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err = relayApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	localPackets, err := adapter.HandleEncryptedPacket(context.Background(), encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(localPackets) != 1 {
		t.Fatalf("relay UDP data returned %d local packets", len(localPackets))
	}
	localUDP := packetAdapterParseUDPv4(t, localPackets[0])
	if localUDP.sourcePort != 443 || localUDP.destinationPort != 40000 || !bytes.Equal(localUDP.payload, []byte("pong")) {
		t.Fatalf("unexpected relay UDP packet: %+v", localUDP)
	}
}

func TestPacketAdapterForwardsDNSFrameWithoutLocalResolver(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x53}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	query := packetAdapterDNSQuery(t, "example.com")
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), packet, now); err != nil {
		t.Fatal(err)
	}
	if local := adapter.DrainLocalPackets(); len(local) != 0 {
		t.Fatalf("uncaptured DNS generated %d local packets", len(local))
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameDNSMessage || !bytes.Equal(blocks[0].Frames[0].Payload, query) {
		t.Fatalf("DNS without local resolver did not emit one encrypted DNS frame: %+v", blocks)
	}
}

func TestPacketAdapterCountsPendingDNSAgainstFlowLimit(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
		MaxFlows:       1,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x54}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	dns := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, packetAdapterDNSQuery(t, "example.com"))
	if err := adapter.Ingress(context.Background(), dns, now); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("pending DNS flow count = %d, want one", adapter.FlowCount())
	}
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err == nil {
		t.Fatal("TCP flow was admitted after pending DNS reached the flow limit")
	}
	if adapter.FlowCount() != 1 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("rejected TCP flow changed adapter state")
	}
}

func TestPacketAdapterHandlesDecodedRelayBlocks(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	adapter.DrainLocalPackets()
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	frame, err := protocol.NewStreamDataFrame(open.FlowID, []byte("response"), 0)
	if err != nil {
		t.Fatal(err)
	}
	local, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{frame}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(local) != 1 || !bytes.Equal(packetAdapterParseTCPv4(t, local[0]).payload, []byte("response")) {
		t.Fatalf("decoded relay frames did not produce the local TCP response: %d packets", len(local))
	}
}

func TestPacketAdapterUsesNativeUDPDatagrams(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, UDPMode: transport.UDPNativeDatagram, Random: bytes.NewReader(bytes.Repeat([]byte{0x54}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{1, 1, 1, 1}, 40000, 443, []byte("ping"))
	if err := adapter.Ingress(context.Background(), udp, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 2 || blocks[0].Frames[1].FrameType != registry.FrameDatagramData || !bytes.Equal(blocks[0].Frames[1].Payload, []byte("ping")) {
		t.Fatalf("native UDP did not emit DATAGRAM_DATA: %+v", blocks)
	}
}

func TestPacketAdapterReopensExpiredUDPAssociation(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, UDPMode: transport.UDPNativeDatagram, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{1, 1, 1, 1}, 40000, 443, []byte("ping"))
	if err := adapter.Ingress(context.Background(), udp, now); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Ingress(context.Background(), udp, now.Add(31*time.Second)); err != nil {
		t.Fatalf("expired UDP association was not reopened: %v", err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now.Add(31*time.Second), encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 2 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen || blocks[0].Frames[1].FrameType != registry.FrameDatagramData {
		t.Fatalf("expired UDP association did not reopen as FLOW_OPEN plus DATAGRAM_DATA: %+v", blocks)
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("expired UDP association left stale mappings: %d", adapter.FlowCount())
	}
}

func TestPacketAdapterOpensIPv6TCPFlow(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2606:4700:4700::1111")
	syn, err := buildPacketAdapterTCPPacket(6, source, target, 50000, 443, 100, 0, tcpFlagSYN, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("IPv6 TCP SYN returned %d local packets", len(localPackets))
	}
	local, err := parsePacketAdapterIPPacket(localPackets[0], 1500)
	if err != nil {
		t.Fatal(err)
	}
	if local.version != 6 || local.tcp.flags != tcpFlagSYN|tcpFlagACK || local.source != target || local.target != source {
		t.Fatalf("unexpected IPv6 synthetic SYN-ACK: %+v", local)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 {
		t.Fatalf("IPv6 TCP SYN did not emit one FLOW_OPEN: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.FlowKind != flow.FlowKindTCPStream || open.LocalBindingMode != flow.LocalBindingTUNPacketFlow || !bytes.Equal(open.TargetHost, target.AsSlice()) {
		t.Fatalf("unexpected IPv6 transparent TCP FLOW_OPEN: %+v", open)
	}
}

func TestPacketAdapterReassemblesOutOfOrderIPv4TCPFragments(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	first, final := packetAdapterIPv4Fragments(t, syn, 8)

	if err := adapter.Ingress(context.Background(), final, now); err != nil {
		t.Fatalf("ingress final IPv4 fragment: %v", err)
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("incomplete IPv4 fragment set allocated a flow or local response")
	}
	if err := adapter.Ingress(context.Background(), first, now); err != nil {
		t.Fatalf("ingress initial IPv4 fragment: %v", err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("reassembled IPv4 TCP SYN returned %d local packets", len(localPackets))
	}
	local, err := parsePacketAdapterIPPacket(localPackets[0], 1500)
	if err != nil {
		t.Fatal(err)
	}
	if local.version != 4 || local.tcp.flags != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("unexpected IPv4 fragment synthetic SYN-ACK: %+v", local)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("reassembled IPv4 TCP SYN did not emit one FLOW_OPEN: %+v", blocks)
	}
}

func TestPacketAdapterRejectsIPv4FragmentBeyondFinalLength(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, bytes.Repeat([]byte{0x5a}, 24))
	far := packetAdapterIPv4FragmentAt(t, packet, 24, 8, true)
	final := packetAdapterIPv4FragmentAt(t, packet, 8, 12, false)

	if err := adapter.Ingress(context.Background(), far, now); err != nil {
		t.Fatalf("ingress far IPv4 fragment: %v", err)
	}
	if err := adapter.Ingress(context.Background(), final, now); err == nil {
		t.Fatal("fragment beyond the declared final length was accepted")
	}
	if len(adapter.ipv4Fragments) != 0 || adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("invalid IPv4 fragment set retained state")
	}
}

func TestPacketAdapterBoundsIPv4FragmentSetsByFlowLimit(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{MaxFlows: 1, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, bytes.Repeat([]byte{0x5a}, 24))
	first := packetAdapterIPv4FragmentAt(t, packet, 24, 8, true)
	second := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(second[4:6], 2)
	binary.BigEndian.PutUint16(second[10:12], 0)
	binary.BigEndian.PutUint16(second[10:12], packetAdapterChecksum(second[:20]))

	if err := adapter.Ingress(context.Background(), first, now); err != nil {
		t.Fatalf("ingress first IPv4 fragment set: %v", err)
	}
	if err := adapter.Ingress(context.Background(), second, now); err == nil {
		t.Fatal("IPv4 fragment set exceeded the configured flow limit")
	}
	if len(adapter.ipv4Fragments) != 1 || adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("fragment set limit retained unexpected state")
	}
}

func TestPacketAdapterRejectsIPv4FragmentsExceedingPacketLimit(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 128, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	packet, err := buildPacketAdapterUDPPacket(4, netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34"), 50000, 443, bytes.Repeat([]byte{0x5a}, 100), 1)
	if err != nil {
		t.Fatal(err)
	}
	packet = packetAdapterIPv4WithOptions(t, packet)
	first := packetAdapterIPv4FragmentAt(t, packet, 0, 8, true)
	final := packetAdapterIPv4FragmentAt(t, packet, 104, 4, false)

	if err := adapter.Ingress(context.Background(), first, now); err != nil {
		t.Fatalf("ingress initial IPv4 fragment: %v", err)
	}
	if err := adapter.Ingress(context.Background(), final, now); err == nil {
		t.Fatal("oversized IPv4 reassembly was accepted")
	}
	if len(adapter.ipv4Fragments) != 0 || adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("oversized IPv4 reassembly retained state")
	}
}

func TestPacketAdapterRejectsIPv4FragmentWithDontFragment(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, bytes.Repeat([]byte{0x5a}, 24))
	fragment := packetAdapterIPv4FragmentAt(t, packet, 24, 8, true)
	fragment[6] |= 0x40
	binary.BigEndian.PutUint16(fragment[10:12], 0)
	binary.BigEndian.PutUint16(fragment[10:12], packetAdapterChecksum(fragment[:20]))

	if err := adapter.Ingress(context.Background(), fragment, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("IPv4 fragment with Don't Fragment was accepted")
	}
	if len(adapter.ipv4Fragments) != 0 || adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("invalid Don't Fragment packet retained state")
	}
}

func TestPacketAdapterOpensIPv6TCPFlowWithOptionsHeaders(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2606:4700:4700::1111")
	syn, err := buildPacketAdapterTCPPacket(6, source, target, 50000, 443, 100, 0, tcpFlagSYN, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	syn = packetAdapterIPv6WithOptionsHeader(t, syn, 60)
	syn = packetAdapterIPv6WithOptionsHeader(t, syn, 0)
	syn[42] = 0x1e
	syn[43] = 2
	syn[44] = 0xa0
	syn[45] = 0xb1
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("IPv6 options TCP SYN returned %d local packets", len(localPackets))
	}
	local, err := parsePacketAdapterIPPacket(localPackets[0], 1500)
	if err != nil {
		t.Fatal(err)
	}
	if local.version != 6 || local.tcp.flags != tcpFlagSYN|tcpFlagACK || local.source != target || local.target != source {
		t.Fatalf("unexpected IPv6 options synthetic SYN-ACK: %+v", local)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 {
		t.Fatalf("IPv6 options TCP SYN did not emit one FLOW_OPEN: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.FlowKind != flow.FlowKindTCPStream || open.LocalBindingMode != flow.LocalBindingTUNPacketFlow || !bytes.Equal(open.TargetHost, target.AsSlice()) {
		t.Fatalf("unexpected IPv6 options transparent TCP FLOW_OPEN: %+v", open)
	}
}

func TestPacketAdapterOpensIPv6UDPFlowWithDestinationOptions(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, UDPMode: transport.UDPNativeDatagram, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2606:4700:4700::1111")
	packet, err := buildPacketAdapterUDPPacket(6, source, target, 50000, 443, []byte("ping"), 1)
	if err != nil {
		t.Fatal(err)
	}
	packet = packetAdapterIPv6WithOptionsHeader(t, packet, 60)
	if err := adapter.Ingress(context.Background(), packet, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 2 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen || blocks[0].Frames[1].FrameType != registry.FrameDatagramData {
		t.Fatalf("IPv6 options UDP packet did not emit FLOW_OPEN and DATAGRAM_DATA: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.FlowKind != flow.FlowKindUDPAssociation || open.LocalBindingMode != flow.LocalBindingTUNPacketFlow || !bytes.Equal(open.TargetHost, target.AsSlice()) {
		t.Fatalf("unexpected IPv6 options UDP FLOW_OPEN: %+v", open)
	}
}

func TestPacketAdapterRejectsUnsafeIPv6ExtensionsWithoutFlowAllocation(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2606:4700:4700::1111")
	packet, err := buildPacketAdapterTCPPacket(6, source, target, 50000, 443, 100, 0, tcpFlagSYN, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	malformedLength := packetAdapterIPv6WithOptionsHeader(t, packet, 60)
	malformedLength[41] = 1
	unsupportedOption := packetAdapterIPv6WithOptionsHeader(t, packet, 60)
	unsupportedOption[42] = 0x80
	routingHeader := packetAdapterIPv6WithOptionsHeader(t, packet, 43)
	fragmentHeader := packetAdapterIPv6WithFragmentHeader(t, packet)
	invalidOrder := packetAdapterIPv6WithOptionsHeader(t, packet, 0)
	invalidOrder = packetAdapterIPv6WithOptionsHeader(t, invalidOrder, 60)
	tooManyOptions := packetAdapterIPv6WithOptionsHeader(t, packet, 60)
	tooManyOptions = packetAdapterIPv6WithOptionsHeader(t, tooManyOptions, 60)
	tooManyOptions = packetAdapterIPv6WithOptionsHeader(t, tooManyOptions, 0)
	badChecksum := packetAdapterIPv6WithOptionsHeader(t, packet, 60)
	badChecksum[len(badChecksum)-1] ^= 0xff
	for name, encoded := range map[string][]byte{
		"malformed options length":  malformedLength,
		"unsupported option action": unsupportedOption,
		"routing header":            routingHeader,
		"fragment header":           fragmentHeader,
		"invalid options order":     invalidOrder,
		"too many options headers":  tooManyOptions,
		"bad transport checksum":    badChecksum,
	} {
		t.Run(name, func(t *testing.T) {
			if err := adapter.Ingress(context.Background(), encoded, time.Unix(1_700_000_000, 0)); err == nil {
				t.Fatal("unsafe IPv6 extension packet was accepted")
			}
		})
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("unsafe IPv6 extension packet allocated local adapter state")
	}
}

func TestPacketAdapterCapturesDNSWithoutPublicResolverLeak(t *testing.T) {
	application, relayApplication := packetAdapterApplications(t)
	defer application.Close()
	defer relayApplication.Close()
	queries := 0
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x63}, 32)),
		DNSAnswers: func(_ context.Context, query []byte) ([]string, error) {
			queries++
			if len(query) == 0 {
				t.Fatal("DNS callback received an empty query")
			}
			return []string{"93.184.216.34"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	query := packetAdapterDNSQuery(t, "example.com")
	dns := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), dns, now); err != nil {
		t.Fatal(err)
	}
	if queries != 1 {
		t.Fatalf("DNS callback calls = %d, want one", queries)
	}
	localPackets := adapter.DrainLocalPackets()
	if len(localPackets) != 1 {
		t.Fatalf("captured DNS query returned %d local packets", len(localPackets))
	}
	localDNS := packetAdapterParseUDPv4(t, localPackets[0])
	if localDNS.sourcePort != 53 || localDNS.destinationPort != 53000 || len(localDNS.payload) < 12 || localDNS.payload[3]&0x0f != 0 {
		t.Fatalf("unexpected synthetic local DNS response: %+v", localDNS)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameDNSMessage || !bytes.Equal(blocks[0].Frames[0].Payload, query) {
		t.Fatalf("captured DNS query leaked outside encrypted DNS frame: %+v", blocks)
	}
}

func TestPacketAdapterExchangesCapturedDNSWithoutLocalResolver(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x64}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	query := packetAdapterDNSQuery(t, "example.com")
	dns := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), dns, now); err != nil {
		t.Fatal(err)
	}
	if packets := adapter.DrainLocalPackets(); len(packets) != 0 {
		t.Fatalf("captured DNS query returned %d local packets before the relay response", len(packets))
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameDNSMessage || !bytes.Equal(blocks[0].Frames[0].Payload, query) {
		t.Fatalf("captured DNS query did not become one encrypted DNS frame: %+v", blocks)
	}
	response := packetAdapterDNSResponse(t, query)
	frame, err := protocol.NewDNSMessageFrame(blocks[0].Frames[0].FlowID, response)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err = relayApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	packets, err := adapter.HandleEncryptedPacket(context.Background(), encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("encrypted DNS response returned %d local packets, want one", len(packets))
	}
	local := packetAdapterParseUDPv4(t, packets[0])
	if local.sourcePort != 53 || local.destinationPort != 53000 || !bytes.Equal(local.payload, response) {
		t.Fatalf("unexpected local DNS response: %+v", local)
	}
}

func TestPacketAdapterRejectsOversizedRelayedDNSQuery(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: defaultPacketAdapterPacketBytes,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x65}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	query := packetAdapterDNSQuery(t, "example.com")
	query = append(query, make([]byte, 4097-len(query))...)
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), packet, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("oversized relayed DNS query was accepted")
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("oversized relayed DNS query allocated packet adapter state")
	}
}

func TestPacketAdapterRejectsMalformedRelayedDNSQuery(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x68}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), packet, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("malformed relayed DNS query was accepted")
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("malformed relayed DNS query allocated packet adapter state")
	}
}

func TestPacketAdapterRejectsOverlongRelayedDNSAdditionalRecordName(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x69}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	query := packetAdapterDNSQuery(t, "example.com")
	binary.BigEndian.PutUint16(query[10:12], 1)
	for label := 0; label < 4; label++ {
		query = append(query, 63)
		query = append(query, bytes.Repeat([]byte{'a'}, 63)...)
	}
	query = append(query, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	packet := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), packet, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("overlong relayed DNS additional-record name was accepted")
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("overlong relayed DNS additional-record name allocated packet adapter state")
	}
}

func TestPacketAdapterRejectsMismatchedDNSResponseWithoutDroppingRequest(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x66}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	query := packetAdapterDNSQuery(t, "example.com")
	request := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), request, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	flowID := blocks[0].Frames[0].FlowID
	wrong := packetAdapterDNSResponse(t, query)
	wrong[1]++
	wrongFrame, err := protocol.NewDNSMessageFrame(flowID, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{wrongFrame}}}, now); err == nil {
		t.Fatal("mismatched DNS response was accepted")
	}
	if adapter.FlowCount() != 1 {
		t.Fatalf("mismatched DNS response discarded the pending request: %d", adapter.FlowCount())
	}
	response := packetAdapterDNSResponse(t, query)
	responseFrame, err := protocol.NewDNSMessageFrame(flowID, response)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{responseFrame}}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || adapter.FlowCount() != 0 {
		t.Fatalf("valid DNS response did not complete request: packets=%d flows=%d", len(packets), adapter.FlowCount())
	}
}

func TestPacketAdapterExpiresPendingDNSRequest(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(bytes.Repeat([]byte{0x67}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	query := packetAdapterDNSQuery(t, "example.com")
	request := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{100, 64, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), request, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protocol.NewDNSMessageFrame(blocks[0].Frames[0].FlowID, packetAdapterDNSResponse(t, query))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{response}}}, now.Add(defaultPacketAdapterDNSLifetime)); err == nil {
		t.Fatal("expired DNS response was accepted")
	}
	if adapter.FlowCount() != 0 {
		t.Fatalf("expired DNS request remained allocated: %d", adapter.FlowCount())
	}
}

func TestPacketAdapterRoutesTCPFromCapturedFakeIPToMappedTarget(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(make([]byte, 32)),
		DNSAnswers: func(context.Context, []byte) ([]string, error) {
			return []string{"93.184.216.34"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	fakeIP := packetAdapterCaptureFakeIP(t, adapter, relayApplication, now)

	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, fakeIP, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	adapter.DrainLocalPackets()
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("captured fake-IP TCP connection did not emit one FLOW_OPEN: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.TargetKind != flow.TargetKindIPv4 || !bytes.Equal(open.TargetHost, []byte{93, 184, 216, 34}) || bytes.Equal(open.TargetHost, fakeIP[:]) {
		t.Fatalf("captured fake-IP TCP flow used the wrong target: %+v", open)
	}
	if open.LocalBindingMode != flow.LocalBindingTransparentFakeIP || len(open.NameBindingID) != 16 || len(open.DNSAnswerSetHash) != 48 {
		t.Fatalf("captured fake-IP TCP flow omitted its binding: %+v", open)
	}
}

func TestPacketAdapterRoutesUDPFromCapturedFakeIPToMappedTarget(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		UDPMode:        transport.UDPNativeDatagram,
		Random:         bytes.NewReader(make([]byte, 32)),
		DNSAnswers: func(context.Context, []byte) ([]string, error) {
			return []string{"93.184.216.34"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	fakeIP := packetAdapterCaptureFakeIP(t, adapter, relayApplication, now)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, fakeIP, 40000, 443, []byte("ping"))
	if err := adapter.Ingress(context.Background(), udp, now); err != nil {
		t.Fatal(err)
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 2 || blocks[0].Frames[0].FrameType != registry.FrameFlowOpen {
		t.Fatalf("captured fake-IP UDP connection did not emit FLOW_OPEN and data: %+v", blocks)
	}
	open := protocol.DecodeFlowOpen(packetAdapterReader(blocks[0].Frames[0].Payload))
	if open.FlowKind != flow.FlowKindUDPAssociation || open.TargetKind != flow.TargetKindIPv4 || !bytes.Equal(open.TargetHost, []byte{93, 184, 216, 34}) || bytes.Equal(open.TargetHost, fakeIP[:]) {
		t.Fatalf("captured fake-IP UDP flow used the wrong target: %+v", open)
	}
	if open.LocalBindingMode != flow.LocalBindingTransparentFakeIP || open.UDPFQDNMode != flow.UDPFQDNClientResolvedNameBinding || len(open.NameBindingID) != 16 || len(open.DNSAnswerSetHash) != 48 {
		t.Fatalf("captured fake-IP UDP flow omitted its binding: %+v", open)
	}
}

func TestPacketAdapterRejectsMalformedPacketsWithoutFlowAllocation(t *testing.T) {
	application, _ := packetAdapterApplications(t)
	defer application.Close()
	adapter, err := NewPacketAdapter(application, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500})
	if err != nil {
		t.Fatal(err)
	}
	malformed := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	malformed[6] |= 0x20
	if err := adapter.Ingress(context.Background(), malformed, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("fragmented IP packet was accepted")
	}
	malformed = packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	malformed[len(malformed)-1] ^= 0xff
	if err := adapter.Ingress(context.Background(), malformed, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("bad TCP checksum was accepted")
	}
	if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
		t.Fatal("malformed IP packet allocated local adapter state")
	}
}

func TestPacketAdapterRejectsRelayPacketExceedingConfiguredLimit(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 128,
		Random:         bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	adapter.DrainLocalPackets()
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.NewStreamDataFrame(1, bytes.Repeat([]byte{0x77}, 90), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := relayApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if packets, err := adapter.HandleEncryptedPacket(context.Background(), encrypted, now); err == nil || len(packets) != 0 {
		t.Fatalf("oversized relay data was delivered to local tunnel: packets=%d err=%v", len(packets), err)
	}
}

func TestPacketAdapterMapsAbnormalRelayCloseToTCPReset(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{
		MaxFlows:       8,
		MaxPacketBytes: 1500,
		Random:         bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	adapter.DrainLocalPackets()
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	close, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 1, CloseCode: protocol.ClosePolicyDenied})
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{close}}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := relayApplication.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	packets, err := adapter.HandleEncryptedPacket(context.Background(), encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 {
		t.Fatalf("abnormal relay close returned %d local packets", len(packets))
	}
	reset := packetAdapterParseTCPv4(t, packets[0])
	if reset.flags != tcpFlagRST|tcpFlagACK {
		t.Fatalf("abnormal relay close flags = 0x%x, want TCP reset", reset.flags)
	}
	if adapter.FlowCount() != 0 {
		t.Fatal("abnormal relay close left a local packet mapping")
	}
}

func TestPacketAdapterRemovesLocalTCPResetImmediately(t *testing.T) {
	clientApplication, relayApplication := packetAdapterApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	adapter, err := NewPacketAdapter(clientApplication, PacketAdapterOptions{MaxFlows: 8, MaxPacketBytes: 1500, Random: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	adapter.DrainLocalPackets()
	if _, err := adapter.NextEncryptedPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	reset := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 101, 0, tcpFlagRST, nil)
	if err := adapter.Ingress(context.Background(), reset, now); err != nil {
		t.Fatal(err)
	}
	if adapter.FlowCount() != 0 {
		t.Fatal("local TCP reset left a packet mapping")
	}
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(context.Background(), now, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameFlowClose {
		t.Fatalf("local TCP reset did not emit one FLOW_CLOSE: %+v", blocks)
	}
	close := protocol.DecodeFlowClose(packetAdapterReader(blocks[0].Frames[0].Payload))
	if close.CloseCode != protocol.CloseResetByPeer {
		t.Fatalf("local TCP reset close code = 0x%x, want reset", close.CloseCode)
	}
}

type packetAdapterTestTCP struct {
	sourcePort      uint16
	destinationPort uint16
	sequence        uint32
	acknowledgment  uint32
	flags           uint8
	payload         []byte
}

func packetAdapterTCPv4(t testing.TB, source, target [4]byte, sourcePort, targetPort uint16, sequence, acknowledgment uint32, flags uint8, payload []byte) []byte {
	t.Helper()
	packet, err := buildPacketAdapterTCPPacket(4, netip.AddrFrom4(source), netip.AddrFrom4(target), sourcePort, targetPort, sequence, acknowledgment, flags, payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func packetAdapterParseTCPv4(t testing.TB, encoded []byte) packetAdapterTestTCP {
	t.Helper()
	packet, err := parsePacketAdapterIPPacket(encoded, defaultPacketAdapterPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	return packetAdapterTestTCP{
		sourcePort:      packet.tcp.sourcePort,
		destinationPort: packet.tcp.destinationPort,
		sequence:        packet.tcp.sequence,
		acknowledgment:  packet.tcp.acknowledgment,
		flags:           packet.tcp.flags,
		payload:         append([]byte(nil), packet.tcp.payload...),
	}
}

func packetAdapterUDPv4(t testing.TB, source, target [4]byte, sourcePort, targetPort uint16, payload []byte) []byte {
	t.Helper()
	packet, err := buildPacketAdapterUDPPacket(4, netip.AddrFrom4(source), netip.AddrFrom4(target), sourcePort, targetPort, payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func packetAdapterIPv6WithOptionsHeader(t testing.TB, encoded []byte, headerType byte) []byte {
	t.Helper()
	if len(encoded) < 40 || encoded[0]>>4 != 6 {
		t.Fatal("packet adapter test packet is not IPv6")
	}
	packet := make([]byte, 0, len(encoded)+8)
	packet = append(packet, encoded[:40]...)
	packet[6] = headerType
	packet = append(packet, encoded[6], 0, 0, 0, 0, 0, 0, 0)
	packet = append(packet, encoded[40:]...)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	return packet
}

func packetAdapterIPv6WithFragmentHeader(t testing.TB, encoded []byte) []byte {
	t.Helper()
	if len(encoded) < 40 || encoded[0]>>4 != 6 {
		t.Fatal("packet adapter test packet is not IPv6")
	}
	packet := make([]byte, 0, len(encoded)+8)
	packet = append(packet, encoded[:40]...)
	packet[6] = 44
	packet = append(packet, encoded[6], 0, 0, 0, 0, 0, 0, 1)
	packet = append(packet, encoded[40:]...)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	return packet
}

func packetAdapterIPv4Fragments(t testing.TB, encoded []byte, split int) ([]byte, []byte) {
	t.Helper()
	if len(encoded) < 20 || encoded[0]>>4 != 4 {
		t.Fatal("packet adapter test packet is not IPv4")
	}
	headerLength := int(encoded[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(encoded) || split <= 0 || split%8 != 0 || split >= len(encoded)-headerLength {
		t.Fatal("packet adapter IPv4 fragment split is invalid")
	}
	payload := encoded[headerLength:]
	return packetAdapterIPv4FragmentAt(t, encoded, 0, split, true), packetAdapterIPv4FragmentAt(t, encoded, split, len(payload)-split, false)
}

func packetAdapterIPv4WithOptions(t testing.TB, encoded []byte) []byte {
	t.Helper()
	if len(encoded) < 20 || encoded[0] != 0x45 {
		t.Fatal("packet adapter test packet has no basic IPv4 header")
	}
	packet := make([]byte, 0, len(encoded)+4)
	packet = append(packet, encoded[:20]...)
	packet[0] = 0x46
	packet = append(packet, 0, 0, 0, 0)
	packet = append(packet, encoded[20:]...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], packetAdapterChecksum(packet[:24]))
	return packet
}

func packetAdapterIPv4FragmentAt(t testing.TB, encoded []byte, offset, length int, more bool) []byte {
	t.Helper()
	if len(encoded) < 20 || encoded[0]>>4 != 4 {
		t.Fatal("packet adapter test packet is not IPv4")
	}
	headerLength := int(encoded[0]&0x0f) * 4
	payload := encoded[headerLength:]
	if headerLength < 20 || headerLength > len(encoded) || offset < 0 || offset%8 != 0 || length <= 0 || offset+length > len(payload) || (more && length%8 != 0) {
		t.Fatal("packet adapter IPv4 fragment range is invalid")
	}
	fragment := append([]byte(nil), encoded[:headerLength]...)
	binary.BigEndian.PutUint16(fragment[2:4], uint16(headerLength+length))
	flags := uint16(offset / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(fragment[6:8], flags)
	binary.BigEndian.PutUint16(fragment[10:12], 0)
	binary.BigEndian.PutUint16(fragment[10:12], packetAdapterChecksum(fragment[:headerLength]))
	return append(fragment, payload[offset:offset+length]...)
}

func packetAdapterParseUDPv4(t testing.TB, encoded []byte) packetAdapterUDPPacket {
	t.Helper()
	packet, err := parsePacketAdapterIPPacket(encoded, defaultPacketAdapterPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	return packet.udp
}

func packetAdapterDNSQuery(t testing.TB, domain string) []byte {
	t.Helper()
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range bytes.Split([]byte(domain), []byte(".")) {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query
}

func packetAdapterDNSResponse(t testing.TB, query []byte) []byte {
	t.Helper()
	if len(query) < 12 {
		t.Fatal("DNS query is shorter than the header")
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	response[3] &= 0xf0
	return response
}

func packetAdapterCaptureFakeIP(t testing.TB, adapter *PacketAdapter, relayApplication *session.Application, now time.Time) [4]byte {
	t.Helper()
	query := packetAdapterDNSQuery(t, "example.com")
	dns := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 53000, 53, query)
	if err := adapter.Ingress(context.Background(), dns, now); err != nil {
		t.Fatal(err)
	}
	responses := adapter.DrainLocalPackets()
	if len(responses) != 1 {
		t.Fatalf("captured DNS query returned %d local packets", len(responses))
	}
	fakeResponse := packetAdapterParseUDPv4(t, responses[0])
	if len(fakeResponse.payload) < 4 {
		t.Fatal("captured DNS response has no synthetic address")
	}
	fakeIP := [4]byte(fakeResponse.payload[len(fakeResponse.payload)-4:])
	encrypted, err := adapter.NextEncryptedPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relayApplication.HandlePacket(context.Background(), now, encrypted); err != nil {
		t.Fatal(err)
	}
	return fakeIP
}

func packetAdapterReader(encoded []byte) *wire.Reader {
	return wire.NewReader(encoded)
}

func packetAdapterApplications(t *testing.T) (*session.Application, *session.Application) {
	t.Helper()
	clientApplication, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
		Limits:          session.Limits{MaxQueuedPackets: 8, MaxQueuedBytes: 64 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayApplication, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
		Read:            session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Limits:          session.Limits{MaxQueuedPackets: 8, MaxQueuedBytes: 64 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 64},
	})
	if err != nil {
		clientApplication.Close()
		t.Fatal(err)
	}
	return clientApplication, relayApplication
}

func FuzzPacketAdapterIngress(f *testing.F) {
	seed, err := buildPacketAdapterTCPPacket(4, netip.AddrFrom4([4]byte{10, 0, 0, 2}), netip.AddrFrom4([4]byte{93, 184, 216, 34}), 50000, 443, 100, 0, tcpFlagSYN, nil, 1)
	if err != nil {
		f.Fatal(err)
	}
	ipv4FragmentSeed, _ := packetAdapterIPv4Fragments(f, seed, 8)
	ipv6Seed, err := buildPacketAdapterTCPPacket(6, netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), 50000, 443, 100, 0, tcpFlagSYN, nil, 1)
	if err != nil {
		f.Fatal(err)
	}
	ipv6Seed = packetAdapterIPv6WithOptionsHeader(f, ipv6Seed, 60)
	malformedIPv6Seed := append([]byte(nil), ipv6Seed...)
	malformedIPv6Seed[41] = 1
	f.Add(seed)
	f.Add(ipv4FragmentSeed)
	f.Add(ipv6Seed)
	f.Add(malformedIPv6Seed)
	f.Add([]byte{0x45, 0x00, 0x00, 0x14})
	f.Add(make([]byte, 1501))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		application, relayApplication := packetAdapterApplications(t)
		defer application.Close()
		defer relayApplication.Close()
		adapter, err := NewPacketAdapter(application, PacketAdapterOptions{
			MaxFlows:        1,
			MaxPacketBytes:  1500,
			MaxLocalPackets: 1,
			Random:          bytes.NewReader(bytes.Repeat([]byte{0x6a}, 32)),
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = adapter.Ingress(context.Background(), encoded, time.Unix(1_700_000_000, 0))
		if adapter.FlowCount() > 1 {
			t.Fatalf("malformed ingress exceeded configured flow limit: %d", adapter.FlowCount())
		}
		if local := adapter.DrainLocalPackets(); len(local) > 1 {
			t.Fatalf("malformed ingress exceeded local packet limit: %d", len(local))
		}
	})
}

func BenchmarkPacketAdapterParseTCPv4(b *testing.B) {
	packet := packetAdapterTCPv4(b, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN|tcpFlagACK, bytes.Repeat([]byte{0x55}, 1024))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := parsePacketAdapterIPPacket(packet, 1500); err != nil {
			b.Fatal(err)
		}
	}
}
