package client

// Drop-not-kill coverage for well-formed local packets the tunnel cannot serve.
// PacketAdapter.Ingress must DROP these packets (return nil, allocate no state)
// instead of reporting an error, because they arise from routine host traffic —
// any local process sending ICMP/ICMPv6 (ping, neighbor discovery) must not be
// able to terminate PacketTUNRuntime.Serve or the native mobile session. Only
// malformed or contradictory packets stay terminal.
//
// Builders reuse the in-package packetAdapter* helpers and checksum functions so
// the packets are structurally valid (correct lengths and IP header checksums)
// and only their protocol/extension is unservable.

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/transport"
)

func TestPacketAdapterDropsUnsupportedProtocolPackets(t *testing.T) {
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

	tcpv6, err := buildPacketAdapterTCPPacket(6, netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), 50000, 443, 100, 0, tcpFlagSYN, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	optionAction := packetAdapterIPv6WithOptionsHeader(t, tcpv6, 60)
	optionAction[42] = 0x80 // option action bits: discard packet (RFC 8200)
	for name, encoded := range map[string][]byte{
		"ICMPv4 echo":                packetAdapterICMPv4Echo(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}),
		"ICMPv6 echo":                packetAdapterICMPv6Echo(t, "2001:db8::2", "2606:4700:4700::1111"),
		"IPv6 routing header":        packetAdapterIPv6WithOptionsHeader(t, tcpv6, 43),
		"IPv6 discard-action option": optionAction,
	} {
		t.Run(name, func(t *testing.T) {
			if err := adapter.Ingress(context.Background(), encoded, now); err != nil {
				t.Fatalf("unsupported-protocol ingress err = %v, want nil (drop, not kill)", err)
			}
			if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
				t.Fatal("dropped packet allocated adapter state")
			}
		})
	}

	// The adapter must remain fully functional after the drops.
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatalf("TCP SYN after unsupported-protocol drops: %v", err)
	}
	if adapter.FlowCount() != 1 || len(adapter.DrainLocalPackets()) != 1 {
		t.Fatal("TCP SYN after drops did not open a flow and answer SYN/ACK")
	}
}

func TestPacketAdapterMalformedPacketsStayTerminal(t *testing.T) {
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

	badChecksum := packetAdapterICMPv4Echo(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34})
	badChecksum[10] ^= 0xff // corrupt the IPv4 header checksum: malformed, not unsupported
	for name, encoded := range map[string][]byte{
		"corrupt IPv4 checksum": badChecksum,
		"truncated IPv4 header": {0x45, 0x00, 0x00, 0x14},
	} {
		t.Run(name, func(t *testing.T) {
			if err := adapter.Ingress(context.Background(), encoded, now); err == nil {
				t.Fatal("malformed packet ingress err = nil, want non-nil (parse errors stay terminal)")
			}
			if adapter.FlowCount() != 0 || len(adapter.DrainLocalPackets()) != 0 {
				t.Fatal("malformed packet allocated adapter state")
			}
		})
	}
}

func packetAdapterICMPv4Echo(t testing.TB, source, target [4]byte) []byte {
	t.Helper()
	payload := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // echo request
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1 // ICMP
	copy(packet[12:16], source[:])
	copy(packet[16:20], target[:])
	binary.BigEndian.PutUint16(packet[10:12], packetAdapterChecksum(packet[:20]))
	copy(packet[20:], payload)
	return packet
}

func packetAdapterICMPv6Echo(t testing.TB, source, target string) []byte {
	t.Helper()
	payload := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01} // echo request
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = 58 // ICMPv6
	packet[7] = 64
	sourceBytes := netip.MustParseAddr(source).As16()
	targetBytes := netip.MustParseAddr(target).As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], targetBytes[:])
	copy(packet[40:], payload)
	return packet
}
