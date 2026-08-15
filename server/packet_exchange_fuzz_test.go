package server

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func fuzzPacketBatchSeeds() [][]byte {
	ipv4 := append([]byte{0x45, 0x00, 0x00, 0x14}, bytes.Repeat([]byte{0x00}, 16)...)
	ipv6 := append([]byte{0x60, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x00}, 36)...)
	one, err := EncodePacketBatch(PacketBatch{Packets: [][]byte{ipv4}, ProtocolNumbers: []uint16{2}})
	if err != nil {
		panic(err)
	}
	two, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{ipv4, ipv6},
		ProtocolNumbers: []uint16{2, 30},
	})
	if err != nil {
		panic(err)
	}
	empty := make([]byte, 2)
	binary.BigEndian.PutUint16(empty, 0)
	return [][]byte{nil, {}, {0x00}, empty, one, two}
}

// FuzzDecodePacketBatch drives the batch parser the cover-carrier packet
// exchange feeds with request bodies, so it runs on bytes an unauthenticated
// peer controls. A batch that decodes has to re-encode to the exact bytes it
// came from, and has to respect the bounds the exchanger relies on before it
// hands packets to a tunnel.
func FuzzDecodePacketBatch(f *testing.F) {
	for _, seed := range fuzzPacketBatchSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		batch, err := DecodePacketBatch(data)
		if err != nil {
			return
		}
		if len(batch.Packets) != len(batch.ProtocolNumbers) {
			t.Fatalf("decoded %d packets with %d protocol numbers", len(batch.Packets), len(batch.ProtocolNumbers))
		}
		if len(batch.Packets) > maxPacketBatchPackets {
			t.Fatalf("decoded %d packets, above the %d bound", len(batch.Packets), maxPacketBatchPackets)
		}
		for i, packet := range batch.Packets {
			if len(packet) == 0 || len(packet) > maxPacketBytes {
				t.Fatalf("packet %d is %d bytes, outside 1..%d", i, len(packet), maxPacketBytes)
			}
			// The exchanger routes on the protocol number, so it must agree
			// with the packet it was decoded alongside.
			if family := packetProtocolNumber(packet); family != batch.ProtocolNumbers[i] {
				t.Fatalf("packet %d has family %d but protocol number %d", i, family, batch.ProtocolNumbers[i])
			}
		}
		reencoded, err := EncodePacketBatch(batch)
		if err != nil {
			t.Fatalf("decoded batch failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("batch re-encoded to %x, want %x", reencoded, data)
		}
	})
}
