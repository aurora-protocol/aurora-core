package packet

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func BenchmarkProtectorSeal1200(b *testing.B) {
	protector, block := benchmarkProtectorAndBlock(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protector.NextPacket = 0
		packet, err := protector.Seal(block)
		if err != nil {
			b.Fatal(err)
		}
		if len(packet.Ciphertext) == 0 || len(packet.AuthTag) != 16 {
			b.Fatal("packet seal failed")
		}
	}
}

func BenchmarkProtectorOpen1200(b *testing.B) {
	protector, block := benchmarkProtectorAndBlock(b)
	sealed, err := protector.Seal(block)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opened, err := protector.Open(sealed)
		if err != nil {
			b.Fatal(err)
		}
		if len(opened.Frames) != 1 || len(opened.Frames[0].Payload) != 1200 {
			b.Fatal("packet open failed")
		}
	}
}

func benchmarkProtectorAndBlock(b *testing.B) (*Protector, protocol.FrameBlock) {
	b.Helper()
	frame, err := protocol.NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, 1200), 0)
	if err != nil {
		b.Fatal(err)
	}
	return &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x42,
		HopLayer:        1,
		Direction:       0,
		Key:             bytes.Repeat([]byte{0x33}, 32),
		StaticIV:        bytes.Repeat([]byte{0x44}, 12),
	}, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
}
