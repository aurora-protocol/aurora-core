package packet

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func sealEncodedProtector(t *testing.T, routeInstanceID uint64, packetNumber uint64) *Protector {
	t.Helper()
	return &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: routeInstanceID,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
		NextPacket:      packetNumber,
	}
}

// TestSealEncodedMatchesSealThenEncode is the contract that matters: the
// single-buffer path must produce exactly the bytes the two-step path produces,
// for every packet number and route instance length that changes the header
// layout.
func TestSealEncodedMatchesSealThenEncode(t *testing.T) {
	payloads := []int{1, 63, 64, 1200, 65535}
	routeInstanceIDs := []uint64{0, 1, 63, 64, 16383, 16384, 1 << 30}
	packetNumbers := []uint64{0, 1, 63, 64, 16383, 16384, 1 << 30}

	for _, payloadLength := range payloads {
		for _, routeInstanceID := range routeInstanceIDs {
			for _, packetNumber := range packetNumbers {
				frame, err := protocol.NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, payloadLength), 0)
				if err != nil {
					t.Fatal(err)
				}
				block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}

				reference := sealEncodedProtector(t, routeInstanceID, packetNumber)
				pkt, err := reference.Seal(block)
				if err != nil {
					t.Fatalf("payload=%d route=%d packet=%d seal: %v", payloadLength, routeInstanceID, packetNumber, err)
				}
				want, err := EncodeAuroraPacket(pkt)
				if err != nil {
					t.Fatal(err)
				}

				subject := sealEncodedProtector(t, routeInstanceID, packetNumber)
				got, err := subject.SealEncoded(block)
				if err != nil {
					t.Fatalf("payload=%d route=%d packet=%d seal encoded: %v", payloadLength, routeInstanceID, packetNumber, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("payload=%d route=%d packet=%d: encoded packet differs\n got %x\nwant %x",
						payloadLength, routeInstanceID, packetNumber, got, want)
				}
				if subject.NextPacket != reference.NextPacket {
					t.Fatalf("packet counter advanced to %d, want %d", subject.NextPacket, reference.NextPacket)
				}
				// The result must decode and open back to the original block.
				decoded, err := DecodeAuroraPacket(got)
				if err != nil {
					t.Fatalf("decode sealed packet: %v", err)
				}
				opener := sealEncodedProtector(t, routeInstanceID, packetNumber)
				opened, err := opener.Open(decoded)
				if err != nil {
					t.Fatalf("open sealed packet: %v", err)
				}
				if len(opened.Frames) != 1 || len(opened.Frames[0].Payload) != payloadLength {
					t.Fatalf("opened block has %d frames", len(opened.Frames))
				}
			}
		}
	}
}

func TestSealEncodedAllocatesOnce(t *testing.T) {
	frame, err := protocol.NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, 1200), 0)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
	protector := sealEncodedProtector(t, 0x42, 0)
	allocations := testing.AllocsPerRun(50, func() {
		encoded, err := protector.SealEncoded(block)
		if err != nil {
			t.Fatalf("seal encoded: %v", err)
		}
		if len(encoded) == 0 {
			t.Fatal("sealed packet is empty")
		}
	})
	// One buffer carries the header, ciphertext and tag; the rest is the
	// nonce and associated data the AEAD needs.
	if allocations > 3 {
		t.Fatalf("SealEncoded allocated %.0f times per packet, want at most 3", allocations)
	}
}

func TestSealEncodedRejectsReservedDirection(t *testing.T) {
	protector := sealEncodedProtector(t, 1, 0)
	protector.Direction = 2
	if _, err := protector.SealEncoded(protocol.FrameBlock{}); err == nil {
		t.Fatal("reserved packet direction was sealed")
	}
	if protector.NextPacket != 0 {
		t.Fatalf("rejected packet advanced the counter to %d", protector.NextPacket)
	}
}

func TestSealEncodedRejectsFrameForOtherDirection(t *testing.T) {
	protector := sealEncodedProtector(t, 1, 0)
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FrameKeyUpdate}}}
	if _, err := protector.SealEncoded(block); err == nil {
		t.Fatal("frame for the other direction was sealed")
	}
	if protector.NextPacket != 0 {
		t.Fatalf("rejected packet advanced the counter to %d", protector.NextPacket)
	}
}

func TestSealEncodedClearsNonceScratchOnRekey(t *testing.T) {
	frame, err := protocol.NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, 64), 0)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
	protector := sealEncodedProtector(t, 0x42, 0)
	if _, err := protector.SealEncoded(block); err != nil {
		t.Fatalf("seal encoded: %v", err)
	}
	if protector.seal == nil || protector.seal.nonce == ([12]byte{}) {
		t.Fatal("sealing left the nonce scratch empty")
	}
	// A retained nonce discloses the static IV it came from, so replacing the
	// traffic material must not leave the previous nonce resident.
	if err := protector.ReplaceMaterial(bytesOf(0x55, 32), bytesOf(0x66, 12)); err != nil {
		t.Fatalf("replace material: %v", err)
	}
	if protector.seal.nonce != ([12]byte{}) {
		t.Fatalf("nonce scratch retained %x after rekey", protector.seal.nonce)
	}

	// Destroy drops the pointer, so the scratch it referenced must be cleared
	// before that happens or the nonce stays resident on the heap.
	if _, err := protector.SealEncoded(block); err != nil {
		t.Fatalf("seal encoded after rekey: %v", err)
	}
	scratch := protector.seal
	if scratch.nonce == ([12]byte{}) {
		t.Fatal("second seal left the nonce scratch empty")
	}
	protector.Destroy()
	if scratch.nonce != ([12]byte{}) || scratch.ad != ([64]byte{}) {
		t.Fatalf("destroy left seal scratch resident: nonce=%x", scratch.nonce)
	}
}

func BenchmarkProtectorSealEncoded1200(b *testing.B) {
	protector, block := benchmarkProtectorAndBlock(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protector.NextPacket = 0
		encoded, err := protector.SealEncoded(block)
		if err != nil {
			b.Fatal(err)
		}
		if len(encoded) == 0 {
			b.Fatal("packet seal failed")
		}
	}
}

func BenchmarkProtectorSealThenEncode1200(b *testing.B) {
	protector, block := benchmarkProtectorAndBlock(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protector.NextPacket = 0
		pkt, err := protector.Seal(block)
		if err != nil {
			b.Fatal(err)
		}
		encoded, err := EncodeAuroraPacket(pkt)
		if err != nil {
			b.Fatal(err)
		}
		if len(encoded) == 0 {
			b.Fatal("packet seal failed")
		}
	}
}
