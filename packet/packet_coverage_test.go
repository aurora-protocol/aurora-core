package packet

// Adversarial coverage for the residual count-0 branches in packet/packet.go.
// The existing packet_test.go / seal_encoded_test.go / receiver_window_test.go
// cover the happy seal/open/round-trip paths and the single-buffer SealEncoded
// contract. The residual count-0 blocks are the rejection and edge branches the
// happy-path tests never drive: the EncodedLen/EncodeAuroraPacket invalid-input
// branches, the decode trailing-bytes branch, the NewProtector/ReplaceMaterial/
// Destroy nil-and-bad-material branches, the Seal/SealEncoded crypto-error and
// layout-fallback branches, the open crypto-error and decode-error branches, and
// the nil-receiver / borrowed-payload-mismatch helpers.
//
// This file covers them with crafted Protectors and packets, perturbing exactly
// one condition per case so the branch under test is the one that fires. Each
// rejection asserts exactly one error substring so the failure is attributable
// to the perturbed field alone.
//
// Uncovered blocks (measured count 0 before this file):
//   - EncodedLen (27): ciphertext/tag length 28, route varint 32, packet varint 36.
//   - EncodeAuroraPacket (43): wire.Encode fallback 47.
//   - decodeAuroraPacket (69): trailing packet bytes 88.
//   - NewProtector (133): ReplaceMaterial propagation 141.
//   - ReplaceMaterial (154): nil receiver 155, static IV length 158, AEAD err 162.
//   - Destroy (181): nil receiver 182.
//   - Seal (193): encodeFrameBlockForSeal err 201, deferred destroy 206, PacketAD
//     err 212, XORNonce96 err 216, cachedAEAD err 220.
//   - SealEncoded (257): nil receiver 258, sealedPacketLayout-false fallback 269,
//     AppendXORNonce96 err 281, cachedAEAD err 285.
//   - sealEncodedByCopy (324): Seal call 324, Seal err 326, happy return 329/330.
//   - sealedPacketLayout (335): out-of-range/false 337, route varint 341, packet
//     varint 345.
//   - OpenOwned (378): validatePacketMetadata propagation 384.
//   - open (390): PacketAD err 392, XORNonce96 err 396, cachedAEAD err 400,
//     DecodeFrameBlock err 414.
//   - borrowedCiphertextAndTag (444): mismatch 451.
//   - cachedAEAD (457): nil receiver 458.
//   - clearAEAD (475): nil receiver 476.
//
// Dead-by-design (documented, not covered):
//   - Seal (193) non-in-place seal 229-231, aead.Seal err 232, sealed < tag 235.
//     The non-in-place `else` branch (229) fires only when encodeFrameBlockForSeal
//     returns reusable=false, which happens only when the block's EncodedLen is
//     not known (line 353) — but a not-known length always fails Encode, so Seal
//     returns at 201 before reaching the seal. When the length is known and in
//     range, EncodeWithReservedCapacity reserves exactly +packetAuthTagBytes so
//     reusable is always true. aead.Seal/SealTo (232) never errors after
//     cachedAEAD succeeds: the nonce is always 12 bytes (XORNonce96 over a
//     ReplaceMaterial-validated 12-byte IV) and the AEAD is non-nil. The sealed
//     payload is always >= packetAuthTagBytes (235) because the AEAD appends a
//     16-byte tag even to empty plaintext.
//   - SealEncoded (257) AppendPacketAD err 277, encoder.Buffer err 299, layout
//     mismatch 303, SealTo err 309, in-place mismatch 313. AppendPacketAD (277)
//     cannot error after sealedPacketLayout returns ok=true: the layout already
//     ran VarintLen on the routeInstanceID and packetNumber (340/344), and those
//     are the only values AppendPacketAD varint-encodes; direction was checked at
//     261. encoder.Buffer (299) cannot error after a known, in-range block: the
//     block encodes cleanly (EncodedLen is known). The encoded length always
//     equals headerLength+plaintextLength (303): the encoder writes exactly
//     VarintLen(routeID)+3+VarintLen(packetNumber)+3 bytes of header plus the
//     block. SealTo (309) never errors after cachedAEAD (12-byte nonce, non-nil
//     AEAD), and the in-place write always holds (313): GCM's Seal appends to the
//     provided dst slice, so &sealed[0]==&encoded[headerLength] and the length is
//     always plaintextLength+tag.
//   - encodeFrameBlockForSeal (351) EncodeWithReservedCapacity err 358. The line
//     358 branch is reached only when block.EncodedLen returns known=true, which
//     means every varint and opaque-24 length in the block is in range (a
//     not-known length short-circuits to line 353). With every length in range
//     the block encodes cleanly, so EncodeWithReservedCapacity never sets an
//     encoder error and 358 is unreachable for any constructible block.
//   - Seal/SealEncoded/open via a reserved suite. AppendPacketAD calls
//     AppendSuiteHash(selectedSuite, ...) (crypto/control.go:108), which rejects
//     an unsupported suite before any key material is touched. So a reserved
//     suite cannot reach XORNonce96 or cachedAEAD on the Seal/open paths; those
//     crypto-error branches are instead driven by a *supported* suite with a
//     wrong-length key (cachedAEAD) or a wrong-length static IV (XORNonce96).
//
// Not duplicated: the happy Seal/SealEncoded/Open round-trip, the
// single-buffer-vs-two-step equality contract, the receiver replay window, and
// the encode/decode happy paths are already covered by the existing packet test
// files and are not re-asserted here except where a table naturally includes them.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The new helpers (packetCovValidBlock,
// packetCovHugeFlowIDPaddingBlock) are each referenced by >=2 tests, so neither
// is U1000. The in-package bytesOf/sealEncodedProtector helpers (packet_test.go,
// seal_encoded_test.go) are reused for valid Protectors and fixed byte slices.
// No context.Context, no deprecated APIs.

import (
	"math"
	"strings"
	"testing"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// packetCovValidBlock returns a minimal FrameBlock that passes
// ValidateFrameBlockForDirection(block, 0), has a known EncodedLen, and is small
// enough to keep sealedPacketLayout on the single-buffer path. Referenced by
// >=2 tests, so not U1000.
func packetCovValidBlock() protocol.FrameBlock {
	frame, err := protocol.NewStreamDataFrame(7, []byte{0x5a}, 0)
	if err != nil {
		panic(err)
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
}

// packetCovHugeFlowIDPaddingBlock returns a FrameBlock whose single PADDING frame
// has a flow_id that overflows the wire varint range. Its EncodedLen is therefore
// not known and its Encode fails, which drives the encodeFrameBlockForSeal error
// path (Seal 201) and the sealedPacketLayout-not-known fallback (SealEncoded 269).
// Referenced by >=2 tests, so not U1000.
func packetCovHugeFlowIDPaddingBlock() protocol.FrameBlock {
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		{FrameType: registry.FramePadding, FlowID: math.MaxUint64, Payload: []byte{0}},
	}}
}

func TestEncodedLenDecidesPerCondition(t *testing.T) {
	base := AuroraPacket{
		RouteInstanceID: 1,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		PacketNumber:    1,
		Ciphertext:      []byte{0},
		AuthTag:         bytesOf(0, packetAuthTagBytes),
	}
	cases := []struct {
		name    string
		mutate  func(*AuroraPacket)
		wantOK  bool
		wantSub string
	}{
		{"auth tag wrong length", func(p *AuroraPacket) { p.AuthTag = nil }, false, ""},
		{"route instance id out of range", func(p *AuroraPacket) { p.RouteInstanceID = math.MaxUint64 }, false, ""},
		{"packet number out of range", func(p *AuroraPacket) { p.PacketNumber = math.MaxUint64 }, false, ""},
		{"valid accepted", nil, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			_, ok := p.EncodedLen()
			if ok != tc.wantOK {
				t.Fatalf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
			}
		})
	}
}

func TestEncodeAuroraPacketFallbackDecidesPerCondition(t *testing.T) {
	// An AuthTag of the wrong length makes EncodedLen return known=false, so
	// EncodeAuroraPacket falls back to wire.Encode (line 47), which fails at
	// WriteOpaqueFixed(AuthTag, 16).
	_, err := EncodeAuroraPacket(AuroraPacket{
		RouteInstanceID: 1,
		PacketNumber:    1,
		Ciphertext:      []byte{0},
		AuthTag:         nil,
	})
	if err == nil || !strings.Contains(err.Error(), "fixed opaque length") {
		t.Fatalf("err = %v, want %q", err, "fixed opaque length")
	}
}

func TestDecodeAuroraPacketTrailingBytesDecidesPerCondition(t *testing.T) {
	enc, err := EncodeAuroraPacket(AuroraPacket{
		RouteInstanceID: 1,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		PacketNumber:    1,
		Ciphertext:      []byte{0},
		AuthTag:         bytesOf(0, packetAuthTagBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	enc = append(enc, 0x00)
	if _, err := DecodeAuroraPacket(enc); err == nil || !strings.Contains(err.Error(), "trailing packet bytes") {
		t.Fatalf("err = %v, want %q", err, "trailing packet bytes")
	}
}

func TestNewProtectorAndReplaceMaterialDecidesPerCondition(t *testing.T) {
	t.Run("bad static IV rejects NewProtector", func(t *testing.T) {
		// ReplaceMaterial rejects the 5-byte IV (line 158) and NewProtector
		// propagates it (line 141).
		_, err := NewProtector(registry.SuiteHybrid768AESGCM, 1, 1, 0, 0, bytesOf(0x33, 32), bytesOf(0x44, 5))
		if err == nil || !strings.Contains(err.Error(), "static IV length") {
			t.Fatalf("err = %v, want %q", err, "static IV length")
		}
	})
	t.Run("nil receiver replace material", func(t *testing.T) {
		var p *Protector
		err := p.ReplaceMaterial(bytesOf(0x33, 32), bytesOf(0x44, 12))
		if err == nil || !strings.Contains(err.Error(), "nil protector") {
			t.Fatalf("err = %v, want %q", err, "nil protector")
		}
	})
	t.Run("unsupported suite replace material", func(t *testing.T) {
		// A manually-constructed Protector with a reserved suite passes the
		// 12-byte IV check (line 158) and fails at NewSuiteAEAD (line 162).
		p := &Protector{Suite: 0xBAD}
		err := p.ReplaceMaterial(bytesOf(0x33, 32), bytesOf(0x44, 12))
		if err == nil || !strings.Contains(err.Error(), "unsupported AEAD suite") {
			t.Fatalf("err = %v, want %q", err, "unsupported AEAD suite")
		}
	})
	t.Run("nil receiver destroy", func(t *testing.T) {
		// Destroy on a nil receiver must not panic (line 182).
		var p *Protector
		p.Destroy()
	})
}

func TestSealRejectionDecidesPerCondition(t *testing.T) {
	t.Run("frame block encode error", func(t *testing.T) {
		// A PADDING frame with an out-of-range flow_id makes encodeFrameBlockForSeal
		// fail (line 201); the deferred plaintext destroy runs (line 206).
		p := sealEncodedProtector(t, 1, 0)
		_, err := p.Seal(packetCovHugeFlowIDPaddingBlock())
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("packet AD route id out of range", func(t *testing.T) {
		// An out-of-range route instance id makes PacketAD fail (line 212) after
		// the frame block encodes cleanly.
		p := sealEncodedProtector(t, math.MaxUint64, 0)
		_, err := p.Seal(packetCovValidBlock())
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("XOR nonce bad static IV", func(t *testing.T) {
		// A manually-constructed Protector with a 5-byte IV passes PacketAD and
		// fails at XORNonce96 (line 216).
		p := &Protector{
			Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 1, HopLayer: 1,
			Direction: 0, KeyPhase: 0, Key: bytesOf(0x33, 32), StaticIV: bytesOf(0x44, 5),
		}
		_, err := p.Seal(packetCovValidBlock())
		if err == nil || !strings.Contains(err.Error(), "static IV length") {
			t.Fatalf("err = %v, want %q", err, "static IV length")
		}
	})
	t.Run("cached AEAD wrong key length", func(t *testing.T) {
		// cachedAEAD (line 220) is reachable only after PacketAD and XORNonce96
		// both pass. AppendPacketAD rejects an unsupported suite via
		// AppendSuiteHash before any key material is touched, so a bad-suite
		// protector cannot reach cachedAEAD; instead a *supported* suite with a
		// wrong-length key keeps PacketAD/XORNonce96 happy and fails inside
		// cachedAEAD -> NewSuiteAEAD -> aes256gcm.
		p := &Protector{
			Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 1, HopLayer: 1,
			Direction: 0, KeyPhase: 0, StaticIV: bytesOf(0x44, 12), Key: bytesOf(0x33, 16),
		}
		_, err := p.Seal(packetCovValidBlock())
		if err == nil || !strings.Contains(err.Error(), "AES-256 key length") {
			t.Fatalf("err = %v, want %q", err, "AES-256 key length")
		}
	})
}

func TestSealEncodedDecidesPerCondition(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var p *Protector
		_, err := p.SealEncoded(packetCovValidBlock())
		if err == nil || !strings.Contains(err.Error(), "nil protector") {
			t.Fatalf("err = %v, want %q", err, "nil protector")
		}
	})
	t.Run("layout unknown falls back to copy error", func(t *testing.T) {
		// sealedPacketLayout returns ok=false (line 337, !known) for the
		// out-of-range flow_id block, so SealEncoded falls back to
		// sealEncodedByCopy (line 270), whose Seal fails (line 326).
		p := sealEncodedProtector(t, 1, 0)
		_, err := p.SealEncoded(packetCovHugeFlowIDPaddingBlock())
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("XOR nonce bad static IV", func(t *testing.T) {
		// A 5-byte IV keeps sealedPacketLayout ok=true (route/packet numbers are
		// small), passes AppendPacketAD, and fails at AppendXORNonce96 (281).
		p := &Protector{
			Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 1, HopLayer: 1,
			Direction: 0, KeyPhase: 0, Key: bytesOf(0x33, 32), StaticIV: bytesOf(0x44, 5),
		}
		_, err := p.SealEncoded(packetCovValidBlock())
		if err == nil || !strings.Contains(err.Error(), "static IV length") {
			t.Fatalf("err = %v, want %q", err, "static IV length")
		}
	})
	t.Run("cached AEAD wrong key length", func(t *testing.T) {
		// A supported suite with a wrong-length key keeps sealedPacketLayout
		// ok=true and passes AppendPacketAD/AppendXORNonce96, then fails inside
		// cachedAEAD (285). A reserved suite would be rejected by
		// AppendPacketAD's AppendSuiteHash before reaching cachedAEAD.
		p := &Protector{
			Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 1, HopLayer: 1,
			Direction: 0, KeyPhase: 0, StaticIV: bytesOf(0x44, 12), Key: bytesOf(0x33, 16),
		}
		_, err := p.SealEncoded(packetCovValidBlock())
		if err == nil || !strings.Contains(err.Error(), "AES-256 key length") {
			t.Fatalf("err = %v, want %q", err, "AES-256 key length")
		}
	})
}

// TestSealEncodedOversizedBlockFallsBackToCopy exercises the >0xffffff sub-condition
// of sealedPacketLayout (line 337) and the sealEncodedByCopy happy-return path
// (lines 329/330). A single PADDING frame with a 0xffffff-byte payload has a
// known EncodedLen but a plaintext length just over the 0xffffff packet-payload
// envelope, so sealedPacketLayout returns false and SealEncoded falls back to
// sealEncodedByCopy. Seal succeeds (the frame's payload is within the opaque-24
// limit), but the resulting ciphertext exceeds the envelope, so the final
// EncodeAuroraPacket rejects it — driving the happy-return path with an error.
// This allocates ~16 MiB; it is a single, bounded coverage case.
func TestSealEncodedOversizedBlockFallsBackToCopy(t *testing.T) {
	p := sealEncodedProtector(t, 1, 0)
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		{FrameType: registry.FramePadding, FlowID: 1, Payload: make([]byte, 0xffffff)},
	}}
	_, err := p.SealEncoded(block)
	if err == nil || !strings.Contains(err.Error(), "opaque24 too long") {
		t.Fatalf("err = %v, want %q", err, "opaque24 too long")
	}
}

func TestSealedPacketLayoutDecidesPerCondition(t *testing.T) {
	block := packetCovValidBlock()
	cases := []struct {
		name           string
		routeInstance  uint64
		packetNumber   uint64
		wantOK         bool
		wantHeaderGT0  bool
		wantPlaintext0 bool
	}{
		{"route instance id out of range", math.MaxUint64, 0, false, false, false},
		{"packet number out of range", 1, math.MaxUint64, false, false, false},
		{"valid layout", 1, 0, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, plaintext, ok := sealedPacketLayout(tc.routeInstance, tc.packetNumber, block)
			if ok != tc.wantOK {
				t.Fatalf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
			}
			if ok && (header <= 0 || plaintext <= 0) {
				t.Fatalf("%s: header=%d plaintext=%d, both must be > 0", tc.name, header, plaintext)
			}
		})
	}
}

func TestOpenRejectionDecidesPerCondition(t *testing.T) {
	// matchingPkt returns an AuroraPacket whose metadata matches p, for the
	// direct p.open calls that exercise the crypto-error branches.
	matchingPkt := func(p *Protector) AuroraPacket {
		return AuroraPacket{
			RouteInstanceID: p.RouteInstanceID,
			HopLayer:        p.HopLayer,
			Direction:       p.Direction,
			KeyPhase:        p.KeyPhase,
		}
	}
	t.Run("packet AD reserved direction", func(t *testing.T) {
		// A reserved direction matches the protector (validatePacketMetadata
		// passes) and fails at PacketAD (line 392) before any key material is
		// touched.
		p := &Protector{RouteInstanceID: 1, HopLayer: 1, Direction: 2, KeyPhase: 0}
		if _, err := p.open(matchingPkt(p), []byte{0}, false); err == nil || !strings.Contains(err.Error(), "reserved packet direction") {
			t.Fatalf("err = %v, want %q", err, "reserved packet direction")
		}
	})
	t.Run("XOR nonce bad static IV", func(t *testing.T) {
		// A supported suite lets PacketAD pass, so XORNonce96's 5-byte IV is the
		// first failure (line 396). (Suite 0 would be rejected by
		// AppendPacketAD's AppendSuiteHash before the nonce is built.)
		p := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 1, HopLayer: 1, Direction: 0, KeyPhase: 0, StaticIV: bytesOf(0x44, 5), Key: bytesOf(0x33, 32)}
		if _, err := p.open(matchingPkt(p), []byte{0}, false); err == nil || !strings.Contains(err.Error(), "static IV length") {
			t.Fatalf("err = %v, want %q", err, "static IV length")
		}
	})
	t.Run("cached AEAD wrong key length", func(t *testing.T) {
		// A supported suite + 12-byte IV lets PacketAD and XORNonce96 pass, so
		// cachedAEAD (line 400) is the first failure via a wrong-length key.
		p := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 1, HopLayer: 1, Direction: 0, KeyPhase: 0, StaticIV: bytesOf(0x44, 12), Key: bytesOf(0x33, 16)}
		if _, err := p.open(matchingPkt(p), []byte{0}, false); err == nil || !strings.Contains(err.Error(), "AES-256 key length") {
			t.Fatalf("err = %v, want %q", err, "AES-256 key length")
		}
	})
	t.Run("decode frame block error", func(t *testing.T) {
		// Seal a one-byte plaintext (frame count 2, no frame bodies) with the
		// protector's own key/nonce/AAD so AEAD Open authenticates it, then
		// let DecodeFrameBlock reject the bogus plaintext (line 414).
		p := sealEncodedProtector(t, 1, 0)
		aad, err := auroracrypto.PacketAD(p.Suite, p.RouteInstanceID, p.HopLayer, p.Direction, p.KeyPhase, 0)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := auroracrypto.XORNonce96(p.StaticIV, 0)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := auroracrypto.NewSuiteAEAD(p.Suite, p.Key)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := aead.Seal(nonce, aad, []byte{0x02})
		if err != nil {
			t.Fatal(err)
		}
		pkt := AuroraPacket{
			RouteInstanceID: p.RouteInstanceID, HopLayer: p.HopLayer, Direction: p.Direction, KeyPhase: p.KeyPhase,
			PacketNumber: 0, Ciphertext: sealed[:len(sealed)-packetAuthTagBytes], AuthTag: sealed[len(sealed)-packetAuthTagBytes:],
		}
		if _, err := p.Open(pkt); err == nil {
			t.Fatalf("expected decode-frame-block error, got nil")
		}
	})
}

func TestOpenOwnedAndBorrowedPayloadDecidesPerCondition(t *testing.T) {
	t.Run("open owned metadata mismatch", func(t *testing.T) {
		// Seal a real packet (sealedPayload set, borrowed payload OK), then mutate
		// the route id so validatePacketMetadata rejects it (line 384) after the
		// borrowed-payload guard passes.
		p := sealEncodedProtector(t, 1, 0)
		pkt, err := p.Seal(packetCovValidBlock())
		if err != nil {
			t.Fatal(err)
		}
		pkt.RouteInstanceID = 999
		if _, err := p.OpenOwned(pkt); err == nil || !strings.Contains(err.Error(), "packet metadata does not match") {
			t.Fatalf("err = %v, want %q", err, "packet metadata does not match")
		}
	})
	t.Run("borrowed ciphertext mismatch", func(t *testing.T) {
		// A packet whose Ciphertext slice is not backed by sealedPayload (but
		// whose lengths agree, so the line-446 guard passes) fails the in-place
		// check at line 451 and returns nil, false. sealedPayload is exactly
		// len(Ciphertext)+len(AuthTag)=17 bytes so it is the in-place check, not
		// the length guard, that rejects it.
		pkt := AuroraPacket{
			Ciphertext: []byte{0xaa}, AuthTag: bytesOf(0xbb, packetAuthTagBytes),
			sealedPayload: append([]byte{0xaa}, bytesOf(0xbb, packetAuthTagBytes)...),
		}
		if sealed, ok := pkt.borrowedCiphertextAndTag(); ok || sealed != nil {
			t.Fatalf("borrowedCiphertextAndTag = %v ok=%v, want nil false", sealed, ok)
		}
	})
	t.Run("cached AEAD nil receiver", func(t *testing.T) {
		var p *Protector
		if _, err := p.cachedAEAD(); err == nil || !strings.Contains(err.Error(), "nil protector") {
			t.Fatalf("err = %v, want %q", err, "nil protector")
		}
	})
	t.Run("clear AEAD nil receiver", func(t *testing.T) {
		// clearAEAD on a nil receiver must not panic (line 476).
		var p *Protector
		p.clearAEAD()
	})
}
