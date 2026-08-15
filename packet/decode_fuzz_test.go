package packet

import (
	"bytes"
	"testing"
)

func fuzzPacketSeeds() [][]byte {
	return [][]byte{
		nil,
		{},
		{0x00},
		{0x01, 0x02, 0x03},
		// Minimal shaped packet: route varint, hop, direction, phase, packet
		// number varint, opaque24 length, ciphertext, 16-byte tag.
		append([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa}, bytes.Repeat([]byte{0xbb}, 16)...),
		append([]byte{0x40, 0x42, 0x01, 0x01, 0x02, 0x40, 0x07, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}, bytes.Repeat([]byte{0xcc}, 16)...),
	}
}

// FuzzDecodeAuroraPacket drives the parser that runs on raw bytes taken off the
// carrier before any cryptographic check, so it sees whatever an unauthenticated
// peer sends. Beyond not panicking, a packet that decodes must re-encode to the
// exact bytes it came from: a second encoding of the same packet would mean the
// wire form is malleable and two distinct byte strings could carry one packet.
func FuzzDecodeAuroraPacket(f *testing.F) {
	for _, seed := range fuzzPacketSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		pkt, err := DecodeAuroraPacket(encoded)
		if err != nil {
			return
		}
		reencoded, err := EncodeAuroraPacket(pkt)
		if err != nil {
			t.Fatalf("decoded packet failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("packet re-encoded to %x, want %x", reencoded, encoded)
		}
		if length, known := pkt.EncodedLen(); !known || length != len(encoded) {
			t.Fatalf("EncodedLen reported (%d, %t) for a %d byte packet", length, known, len(encoded))
		}
	})
}

// FuzzDecodeAuroraPacketView additionally covers the borrowed-payload form used
// on the owned receive path. Its ciphertext and tag must alias one contiguous
// region of the caller's buffer, because the in-place open relies on that
// aliasing and would otherwise authenticate storage it does not own.
func FuzzDecodeAuroraPacketView(f *testing.F) {
	for _, seed := range fuzzPacketSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		owned := append([]byte(nil), encoded...)
		view, viewErr := DecodeAuroraPacketView(owned)
		copied, copiedErr := DecodeAuroraPacket(encoded)
		if (viewErr == nil) != (copiedErr == nil) {
			t.Fatalf("view error %v disagrees with copying error %v", viewErr, copiedErr)
		}
		if viewErr != nil {
			return
		}
		if !bytes.Equal(view.Ciphertext, copied.Ciphertext) || !bytes.Equal(view.AuthTag, copied.AuthTag) {
			t.Fatal("view and copying decoders produced different payloads")
		}

		sealed, ok := view.borrowedCiphertextAndTag()
		if !ok {
			t.Fatal("view decode did not produce a borrowed contiguous payload")
		}
		if len(sealed) != len(view.Ciphertext)+len(view.AuthTag) {
			t.Fatalf("borrowed payload is %d bytes, want %d", len(sealed), len(view.Ciphertext)+len(view.AuthTag))
		}
		// The borrowed region must sit inside the caller's buffer.
		if len(sealed) > 0 && (&sealed[0] != &owned[len(owned)-len(sealed)]) {
			t.Fatal("borrowed payload does not alias the end of the input buffer")
		}
	})
}
