package wire

import (
	"bytes"
	"testing"
)

// FuzzDecodeVarint asserts that the varint decoder never panics on arbitrary
// input and that every accepted encoding is canonical: a successful decode must
// round-trip through EncodeVarint and reproduce the exact consumed bytes.
// This is the same canonical-re-encoding invariant the protocol fuzzer enforces
// (see test/fuzz-protocol-canonicality), applied to the wire primitive that
// frames every length, vector count, and scalar on the network.
func FuzzDecodeVarint(f *testing.F) {
	// Empty input and each width's boundary values.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x3f})
	f.Add([]byte{0x40, 0x40})
	f.Add([]byte{0x7f, 0xff})
	f.Add([]byte{0x80, 0x00, 0x40, 0x00})
	f.Add([]byte{0xbf, 0xff, 0xff, 0xff})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00})
	// Non-minimal and short encodings that the decoder must reject, not misread.
	f.Add([]byte{0x40, 0x00})
	f.Add([]byte{0x80, 0x00, 0x00, 0x3f})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xff})
	f.Add([]byte{0xff})
	f.Add([]byte{0x80, 0x00})
	f.Add([]byte{0xc0})

	f.Fuzz(func(t *testing.T, data []byte) {
		value, n, err := DecodeVarint(data)
		if err != nil {
			// Any error is acceptable; the decoder must only avoid panicking.
			return
		}
		if n <= 0 || n > len(data) {
			t.Fatalf("DecodeVarint(%x) consumed n=%d, out of range", data, n)
		}
		if value > MaxVarint {
			t.Fatalf("DecodeVarint(%x) returned out-of-range value %d", data, value)
		}
		// A successful decode is minimal by construction, so re-encoding the
		// value must reproduce the exact consumed bytes and round-trip cleanly.
		encoded, encErr := EncodeVarint(value)
		if encErr != nil {
			t.Fatalf("EncodeVarint(%d) failed: %v", value, encErr)
		}
		if len(encoded) != n {
			t.Fatalf("DecodeVarint(%x) n=%d but EncodeVarint(%d) width=%d", data, n, value, len(encoded))
		}
		if !bytes.Equal(encoded, data[:n]) {
			t.Fatalf("non-canonical varint: input=%x re-encoded=%x", data[:n], encoded)
		}
		roundTrip, roundTripN, roundTripErr := DecodeVarint(encoded)
		if roundTripErr != nil || roundTrip != value || roundTripN != len(encoded) {
			t.Fatalf("round-trip failed: DecodeVarint(%x)=%d/%d err=%v want %d/%d",
				encoded, roundTrip, roundTripN, roundTripErr, value, len(encoded))
		}
	})
}