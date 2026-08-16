package wire

// Adversarial coverage for the wire codec's error short-circuit and
// non-canonical-input edges.
//
// The happy paths (round-trip encode/decode, canonical varints of every
// prefix length, vector reads/writes, opaque reads of every width) are
// already covered by wire_test.go, reader_test.go, encoder_test.go, and
// varint_test.go, and are not re-asserted here except as anchors.
//
// This file covers the residual count-0 blocks across the codec, perturbing
// exactly one input per case so the branch under test is the one that fires:
//
//   - Reader.ReadVarint 100: the top `if r.err != nil` guard. A reader that is
//     already in an error state must short-circuit to 0 without touching the
//     buffer. Reached by presetting r.err (a first ReadVarint on a truncated
//     2-byte varint sets it via 104-107), then a second ReadVarint hits 100.
//   - Reader.ReadVarintVector 154: the same preset-error guard. Reached by
//     presetting r.err, then ReadVarintVector returns nil at 154 (the
//     preceding ReadVectorCount returns 0 under the preset error).
//   - DecodeVarint 61: the 2-byte-prefix `if len(b) < 2` branch. Reached by a
//     direct call with a single byte whose top two bits mark a 2-byte varint
//     (0x40), so the prefix dispatch enters case 1 but the buffer is short.
//   - encode 57: the `if e.err != nil` propagation in the generic Encode
//     path. Reached by encoding an Encodable whose EncodeTo calls SetErr (an
//     exported error setter), so the encoder records the error and encode
//     returns it instead of the bytes.
//
// No dead-by-design blocks remain in the codec: these four lines are the
// complete residual count-0 across reader.go, varint.go, and encoder.go, and
// every one is reachable with pure-data inputs (no crypto, no context, no
// goroutines, no real network or filesystem).
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). One local Encodable fixture is introduced
// (fixtureEncodable) plus one sentinel error (errEncodeFixture); both are
// referenced in the test body and the fixture's method, so there is nothing
// for staticcheck U1000 to flag. No context.Context, no goroutines, no
// deprecated APIs.

import (
	"errors"
	"strings"
	"testing"
)

func TestReadVarintShortCircuitOnError(t *testing.T) {
	// A single 0x40 byte is a 2-byte-prefix varint with only one byte present,
	// so the first ReadVarint decodes, fails, and sets r.err (via 104-107).
	r := NewReader([]byte{0x40})
	if v := r.ReadVarint(); v != 0 {
		t.Fatalf("first ReadVarint = %d, want 0 (decode failure)", v)
	}
	if err := r.Err(); err == nil {
		t.Fatal("first ReadVarint did not set r.err")
	}
	// The second read must short-circuit on the preset error (100) and return
	// 0 without re-entering DecodeVarint.
	if v := r.ReadVarint(); v != 0 {
		t.Fatalf("second ReadVarint = %d, want 0 (short-circuit on preset error)", v)
	}
}

func TestReadVarintVectorShortCircuitOnError(t *testing.T) {
	// Preset r.err the same way, then ReadVarintVector returns nil at the top
	// guard (154) — ReadVectorCount returns 0 under the preset error, and the
	// guard fires before the decode loop runs.
	r := NewReader([]byte{0x40})
	_ = r.ReadVarint()
	if err := r.Err(); err == nil {
		t.Fatal("preset failed: r.err is nil")
	}
	if out := r.ReadVarintVector(); out != nil {
		t.Fatalf("ReadVarintVector = %v, want nil (short-circuit on preset error)", out)
	}
}

func TestDecodeVarintShortTwoBytePrefix(t *testing.T) {
	// 0x40 has prefix bits 01 (a 2-byte varint) but only one byte is present,
	// so case 1 trips the `len(b) < 2` guard (61).
	_, _, err := DecodeVarint([]byte{0x40})
	if err == nil || !strings.Contains(err.Error(), "short 2-byte varint") {
		t.Fatalf("DecodeVarint([0x40]) err = %v, want short 2-byte varint", err)
	}

	// Anchor: a complete, canonical 2-byte varint decodes cleanly, proving the
	// failure above is the short-buffer branch and not a bad prefix dispatch.
	// 0x40 0x40 -> v = (0x40 & 0x3f) << 8 | 0x40 = 64, which exceeds 63 so the
	// non-canonical guard (62-63) does not fire.
	v, n, err := DecodeVarint([]byte{0x40, 0x40})
	if err != nil || v != 64 || n != 2 {
		t.Fatalf("DecodeVarint([0x40 0x40]) = (%d, %d, %v), want (64, 2, nil)", v, n, err)
	}
}

// fixtureEncodable is a minimal Encodable used to drive the encode-error path.
// Its fail field controls whether EncodeTo records an error via SetErr.
type fixtureEncodable struct {
	fail bool
}

func (f fixtureEncodable) EncodeTo(e *Encoder) {
	if f.fail {
		e.SetErr(errEncodeFixture)
		return
	}
	e.WriteUint8(0x42)
}

var errEncodeFixture = errors.New("wire: encode fixture failure")

func TestEncodePropagatesEncodeToError(t *testing.T) {
	// A fixture whose EncodeTo records an error must surface it from Encode at
	// the `if e.err != nil` guard (57), returning (nil, err) rather than bytes.
	_, err := Encode(fixtureEncodable{fail: true})
	if err == nil || !strings.Contains(err.Error(), errEncodeFixture.Error()) {
		t.Fatalf("Encode(failing fixture) err = %v, want %v", err, errEncodeFixture)
	}

	// Anchor: the same fixture with fail=false encodes one byte, proving 57
	// fires because of the recorded error and not because of the fixture shape.
	out, err := Encode(fixtureEncodable{fail: false})
	if err != nil || len(out) != 1 || out[0] != 0x42 {
		t.Fatalf("Encode(ok fixture) = (%x, %v), want ([0x42], nil)", out, err)
	}
}
