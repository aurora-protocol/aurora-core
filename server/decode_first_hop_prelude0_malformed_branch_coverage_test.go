package server

// Adversarial white-box coverage for the count-0 reader-error guard of
// decodeFirstHopPrelude0 (server/first_hop.go:927). The function decodes
// encoded via wire.NewReader + protocol.DecodeCoverPrelude0 (which reads ~18
// fields: varints, a varint vector, fixed opaques, length-prefixed opaques,
// pre-hashes, and extensions), then checks reader.Err() at :927 and
// reader.EOF() at :931. The existing caller (first_hop.go:556) passes a VALID
// full CoverPrelude0 -> DecodeCoverPrelude0 reads all fields cleanly
// (reader.Err()==nil, reader.EOF()==true) -> returns at :935, so the :927 error
// body stayed COUNT 0.
//
// Coverage target (baseline measured on main; body COUNT 0):
//   - first_hop.go:927.25,930.3 0 — decodeFirstHopPrelude0: reader.Err() != nil
//     -> returns reader.Err() (e.g. "wire: short read" / varint decode error)
//
// Reachability: pass a too-short encoded. wire.Reader is the safe non-panicking
// decoder (ReadVarint/ReadOpaqueFixed set r.err on underflow and return zero,
// never panic — see wire/reader.go). On an empty encoded, the first ReadVarint
// (MsgType) underflows immediately -> r.err set -> all subsequent reads
// early-return -> :927 reader.Err() != nil returns the error. A 1-byte and
// 3-byte encoded underflow on a later read similarly.
//
// None of these short encodeds can decode a complete CoverPrelude0 (which is
// ~100+ bytes), so they trip :927 (reader.Err) rather than :931 (trailing).
// Error is asserted non-nil (self-validating: if wire.Reader failed to set Err
// on underflow, err would be nil -> Fatalf); the per-line coverage flip is the
// rigorous proof. decodeFirstHopPrelude0 is unexported, so in-package
// (package server) matches the existing server test family. One TestXxx with
// table cases; imports only testing -> no U1000 surface.

import (
	"testing"
)

func TestDecodeFirstHopPrelude0RejectsMalformedEncoded(t *testing.T) {
	cases := []struct {
		name    string
		encoded []byte
	}{
		{"empty", []byte{}},                       // underflows on first ReadVarint (MsgType)
		{"one byte", []byte{0x00}},                // MsgType decodes, underflows on Version ReadVarint
		{"three bytes", []byte{0x00, 0x00, 0x00}}, // MsgType/Version/SuiteOffers-count decode, underflows on ClientNonce ReadOpaqueFixed(32)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeFirstHopPrelude0(c.encoded)
			if err == nil {
				t.Fatalf("decodeFirstHopPrelude0(%d-byte encoded) err = nil, want non-nil reader error (:927)", len(c.encoded))
			}
		})
	}
}
