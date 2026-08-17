package issuerd

// Adversarial white-box coverage for the count-0 reader-error guard of
// DecodeAdmissionProofBytes (issuerd/http.go:434). The function decodes raw via
// wire.NewReader + protocol.DecodeAdmissionProof (which reads ~14 fields:
// varints, fixed opaques, length-prefixed opaques, and extensions), then checks
// reader.Err() at :434 and reader.EOF() at :437. The existing test
// (http_test.go:233) passes a VALID full BlindRSA proof (issued via /blind-rsa/issue)
// -> DecodeAdmissionProof reads all fields cleanly (reader.Err()==nil,
// reader.EOF()==true) -> returns at :440, so the :434 error body stayed COUNT 0.
//
// Coverage target (baseline measured on main; body COUNT 0):
//   - http.go:434.25,436.3 0 — DecodeAdmissionProofBytes: reader.Err() != nil
//     -> returns reader.Err() (e.g. "wire: short read" / varint decode error)
//
// Reachability: pass a too-short raw. wire.Reader is the safe non-panicking
// decoder (ReadVarint/ReadOpaqueFixed set r.err on underflow and return zero,
// never panic — see wire/reader.go: ReadVarint -> DecodeVarint err -> r.err=err,
// return 0; ReadOpaqueFixed -> "wire: short read" -> r.err set). On an empty raw,
// ReadVarint underflows immediately -> r.err set -> all subsequent reads
// early-return -> :434 reader.Err() != nil returns the error. A 1-byte and 3-byte
// raw underflow on the following ReadOpaqueFixed(16) similarly.
//
// None of these short raws can decode a complete AdmissionProof (which is ~100+
// bytes), so they trip :434 (reader.Err) rather than :437 (trailing). Error is
// asserted non-nil (self-validating: if wire.Reader failed to set Err on
// underflow, err would be nil -> Fatalf); the per-line coverage flip is the
// rigorous proof. DecodeAdmissionProofBytes is exported, but in-package
// (package issuerd) matches the existing issuerd test family. One TestXxx with
// table cases; imports only testing -> no U1000 surface.

import (
	"testing"
)

func TestDecodeAdmissionProofBytesRejectsMalformedRaw(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},                       // underflows on first ReadVarint
		{"one byte", []byte{0x00}},                // varint ok, underflows on ReadOpaqueFixed(16)
		{"three bytes", []byte{0x00, 0x00, 0x00}}, // underflows on ReadOpaqueFixed(16)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeAdmissionProofBytes(c.raw)
			if err == nil {
				t.Fatalf("DecodeAdmissionProofBytes(%d-byte raw) err = nil, want non-nil reader error (:434)", len(c.raw))
			}
		})
	}
}
