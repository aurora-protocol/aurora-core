package issuerd

// Adversarial white-box coverage for the count-0 trailing-bytes guard of
// DecodeAdmissionProofBytes (issuerd/http.go:437). The function decodes raw via
// wire.NewReader + protocol.DecodeAdmissionProof (reads ~14 fields), then checks
// reader.Err() at :434 (covered by the malformed-raw companion test) and
// reader.EOF() at :437. The :437 body returns "issuerd: trailing admission proof
// bytes" when the raw decodes a COMPLETE admission proof but has trailing bytes.
// The existing test (http_test.go:233) passes a VALID full BlindRSA proof with
// no trailing bytes -> reader.EOF()==true -> returns at :440, so the :437 body
// stayed COUNT 0. The malformed-raw companion test trips :434 (reader.Err) on
// short input, never reaching :437.
//
// Coverage target (baseline measured on main; body COUNT 0):
//   - http.go:437.19,439.3 0 — DecodeAdmissionProofBytes: !reader.EOF()
//     -> "issuerd: trailing admission proof bytes"
//
// Reachability: build a STRUCTURALLY-VALID AdmissionProof (crypto-invalid, but
// DecodeAdmissionProofBytes does not verify crypto — only reader.Err/EOF) with
// the exact fixed-opaque field lengths EncodeTo/DecodeAdmissionProof expect,
// encode via wire.Encode (which calls AdmissionProof.EncodeTo — the exact mirror
// of DecodeAdmissionProof), then append ONE trailing byte. DecodeAdmissionProof
// then reads all 14 fields cleanly (reader.Err()==nil, every ReadOpaqueFixed/
// ReadOpaque16/ReadVectorCount succeeds) but reader.off == len(valid) <
// len(valid)+1 == len(raw), so !reader.EOF() is true -> :437 returns the error.
//
// WriteOpaqueFixed(b, n) requires len(b)==n exactly (else SetErr), so the fixed
// fields use make([]byte, N) at the exact lengths: IssuerID 16, TokenKeyID 32,
// RelayBucketID 16, TokenScopeID 16, TokenNonce 32, RedemptionContextHash 48
// (ReadPreHash == ReadOpaqueFixed(48)). The Opaque16 fields and Extensions are
// left nil -> WriteOpaque16 length 0 / EncodeExtensions count 0 (decode cleanly).
//
// Error string is asserted (self-validating); the per-line coverage flip is the
// rigorous proof. In-package (package issuerd) matches the existing test family
// and the malformed-raw companion. Distinct filename + test name, no shared
// helpers, no overlap. One TestXxx; imports strings/testing/protocol/registry/
// wire (all used) -> no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestDecodeAdmissionProofBytesRejectsTrailingBytes(t *testing.T) {
	// Structurally-valid (crypto-invalid) AdmissionProof with exact fixed-opaque
	// lengths so wire.Encode succeeds and DecodeAdmissionProof reads all 14 fields
	// cleanly (reader.Err()==nil).
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              make([]byte, 16),
		TokenKeyID:            make([]byte, 32),
		RelayBucketID:         make([]byte, 16),
		TokenScopeID:          make([]byte, 16),
		ExpiryUnix:            300,
		TokenNonce:            make([]byte, 32),
		RedemptionContextHash: make([]byte, 48), // ReadPreHash == ReadOpaqueFixed(48)
		// TokenPublicMetadata / TokenAuthenticator / BindingProof: nil
		//   -> WriteOpaque16 length 0 (decode cleanly).
		// Extensions: nil -> EncodeExtensions count 0 (decode cleanly).
	}
	valid, err := wire.Encode(proof)
	if err != nil {
		t.Fatalf("wire.Encode(AdmissionProof) err = %v, want nil (structurally-valid fields)", err)
	}
	// One trailing byte -> DecodeAdmissionProof reads all 14 fields (off ==
	// len(valid)) but !reader.EOF() -> :437 returns "trailing admission proof
	// bytes".
	withTrailing := append(append([]byte(nil), valid...), 0xAB)
	_, err = DecodeAdmissionProofBytes(withTrailing)
	if err == nil || !strings.Contains(err.Error(), "trailing admission proof bytes") {
		t.Fatalf("DecodeAdmissionProofBytes(valid+trailing) err = %v, want non-nil containing \"trailing admission proof bytes\" (:437)", err)
	}
}
