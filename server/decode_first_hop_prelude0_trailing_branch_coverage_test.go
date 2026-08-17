package server

// Adversarial white-box coverage for the count-0 trailing-bytes guard of
// decodeFirstHopPrelude0 (server/first_hop.go:931). This is the companion to
// #360 (which covers the :927 malformed-raw guard) and completes
// decodeFirstHopPrelude0 branch coverage: the malformed-raw path (:927,
// reader.Err), the trailing-bytes path (:931, !EOF), and the existing happy
// path (:935, valid prelude) will all be covered.
//
// decodeFirstHopPrelude0 decodes encoded via wire.NewReader +
// protocol.DecodeCoverPrelude0 (reads ~18 fields), then checks reader.Err() at
// :927 and reader.EOF() at :931. The :931 body returns
// "server: trailing first-hop Prelude0 bytes" when the encoded decodes a
// COMPLETE CoverPrelude0 but has trailing bytes. The existing caller
// (first_hop.go:556) passes a VALID full CoverPrelude0 with no trailing bytes
// -> reader.EOF()==true -> returns at :935, so the :931 body stayed COUNT 0.
// The #360 malformed-raw test trips :927 (reader.Err) on short input and never
// reaches :931.
//
// Coverage target (baseline measured on main; body COUNT 0):
//   - first_hop.go:931.19,934.3 0 — decodeFirstHopPrelude0: !reader.EOF()
//     -> "server: trailing first-hop Prelude0 bytes"
//
// Reachability: build a STRUCTURALLY-VALID CoverPrelude0 (crypto-invalid, but
// decodeFirstHopPrelude0 does not verify crypto — only reader.Err/EOF) with
// the exact fixed-opaque field lengths EncodeTo/DecodeCoverPrelude0 expect,
// encode via wire.Encode (which calls CoverPrelude0.EncodeTo — the exact mirror
// of DecodeCoverPrelude0), then append ONE trailing byte. DecodeCoverPrelude0
// then reads all ~18 fields cleanly (reader.Err()==nil, every ReadVarint/
// ReadOpaqueFixed/ReadOpaque16/ReadPreHash/ReadVarintVector succeeds on the
// valid encoding) but reader.off == len(valid) < len(valid)+1 == len(encoded),
// so !reader.EOF() is true -> :931 returns the error.
//
// WriteOpaqueFixed(b, n) requires len(b)==n exactly (else SetErr), so the fixed
// fields use make([]byte, N) at the exact lengths: ClientNonce 32,
// RelayDescriptorHash 48 (WritePreHash == WriteOpaqueFixed(48)),
// CoverTemplateHash 48, HintIssuerID 16, RelayBucketID 16, HintSelector 16,
// AccessHint 16, ClientCoverRandom 32. The Opaque16 fields
// (ClientClassicalEphPub/ClientMLKEMEncapsulationKey/Padding), SuiteOffers, and
// Extensions are left nil -> WriteOpaque16 length 0 / WriteVarintVector count 0
// / EncodeExtensions count 0 (decode cleanly).
//
// Error string is asserted (self-validating); the per-line coverage flip is the
// rigorous proof. In-package (package server) matches the existing server test
// family and the malformed-raw companion. Distinct filename + test name, no
// shared helpers, no overlap. One TestXxx; imports strings/testing/protocol/
// registry/wire (all used) -> no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestDecodeFirstHopPrelude0RejectsTrailingBytes(t *testing.T) {
	// Structurally-valid (crypto-invalid) CoverPrelude0 with exact fixed-opaque
	// lengths so wire.Encode succeeds and DecodeCoverPrelude0 reads all ~18
	// fields cleanly (reader.Err()==nil).
	prelude := protocol.CoverPrelude0{
		MsgType:             registry.MsgCoverPrelude0,
		Version:             registry.Version20,
		RequestClassID:      1,
		HintEpochID:         1,
		ClientNonce:         make([]byte, 32),
		RelayDescriptorHash: make([]byte, 48), // WritePreHash == WriteOpaqueFixed(48)
		CoverTemplateHash:   make([]byte, 48), // WritePreHash == WriteOpaqueFixed(48)
		HintIssuerID:        make([]byte, 16),
		RelayBucketID:       make([]byte, 16),
		HintSelector:        make([]byte, 16),
		AccessHint:          make([]byte, 16),
		ClientCoverRandom:   make([]byte, 32),
		// SuiteOffers: nil -> WriteVarintVector count 0 (decode cleanly).
		// ClientClassicalEphPub / ClientMLKEMEncapsulationKey / Padding: nil
		//   -> WriteOpaque16 length 0 (decode cleanly).
		// Extensions: nil -> EncodeExtensions count 0 (decode cleanly).
	}
	valid, err := wire.Encode(prelude)
	if err != nil {
		t.Fatalf("wire.Encode(CoverPrelude0) err = %v, want nil (structurally-valid fields)", err)
	}
	// One trailing byte -> DecodeCoverPrelude0 reads all ~18 fields (off ==
	// len(valid)) but !reader.EOF() -> :931 returns "trailing first-hop
	// Prelude0 bytes".
	withTrailing := append(append([]byte(nil), valid...), 0xAB)
	_, err = decodeFirstHopPrelude0(withTrailing)
	if err == nil || !strings.Contains(err.Error(), "trailing first-hop Prelude0 bytes") {
		t.Fatalf("decodeFirstHopPrelude0(valid+trailing) err = %v, want non-nil containing \"trailing first-hop Prelude0 bytes\" (:931)", err)
	}
}
