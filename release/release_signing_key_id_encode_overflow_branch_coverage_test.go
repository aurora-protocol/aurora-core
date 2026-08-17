package release

// Adversarial white-box branch coverage for the lone count-0 Encode-error
// guard in releaseSigningKeyID (release/release.go:740-746):
//
//	func releaseSigningKeyID(publicKey protocol.PublicKeyRecord) ([]byte, error) {
//	    encoded, err := protocol.Encode(publicKey)   // :741
//	    if err != nil {                               // :742
//	        return nil, err                            // :743  <-- COUNT 0
//	    }
//	    return auroracrypto.Truncate128(
//	        auroracrypto.PreHashLabel("aurora release signing key", encoded)), nil
//	}
//
// releaseSigningKeyID is reached in production only from newSigner (:717),
// which builds the PublicKeyRecord from a freshly generated ecdsa P-256 key
// (a ~65-byte SEC1 public key) — so the Encode never errors and :742-744
// stayed count 0. The existing release/verify_release_empty_bundle_branch_coverage_test.go
// documented :742-744 as dead-by-design (lines 36-39) alongside the crypto
// guards :718-720 (newSigner's ecdsa.GenerateKey) and :730-732 (sign's
// ecdsa.SignASN1). That classification is OVERBROAD for :742: those crypto
// guards need a faulting rand.Reader (a global not injectable from a test)
// and are genuinely dead/heavy, but releaseSigningKeyID is a PURE Encode+hash
// helper (no rand, no signing) — its Encode err is its OWN bounds check,
// reachable by a direct in-package call with an oversize PublicKey. This is
// the same own-bounds-check / constructor-is-separate-entry-point shape as
// #368 (transport CarrierSession) and #369 (issuerd reserveIssuerdOwnedBytes).
//
// Reachability: PublicKeyRecord.EncodeTo (protocol/records.go:23) serializes
// the PublicKey field via wire.Encoder.WriteOpaque16 (protocol/records.go:26),
// which calls SetErr("wire: opaque16 too long: %d") and returns when
// len(b) > 0xffff (wire/encoder.go:171-175). protocol.Encode (protocol/types.go:61)
// surfaces that error via Encoder.Bytes(). So a PublicKeyRecord with
// PublicKey = make([]byte, 65536) makes protocol.Encode return a non-nil error
// and :742-744 fires. A short valid PublicKey encodes cleanly (nil error),
// providing a contrast that proves the error is the oversize, not some
// earlier validation. The per-line coverage flip (0 -> 1) is the proof.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestReleaseSigningKeyIDEncodeOverflowGuard(t *testing.T) {
	// release.go:742-744 — an oversize PublicKey (65536 bytes > 0xffff) makes
	// WriteOpaque16 set the encoder error, so protocol.Encode returns it and
	// releaseSigningKeyID returns (nil, err) at :743.
	_, err := releaseSigningKeyID(protocol.PublicKeyRecord{
		PublicKey: make([]byte, 65536),
	})
	if err == nil {
		t.Fatal("releaseSigningKeyID(oversize PublicKey) err = nil, want non-nil (:742 Encode guard should fire)")
	}
	if !strings.Contains(err.Error(), "opaque16") {
		t.Fatalf("releaseSigningKeyID(oversize) err = %v, want substring \"opaque16\" (the WriteOpaque16 overflow)", err)
	}

	// Contrast: a short valid PublicKey encodes cleanly (WriteOpaque16 accepts
	// any length <= 0xffff), so releaseSigningKeyID returns a non-nil hash and a
	// nil error. This proves the error above is the oversize PublicKey, not some
	// earlier validation, and locks the happy path alongside the guard.
	got, err := releaseSigningKeyID(protocol.PublicKeyRecord{
		PublicKey: []byte{0x04, 0x01, 0x02, 0x03},
	})
	if err != nil {
		t.Fatalf("releaseSigningKeyID(short valid PublicKey) err = %v, want nil", err)
	}
	if len(got) == 0 {
		t.Fatal("releaseSigningKeyID(short valid PublicKey) returned empty hash, want a 16-byte Truncate128 digest")
	}
}
