package client

// Adversarial coverage for client/native_provisioning_trust.go, the parser for
// the independently configured signed-seed trust anchor root set.
//
// Dead-by-design branches (documented, not contrived): the file carries a
// layer of redundant post-validation checks that can never fire because an
// earlier validation already guarantees their precondition. These are real
// findings about over-defensive code that could be simplified; they are NOT
// exercised by fabricated impossible state.
//
//   - NewNativeProvisioningTrust:42-44 — `len(trustedRoots) != len(roots)`.
//     NewSignedSeedTrustStore either errors (caught at 38-40) or stores a
//     faithful clone of every input root; store.AuthorityKeys() returns
//     pinnedRoots+promotedKeys and promotedKeys is empty for a fresh store,
//     so the count always equals the input. No code path silently drops or
//     reorders roots.
//   - EncodeNativeProvisioningTrust:62-64 — `encoder.Bytes()` error after
//     validate() passed. validate() runs NewSignedSeedTrustStore, which
//     validates every root's canonical AuthorityKeyID, scheme/encoding
//     compatibility and structural fields, so each root.EncodeTo succeeds.
//   - EncodeNativeProvisioningTrust:65-67 — `len(encoded) >
//     MaximumNativeProvisioningTrustBytes` (64 KiB). A root set is capped at
//     16 entries and AuthorityKeyRecord has no variable-length field beyond
//     PublicKey (<= ~512 B for the largest permitted RSA key), so a valid set
//     encodes to well under 64 KiB.
//   - ParseNativeProvisioningTrust:98-100 — re-encode error during the
//     canonical-form check. `value` was just produced by NewNativeProvisioningTrust
//     (validated), so EncodeNativeProvisioningTrust succeeds.
//   - sortNativeProvisioningAuthorityKeys:136-138 — encode error inside the
//     sort comparator. Reached only with already-validated roots (called at
//     NewNativeProvisioningTrust:45 on store.AuthorityKeys()), which always
//     encode.
//   - validate:119-121 / nativeProvisioningAuthorityKeysEqual:146-148 and
//     152-156 — the canonical-equality check compares value.roots against
//     store.AuthorityKeys(), which is a faithful same-order clone of
//     value.roots. The two are always byte-identical, so the equality check
//     and its length/mismatch branches never fire.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

// validNativeProvisioningRoot builds one structurally-valid, canonically-keyed
// bootstrap root with a caller-chosen 16-byte AuthorityID. The AuthorityKeyID
// is the canonical trust.AuthorityKeyID(protocol.Encode(publicKey)) required by
// validateAuthorityKeyID.
func validNativeProvisioningRoot(t testing.TB, authorityIDByte byte) protocol.AuthorityKeyRecord {
	t.Helper()
	key := nativeProvisioningECDSAKey(t)
	pub := nativeProvisioningPublicRecord(t, key)
	encodedPub, err := protocol.Encode(pub)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.AuthorityKeyRecord{
		AuthorityID:    nativeProvisioningBytes(authorityIDByte, 16),
		AuthorityKeyID: trust.AuthorityKeyID(encodedPub),
		AuthorityRole:  1,
		PublicKey:      pub,
		ValidFromUnix:  1000,
		ValidUntilUnix: 2000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}
}

// encodeNativeProvisioningTrustRaw encodes a root set in the supplied order,
// bypassing NewNativeProvisioningTrust's internal canonical sort. It is used to
// construct non-canonical encodings that ParseNativeProvisioningTrust must
// reject by re-deriving the canonical form and comparing byte-for-byte.
func encodeNativeProvisioningTrustRaw(t testing.TB, roots ...protocol.AuthorityKeyRecord) []byte {
	t.Helper()
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningTrustFormat)
	encoder.WriteVarint(uint64(len(roots)))
	for _, root := range roots {
		root.EncodeTo(encoder)
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// TestNewNativeProvisioningTrustRejectsInvalidRootCount covers the count guard
// at NewNativeProvisioningTrust:34-36, which fires before the roots are handed
// to the trust store (so the roots need not be valid).
func TestNewNativeProvisioningTrustRejectsInvalidRootCount(t *testing.T) {
	if _, err := NewNativeProvisioningTrust(nil); err == nil {
		t.Fatal("NewNativeProvisioningTrust accepted zero roots")
	}
	tooMany := make([]protocol.AuthorityKeyRecord, maximumNativeProvisioningSignedSeedTrustRoots+1)
	if _, err := NewNativeProvisioningTrust(tooMany); err == nil {
		t.Fatalf("NewNativeProvisioningTrust accepted %d roots", len(tooMany))
	}
}

// TestNewNativeProvisioningTrustRejectsDuplicateAuthorityKey covers the
// NewSignedSeedTrustStore error propagation at 38-40 via two roots sharing a
// signer identity (identical AuthorityKeyID + scheme + encoding), which
// rejectDuplicateAuthorityKeys rejects.
func TestNewNativeProvisioningTrustRejectsDuplicateAuthorityKey(t *testing.T) {
	root := validNativeProvisioningRoot(t, 0x40)
	if _, err := NewNativeProvisioningTrust([]protocol.AuthorityKeyRecord{root, root}); err == nil {
		t.Fatal("NewNativeProvisioningTrust accepted duplicate authority keys")
	}
}

// TestEncodeNativeProvisioningTrustRejectsUnvalidatedValue covers
// EncodeNativeProvisioningTrust:52-54 and the validate() count guard at
// 110-112. Encoding a zero-root trust fails validation before any wire write.
func TestEncodeNativeProvisioningTrustRejectsUnvalidatedValue(t *testing.T) {
	if _, err := EncodeNativeProvisioningTrust(NativeProvisioningTrust{}); err == nil {
		t.Fatal("EncodeNativeProvisioningTrust accepted a zero-root trust")
	}
}

// TestParseNativeProvisioningTrustRejectsBadFormat covers the format-version
// guard at 78-80.
func TestParseNativeProvisioningTrustRejectsBadFormat(t *testing.T) {
	encoder := wire.NewEncoder()
	encoder.WriteVarint(0) // unsupported format
	encoder.WriteVarint(1)
	validNativeProvisioningRoot(t, 0x50).EncodeTo(encoder)
	encoded, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningTrust(encoded); err == nil {
		t.Fatal("ParseNativeProvisioningTrust accepted an unsupported format version")
	}
}

// TestParseNativeProvisioningTrustRejectsMalformedAndTrailing covers the
// reader-error / trailing-byte guard at 89-91: a count that promises more roots
// than the buffer holds, and a complete encoding with a surplus byte.
func TestParseNativeProvisioningTrustRejectsMalformedAndTrailing(t *testing.T) {
	root := validNativeProvisioningRoot(t, 0x51)

	// Truncated: count=2 but only one root follows; the second decode short-reads.
	truncated := encodeNativeProvisioningTrustRaw(t, root) // writes format + count=1 + root
	// Overwrite the count to promise two roots but keep a single root's bytes.
	// Re-encode with count=2 and one root directly.
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningTrustFormat)
	encoder.WriteVarint(2)
	root.EncodeTo(encoder)
	promiseTwo, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningTrust(promiseTwo); err == nil {
		t.Fatal("ParseNativeProvisioningTrust accepted a truncated root vector")
	}

	// Trailing: a complete single-root encoding plus one surplus byte.
	if _, err := ParseNativeProvisioningTrust(append(truncated, 0xff)); err == nil {
		t.Fatal("ParseNativeProvisioningTrust accepted trailing bytes")
	}
}

// TestParseNativeProvisioningTrustRejectsNonCanonicalRootID covers the
// NewNativeProvisioningTrust error propagation at ParseNativeProvisioningTrust
// 94-96. A structurally-decodable root whose AuthorityKeyID is not the canonical
// digest of its public key passes the wire reader but fails the trust store's
// canonical-id validation.
func TestParseNativeProvisioningTrustRejectsNonCanonicalRootID(t *testing.T) {
	root := validNativeProvisioningRoot(t, 0x52)
	root.AuthorityKeyID = nativeProvisioningBytes(0xff, 16) // not canonical
	encoded := encodeNativeProvisioningTrustRaw(t, root)
	if _, err := ParseNativeProvisioningTrust(encoded); err == nil {
		t.Fatal("ParseNativeProvisioningTrust accepted a non-canonical authority key id")
	}
}

// TestParseNativeProvisioningTrustRejectsNonCanonicalOrder covers the
// canonical-form comparison at 101-104. Two valid canonical roots are encoded
// in non-sorted order; Parse re-derives the canonical (sorted) encoding and
// rejects the input because it is not byte-identical.
func TestParseNativeProvisioningTrustRejectsNonCanonicalOrder(t *testing.T) {
	rootA := validNativeProvisioningRoot(t, 0x01) // sorts before rootB by AuthorityID
	rootB := validNativeProvisioningRoot(t, 0x02)
	encoded := encodeNativeProvisioningTrustRaw(t, rootB, rootA) // reverse order
	if _, err := ParseNativeProvisioningTrust(encoded); err == nil {
		t.Fatal("ParseNativeProvisioningTrust accepted a non-canonical root order")
	}
}

// TestNativeProvisioningTrustNewStoreRejectsUnvalidatedValue covers the
// newStore() validate-error propagation at 126-128 (and re-exercises the
// validate() count guard at 110-112 via the store path).
func TestNativeProvisioningTrustNewStoreRejectsUnvalidatedValue(t *testing.T) {
	if _, err := (NativeProvisioningTrust{}).newStore(); err == nil {
		t.Fatal("newStore accepted a zero-root trust")
	}
}