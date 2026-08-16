package release

// Adversarial white-box coverage for verifyThreshold (release/release.go
// 664-695), the release-signature threshold gate. verifyThreshold walks a
// slice of SignatureRecords, counts how many are backed by a DISTINCT valid
// signing key, and returns whether that count reaches the threshold. A
// record is counted only after it clears five guards in order:
//
//	:668  len(KeyID) == 16
//	:672  KeyID not already seen (distinct keys only)
//	:675  PublicKey.ValidateCompatibility() == nil
//	:679  KeyID == releaseSigningKeyID(PublicKey)   (the key id binds to the key)
//	:688  auroracrypto.VerifySignature(PublicKey, input, Signature) == nil
//
// The existing release harness (release_coverage_test.go / the readiness
// bundle) only feeds verifyThreshold signatures produced by newSigner()/sign(),
// which clear all five guards, so every `continue` rejection branch is
// unreached. Each test below produces one such valid record with
// newSigner()/sign() and then perturbs exactly one field (or the record set)
// to trip exactly one guard, with an un-perturbed contrast that asserts the
// same record set reaches the threshold when the guard is not tripped.
//
// The cryptography is real ECDSA P-256 (newSigner draws a key from
// crypto/rand; sign produces an ASN.1 ECDSA signature), but it is bounded and
// self-contained: no network, no filesystem, no goroutines, and no flaky
// surface. The assertions are on boolean verifyThreshold results, which are
// deterministic given the perturbation (a flipped signature bit always fails
// verification; a 16-byte all-0xFF key id never collides with a Truncate128 of
// a SHA-384 hash in practice, and the :679 test guards against the
// astronomically-unlikely collision explicitly).
//
// Targets covered (previously count-0):
//
//   - :668-670 — a 3-byte KeyID fails the length guard before the key is
//     inspected.
//   - :672-674 — a record whose KeyID was already counted is skipped, so two
//     copies of one valid signature count once. Locked by a threshold-2
//     (false: one distinct key < 2) vs threshold-1 (true) contrast on the same
//     pair, proving the duplicate is deduped, not rejected.
//   - :675-677 — a zero-value PublicKey fails ValidateCompatibility ("public
//     key is empty" / unknown scheme) even with a 16-byte KeyID.
//   - :679-681 — a 16-byte KeyID that does not equal releaseSigningKeyID of
//     the record's own PublicKey. The test asserts the tampered id differs
//     from the expected id before asserting rejection, and contrasts with the
//     un-tampered record reaching the threshold.
//   - :688-690 — a corrupted Signature (last byte flipped) fails ECDSA
//     verification. The KeyID still matches the PublicKey, so :679 passes and
//     the failure originates at :688. Contrasted with the un-corrupted record.
//
// verifyThresholdSucceedsAtThreshold grounds the happy path: two DISTINCT
// valid signers produce two records that both clear every guard, so the
// threshold-2 case returns true and the threshold-3 case returns false,
// exercising the :691 seen/valid update and the :694 `valid >= threshold`
// boundary in both directions.
//
// validSignedRecord is referenced by five tests, so there is no staticcheck
// U1000 surface. No context.Context (no SA1012 surface).

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// validSignedRecord returns a SignatureRecord produced by newSigner()/sign()
// that clears all five verifyThreshold guards: a 16-byte KeyID equal to
// releaseSigningKeyID(PublicKey), a P-256 SEC1 PublicKey that passes
// ValidateCompatibility, and a valid ECDSA ASN.1 signature over input. Each
// call draws a fresh key, so two calls produce two distinct (KeyID, key) pairs.
func validSignedRecord(t *testing.T, input []byte) SignatureRecord {
	t.Helper()
	s, err := newSigner()
	if err != nil {
		t.Fatalf("newSigner err = %v, want nil", err)
	}
	rec, err := s.sign(input)
	if err != nil {
		t.Fatalf("sign err = %v, want nil", err)
	}
	return rec
}

func TestVerifyThresholdRejectsShortKeyID(t *testing.T) {
	// 668-670: a 3-byte KeyID fails the length guard before the PublicKey is
	// inspected, so the PublicKey can be anything (a zero key here).
	input := []byte("threshold-input")
	got := verifyThreshold(input, []SignatureRecord{{KeyID: []byte{0x01, 0x02, 0x03}}}, 1)
	if got {
		t.Fatal("verifyThreshold(3-byte KeyID, threshold 1) = true, want false")
	}
}

func TestVerifyThresholdRejectsDuplicateKeyID(t *testing.T) {
	// 672-674: two copies of one valid signature count once, so the second
	// iteration hits the seen-key guard. The threshold-2 case returns false
	// (one distinct key < 2); the threshold-1 case returns true on the same
	// pair, proving the duplicate is deduped rather than rejected at an earlier
	// guard.
	input := []byte("threshold-input")
	rec := validSignedRecord(t, input)
	pair := []SignatureRecord{rec, rec}

	if verifyThreshold(input, pair, 2) {
		t.Fatal("verifyThreshold(duplicate pair, threshold 2) = true, want false (one distinct key)")
	}
	if !verifyThreshold(input, pair, 1) {
		t.Fatal("verifyThreshold(duplicate pair, threshold 1) = false, want true (the one distinct key validates)")
	}
}

func TestVerifyThresholdRejectsIncompatiblePublicKey(t *testing.T) {
	// 675-677: a 16-byte KeyID (passes :668) but a zero-value PublicKey fails
	// ValidateCompatibility before the key-id binding or signature is checked.
	input := []byte("threshold-input")
	rec := SignatureRecord{KeyID: make([]byte, 16), PublicKey: protocol.PublicKeyRecord{}}
	if verifyThreshold(input, []SignatureRecord{rec}, 1) {
		t.Fatal("verifyThreshold(zero PublicKey, threshold 1) = true, want false (incompatible key)")
	}
}

func TestVerifyThresholdRejectsMismatchedKeyID(t *testing.T) {
	// 679-681: a valid PublicKey (passes :675) but a KeyID that does not equal
	// releaseSigningKeyID(PublicKey). The tampered id is 16 all-0xFF bytes; the
	// test asserts it differs from the expected id (guarding the
	// astronomically-unlikely collision) before asserting rejection, and
	// contrasts with the un-tampered record reaching the threshold.
	input := []byte("threshold-input")
	rec := validSignedRecord(t, input)

	expected, err := releaseSigningKeyID(rec.PublicKey)
	if err != nil {
		t.Fatalf("releaseSigningKeyID err = %v, want nil", err)
	}
	tampered := bytes.Repeat([]byte{0xFF}, 16)
	if bytes.Equal(tampered, expected) {
		t.Fatalf("tampered KeyID unexpectedly equals releaseSigningKeyID (% x); pick a different constant", tampered)
	}
	rec.KeyID = tampered

	if verifyThreshold(input, []SignatureRecord{rec}, 1) {
		t.Fatal("verifyThreshold(mismatched KeyID, threshold 1) = true, want false (key id does not bind to the key)")
	}

	// Contrast: the un-tampered record reaches the threshold.
	untampered := validSignedRecord(t, input)
	if !verifyThreshold(input, []SignatureRecord{untampered}, 1) {
		t.Fatal("verifyThreshold(valid record, threshold 1) = false, want true (contrast for the mismatched case)")
	}
}

func TestVerifyThresholdRejectsInvalidSignature(t *testing.T) {
	// 688-690: a corrupted Signature (last byte flipped) fails ECDSA
	// verification. The KeyID still matches the PublicKey (computed from the
	// key, not the signature), so :679 passes and the failure originates at
	// :688. Contrasted with the un-corrupted record reaching the threshold.
	input := []byte("threshold-input")
	rec := validSignedRecord(t, input)

	if len(rec.Signature) == 0 {
		t.Fatal("sign() produced an empty signature, want non-empty ASN.1")
	}
	corruptSig := append([]byte(nil), rec.Signature...)
	corruptSig[len(corruptSig)-1] ^= 0xFF
	rec.Signature = corruptSig

	if verifyThreshold(input, []SignatureRecord{rec}, 1) {
		t.Fatal("verifyThreshold(corrupted signature, threshold 1) = true, want false (signature does not verify)")
	}

	// Contrast: the un-corrupted record reaches the threshold.
	valid := validSignedRecord(t, input)
	if !verifyThreshold(input, []SignatureRecord{valid}, 1) {
		t.Fatal("verifyThreshold(valid record, threshold 1) = false, want true (contrast for the corrupted case)")
	}
}

func TestVerifyThresholdSucceedsAtThreshold(t *testing.T) {
	// Happy path: two DISTINCT valid signers produce two records that both
	// clear every guard, so the threshold-2 case returns true (exercising the
	// :691 seen/valid update and the :694 `valid >= threshold` true branch) and
	// the threshold-3 case returns false (the :694 false branch).
	input := []byte("threshold-input")
	recs := []SignatureRecord{
		validSignedRecord(t, input),
		validSignedRecord(t, input),
	}

	// Sanity: the two fresh signers produced distinct key ids, so both count.
	if bytes.Equal(recs[0].KeyID, recs[1].KeyID) {
		t.Fatal("two newSigner() calls produced the same KeyID; distinct-key assumption violated")
	}

	if !verifyThreshold(input, recs, 2) {
		t.Fatal("verifyThreshold(two distinct valid records, threshold 2) = false, want true")
	}
	if verifyThreshold(input, recs, 3) {
		t.Fatal("verifyThreshold(two distinct valid records, threshold 3) = true, want false")
	}
}
