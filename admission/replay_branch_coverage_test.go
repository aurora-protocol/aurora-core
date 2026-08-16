package admission

// Adversarial white-box coverage for the deterministic hash/encode helpers of
// admission/replay.go. replay.go builds the cryptographically bound admission
// and replay contexts: PolicyOfferHash, ClientTransportHintsHash,
// AdmissionContextHash, TokenRedemptionHash, TokenSpentKey,
// ReplayContextHash, and BootstrapDedupKey, plus the VerifyAndSpendReplay
// orchestrator. Every helper below is pure wire encoding followed by a
// SHA-384 PreHash — no cryptography keys are generated, no signatures are
// verified, no replay cache is touched, and there is no network, filesystem,
// or goroutine activity. The orchestrator's error paths (VerifyAndSpendReplay
// beyond its already-covered nil-cache, retention-epoch, and insert guards)
// need a fully constructed AdmissionProof/ReplayProof pair that passes
// ValidateStructural with matching token-redemption and replay-context
// hashes; that is proof-construction work and is left for a dedicated
// admission-verification pillar, NOT claimed here.
//
// PreHash is SHA-384, so every success path returns a 48-byte digest. The
// success cases assert len == 48 and that two calls produce identical bytes,
// locking the helpers' byte identity without hardcoding a golden digest.
//
// Targets covered:
//
//   - PolicyOfferHash:29-31 — the protocol.Encode error. Encode fails only on
//     an oversized field; PolicyOffer.EncodeTo writes OfferedVersions (and the
//     other offer vectors) as WriteVarintVector, so a single element of
//     ^uint64(0) (above wire.MaxVarint = 1<<62-1) makes WriteVarint fail and
//     PolicyOfferHash surfaces it. The existing suite encodes only canonical
//     offers, so the propagation is unreached.
//   - clientTransportHintsHashForPolicy:40-42 — the ValidatePrototype error.
//     The existing suite passes only prototype-valid hints, so the propagation
//     is unreached. HintFlags = 1 fails ValidatePrototype (hint_flags must be
//     zero) before any encoding runs.
//   - clientTransportHintsHashForPolicy:51-53 — the protocol.Encode(hints)
//     error after ValidatePrototype + NormalizePrototype. ValidatePrototype
//     caps NetworkCohortHint (<=16) but NOT Padding, and EncodeTo writes
//     Padding via WriteOpaque16 (max 0xffff), so a prototype-valid hints with a
//     70000-byte Padding passes both gates and fails Encode at the
//     WriteOpaque16 write. (This corrects a prior note in this file's
//     dead-by-design section that classified this branch as unreachable: that
//     analysis treated every EncodeTo field as a fixed-width scalar or an
//     extension, but Padding is an uncapped Opaque16.)
//   - AdmissionContextHash:59-61 — the PolicyOfferHash error propagation. The
//     existing suite drives AdmissionContextHash only with canonical offers,
//     so the propagation is unreached. The same oversized OfferedVersions
//     element makes PolicyOfferHash fail at the very first step.
//   - AdmissionContextHash:63-65 — the RouteHop branch that replaces the
//     caller's hints with EmptyClientTransportHints(). The existing suite
//     exercises AdmissionContextHash only with RouteHop false, so the empty
//     branch is unreached. A RouteHop-true input takes it (and the rest of the
//     success body, see below).
//   - AdmissionContextHash:66-68 — the clientTransportHintsHashForPolicy
//     success return (RouteHop-true input substitutes the empty, valid hints)
//     AND its error propagation (RouteHop-false input with HintFlags = 1 fails
//     ValidatePrototype). The existing suite does neither through this
//     wrapper.
//   - AdmissionContextHash:70-87 — the ENTIRE success body: the wire encoder
//     writes (version, suite, descriptor hash, template hash, route-mode id,
//     route instance id, hop index, binding context, prelude transcript,
//     policy-offer hash, hints hash), e.Bytes(), and the PreHash return. The
//     existing suite never reaches AdmissionContextHash's success path (it
//     either never calls the helper or always hits an earlier error), so this
//     whole block is unreached. A fully valid ContextInput (canonical offer,
//     empty hints, 48-byte descriptor/template hashes, RouteHop true) drives
//     every write to completion.
//   - AdmissionContextHash:84-86 — the e.Bytes() error. WritePreHash is
//     WriteOpaqueFixed(b, 48), so a RelayDescriptorHash of the wrong length
//     fails the fixed-width write at the first PreHash (line 74); the encoder
//     records the error and e.Bytes() surfaces it. The existing suite passes
//     only 48-byte hashes, so the propagation is unreached.
//   - TokenRedemptionHash:105-107 — the e.Bytes() error. ProofType is written
//     as WriteVarint, so ProofType = ^uint64(0) (above MaxVarint) fails the very
//     first write. The existing suite passes only canonical proof types, so
//     the propagation is unreached.
//   - TokenSpentKey:112-114 — the length guard. The existing suite passes only
//     48-byte redemption hashes (the output of TokenRedemptionHash), so the
//     wrong-length return is unreached. A 3-byte input hits it before PreHash.
//   - ReplayContextHash:129-131 — the e.Bytes() error. routeInstanceID is
//     written as WriteVarint, so routeInstanceID = ^uint64(0) fails that write.
//     The existing suite passes only canonical route ids, so the propagation
//     is unreached.
//   - BootstrapDedupKey:141-143 — the e.Bytes() error. replayContextHash is
//     written as WritePreHash (fixed 48), so a wrong-length input fails the
//     write and e.Bytes() surfaces it. The existing suite passes only 48-byte
//     replay-context hashes, so the propagation is unreached.
//
// Dead-by-design (documented, NOT claimed):
//   - VerifyAndSpendReplay:186-188 — the TokenSpentKey error inside the
//     orchestrator. tokenRedemptionHash is the output of TokenRedemptionHash,
//     which is always a 48-byte SHA-384 digest, so TokenSpentKey (which only
//     errs on len != 48) can never err here — TokenRedemptionHash-always-48.
//
// Out of scope (NOT claimed): the VerifyAndSpendReplay error paths at
// 179/182/190/193/197/201/205/219 require an AdmissionProof/ReplayProof pair
// that passes ValidateStructural with deliberately mismatched or duplicate
// hashes; that is proof-construction work for a dedicated pillar.
//
// No new package-level helpers or types are introduced (only test functions and
// inline literals), so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no signature keys, no
// replay cache, no real network or filesystem. This file deliberately does NOT
// touch replay_cache_retention (the file-backed cache exercised by the
// flaky TestRetentionFileReplayCacheMatchesFullReload): it covers only the
// pure in-memory hash helpers, so it cannot itself be a source of that race.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestPolicyOfferHashRejectsOversizedVarint(t *testing.T) {
	// 29-31: a single OfferedVersions element above wire.MaxVarint makes
	// WriteVarintVector fail inside protocol.Encode, and PolicyOfferHash
	// surfaces it.
	_, err := PolicyOfferHash(protocol.PolicyOffer{
		OfferedVersions: []uint64{^uint64(0)},
	})
	if err == nil {
		t.Fatal("PolicyOfferHash(oversized offered version) err = nil, want Encode error")
	}
}

func TestClientTransportHintsHashRejectsInvalidPrototype(t *testing.T) {
	// 40-42: HintFlags = 1 fails ValidatePrototype (hint_flags must be zero)
	// before any encoding runs, so clientTransportHintsHashForPolicy surfaces
	// the validation error.
	_, err := ClientTransportHintsHash(protocol.ClientTransportHints{HintFlags: 1})
	if err == nil ||
		!strings.Contains(err.Error(), "client transport hint_flags must be zero") {
		t.Fatalf("ClientTransportHintsHash(HintFlags=1) err = %v, want substring \"client transport hint_flags must be zero\"", err)
	}
}

func TestClientTransportHintsHashRejectsOversizedPadding(t *testing.T) {
	// 51-53: ValidatePrototype caps NetworkCohortHint (<=16) but NOT Padding,
	// and EncodeTo writes Padding via WriteOpaque16 (max 0xffff). A
	// prototype-valid hints (HintFlags 0, no cohort, no extensions) with a
	// 70000-byte Padding passes ValidatePrototype + NormalizePrototype, then
	// protocol.Encode -> EncodeTo -> WriteOpaque16 records "wire: opaque16 too
	// long" and Encode surfaces it, so clientTransportHintsHashForPolicy returns
	// the error at :51-53. ClientTransportHintsHash calls the helper with
	// requestedPolicyID 0, so the policy switch is skipped and the failure
	// originates at the Encode step (not the cohort guard at :44-47).
	_, err := ClientTransportHintsHash(protocol.ClientTransportHints{
		Padding: make([]byte, 70000), // > 0xffff
	})
	if err == nil ||
		!strings.Contains(err.Error(), "opaque16 too long") {
		t.Fatalf("ClientTransportHintsHash(oversized padding) err = %v, want substring \"opaque16 too long\"", err)
	}
}

func TestAdmissionContextHashSucceedsAndIsDeterministic(t *testing.T) {
	// 63-65 + 66 (success) + 70-87: a fully valid ContextInput with RouteHop
	// true takes the empty-hints branch, both hash sub-calls succeed, and the
	// full encoder body runs to completion. PreHash is SHA-384, so the digest
	// is 48 bytes and two calls produce identical bytes (byte-identity lock).
	in := ContextInput{
		SelectedVersion:     1,
		SelectedSuite:       1,
		RelayDescriptorHash: make([]byte, 48),
		CoverTemplateHash:   make([]byte, 48),
		PolicyOffer:         protocol.PolicyOffer{},
		RouteHop:            true,
	}
	hash, err := AdmissionContextHash(in)
	if err != nil {
		t.Fatalf("AdmissionContextHash(valid) err = %v, want nil", err)
	}
	if len(hash) != 48 {
		t.Fatalf("AdmissionContextHash(valid) len = %d, want 48 (SHA-384)", len(hash))
	}
	again, err := AdmissionContextHash(in)
	if err != nil {
		t.Fatalf("AdmissionContextHash(valid, second call) err = %v, want nil", err)
	}
	if !bytes.Equal(hash, again) {
		t.Fatal("AdmissionContextHash(valid) is non-deterministic across two calls")
	}
}

func TestAdmissionContextHashPropagatesPolicyOfferError(t *testing.T) {
	// 59-61: an oversized OfferedVersions element makes PolicyOfferHash fail at
	// the very first step, so AdmissionContextHash surfaces the error before
	// the hints or encoder paths run.
	_, err := AdmissionContextHash(ContextInput{
		RelayDescriptorHash: make([]byte, 48),
		CoverTemplateHash:   make([]byte, 48),
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions: []uint64{^uint64(0)},
		},
	})
	if err == nil {
		t.Fatal("AdmissionContextHash(oversized offer) err = nil, want PolicyOfferHash error")
	}
}

func TestAdmissionContextHashPropagatesHintsError(t *testing.T) {
	// 66-68: with RouteHop false the caller's hints are used directly, so
	// HintFlags = 1 fails ValidatePrototype inside clientTransportHintsHashForPolicy
	// and AdmissionContextHash surfaces it after PolicyOfferHash succeeds.
	_, err := AdmissionContextHash(ContextInput{
		RelayDescriptorHash:  make([]byte, 48),
		CoverTemplateHash:    make([]byte, 48),
		PolicyOffer:          protocol.PolicyOffer{},
		ClientTransportHints: protocol.ClientTransportHints{HintFlags: 1},
		RouteHop:             false,
	})
	if err == nil ||
		!strings.Contains(err.Error(), "client transport hint_flags must be zero") {
		t.Fatalf("AdmissionContextHash(invalid hints) err = %v, want substring \"client transport hint_flags must be zero\"", err)
	}
}

func TestAdmissionContextHashRejectsMalformedDescriptorHash(t *testing.T) {
	// 84-86: WritePreHash is WriteOpaqueFixed(b, 48), so a 3-byte
	// RelayDescriptorHash fails the first fixed-width write (line 74); the
	// encoder records the error and e.Bytes() surfaces it. PolicyOfferHash and
	// the hints hash both succeed first, so the error originates in the encoder
	// body.
	_, err := AdmissionContextHash(ContextInput{
		RelayDescriptorHash: []byte{0x01, 0x02, 0x03},
		CoverTemplateHash:   make([]byte, 48),
		PolicyOffer:         protocol.PolicyOffer{},
		RouteHop:            true,
	})
	if err == nil {
		t.Fatal("AdmissionContextHash(short descriptor hash) err = nil, want encoder error")
	}
}

func TestTokenRedemptionHashRejectsOversizedProofType(t *testing.T) {
	// 105-107: ProofType is written as WriteVarint, so ProofType = ^uint64(0)
	// (above MaxVarint) fails the very first write. e.Bytes() surfaces it.
	_, err := TokenRedemptionHash(protocol.AdmissionProof{ProofType: ^uint64(0)})
	if err == nil {
		t.Fatal("TokenRedemptionHash(oversized ProofType) err = nil, want encoder error")
	}
}

func TestTokenSpentKeyRejectsWrongLength(t *testing.T) {
	// 112-114: a 3-byte token-redemption hash hits the length guard before
	// PreHashLabel runs.
	_, err := TokenSpentKey([]byte{0x01, 0x02, 0x03})
	if err == nil ||
		!strings.Contains(err.Error(), "token redemption hash length 3, want 48") {
		t.Fatalf("TokenSpentKey(3 bytes) err = %v, want substring \"token redemption hash length 3, want 48\"", err)
	}
}

func TestReplayContextHashRejectsOversizedRouteInstance(t *testing.T) {
	// 129-131: routeInstanceID is written as WriteVarint, so ^uint64(0) (above
	// MaxVarint) fails that write. e.Bytes() surfaces it.
	_, err := ReplayContextHash(
		make([]byte, 48),
		protocol.ReplayProof{},
		^uint64(0),
		0,
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("ReplayContextHash(oversized routeInstanceID) err = nil, want encoder error")
	}
}

func TestBootstrapDedupKeyRejectsMalformedReplayContextHash(t *testing.T) {
	// 141-143: replayContextHash is written as WritePreHash (fixed 48), so a
	// 3-byte input fails the write and e.Bytes() surfaces it.
	_, err := BootstrapDedupKey([]byte{0x01, 0x02, 0x03}, make([]byte, 16))
	if err == nil {
		t.Fatal("BootstrapDedupKey(short replayContextHash) err = nil, want encoder error")
	}
}
