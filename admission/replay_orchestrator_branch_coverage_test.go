package admission

// Adversarial white-box coverage for the VerifyAndSpendReplay orchestrator of
// admission/replay.go (lines 162-223). VerifyAndSpendReplay is the relay-side
// replay-defense gate: it structurally validates the admission and replay
// proofs, checks the retention epoch, hashes the admission proof into a
// token-redemption digest, binds it to the replay proof's two cryptographically
// committed hashes, derives the token-spent and bootstrap-dedup keys, computes
// retention deadlines, and inserts both keys into the replay caches. Every
// branch below is reached WITHOUT real cryptography: a ProofLabStaticToken
// admission proof (registry.ProofLabStaticToken = 0x7fff) with AllowLabProofs
// true SKIPS the production token-metadata validation (admission.go 114-123)
// and requires only a zero-length BindingProof (admission.go 110-112), so a
// structurally valid proof is constructible with correct field lengths alone —
// no issuer signature, no VOPRF/RSA math. The replay proof's two committed
// hashes (TokenRedemptionHash, ReplayContextHash) are computed from the same
// admission proof via the package's own TokenRedemptionHash and ReplayContext
// Hash helpers, so the orchestrator's ConstantTimeCompare gates pass and the
// flow proceeds to the retention-deadline and cache-insert paths.
//
// validReplayVerificationInput builds a fully matching proof pair (token-
// redemption and replay-context hashes agree) plus a valid retention epoch and
// two fresh in-memory caches, so a first VerifyAndSpendReplay call succeeds end
// to end — exercising the happy path and seeding the caches. Each test then
// perturbs exactly one input to trip one guard:
//
// Targets covered:
//
//   - VerifyAndSpendReplay:182-184 — the token-redemption-hash mismatch. The
//     existing suite never drives the orchestrator with a structurally valid
//     but mismatched replay proof, so the ConstantTimeCompare != 1 return is
//     unreached. Overwriting ReplayProof.TokenRedemptionHash with a 48-byte
//     all-zero slice (still structurally valid) makes :182 mismatch and returns
//     "replay token_redemption_hash mismatch" before the ReplayContextHash /
//     cache paths run.
//   - VerifyAndSpendReplay:190-192 — the ReplayContextHash error propagation.
//     ReplayContextHash writes RouteInstanceID as a varint (replay.go 124), so
//     RouteInstanceID = ^uint64(0) (above wire.MaxVarint = 1<<62-1) fails that
//     write and the orchestrator surfaces it. The token-redemption hashes
//     still match, so :182 passes and the error originates at :189-190, BEFORE
//     the :193 comparison. (The wire error string is version-dependent, so
//     assert non-nil.)
//   - VerifyAndSpendReplay:193-195 — the replay-context-hash mismatch. The
//     existing suite never drives the orchestrator with matching token-
//     redemption hashes but a mismatched replay-context hash, so the second
//     ConstantTimeCompare != 1 return is unreached. Overwriting
//     ReplayProof.ReplayContextHash with a 48-byte all-zero slice (still
//     structurally valid) makes :193 mismatch and returns "replay_context_hash
//     mismatch". ReplayContextHash does not read ReplayProof.ReplayContextHash,
//     so the recomputed hash is unchanged and the mismatch is deterministic.
//   - VerifyAndSpendReplay:201-203 — the RetentionDeadline(ExpiryUnix) error.
//     RetentionDeadline errs when baseUnix > math.MaxUint64 - grace (600).
//     ValidateStructural imposes no upper bound on ExpiryUnix (only now <
//     ExpiryUnix), so ExpiryUnix = math.MaxUint64 passes :74, makes the two
//     committed hashes match (after recomputing them, since ExpiryUnix is part
//     of the token-redemption hash at :98), and reaches :200 where
//     RetentionDeadline(MaxUint64) overflows and returns "admission:
//     replay-cache retention deadline is invalid".
//   - VerifyAndSpendReplay:205-207 — the MaximumRetentionDeadline error. The
//     three deadline inputs (ExpiryUnix, ReplayEpochValidUntilUnix,
//     RelayEpochValidUntilUnix) are all nonzero at :204 (the :175 epoch gate
//     rejects zeros, and ValidateStructural requires ExpiryUnix > now > 0), so
//     MaximumRetentionDeadline reaches RetentionDeadline(latest). Setting
//     ReplayEpochValidUntilUnix = math.MaxUint64 makes latest = MaxUint64,
//     RetentionDeadline(latest) overflows, and :205 surfaces the same
//     "admission: replay-cache retention deadline is invalid" error. ExpiryUnix
//     stays normal so :200 passes first.
//   - VerifyAndSpendReplay:219-221 — the "bootstrap attempt already seen"
//     return. A first VerifyAndSpendReplay call succeeds and seeds both caches
//     (token-spent and bootstrap-dedup). A second call with a FRESH token-
//     spent cache (so :208 re-accepts the token and :212 passes) but the SAME
//     bootstrap-dedup cache (which already holds the dedup key under a still-
//     valid retention deadline) makes :215's InsertIfAbsentRetained return
//     false, so :219 fires. This isolates :219 from :212 (the token is freshly
//     accepted on the second call; only the bootstrap key is a duplicate).
//
// Dead-by-design (documented, NOT claimed):
//   - VerifyAndSpendReplay:179-181 — the TokenRedemptionHash error. Token
//     RedemptionHash writes ProofType as a varint (:93) and can only fail when
//     ProofType > MaxVarint. AdmissionProof.ValidateStructural's ProofType
//     switch (:77-89) rejects every unknown type via the default branch before
//     the orchestrator reaches :178, and every known ProofType is a small
//     registry constant (all far below MaxVarint), so a structurally valid
//     proof can never fail TokenRedemptionHash. ValidateStructural-gates-
//     invalid-ProofType.
//   - VerifyAndSpendReplay:186-188 — the TokenSpentKey error. tokenRedemption
//     Hash is the output of TokenRedemptionHash, which is always a 48-byte
//     SHA-384 digest, so TokenSpentKey (which errs only on len != 48) cannot
//     err. TokenRedemptionHash-always-48.
//   - VerifyAndSpendReplay:197-199 — the BootstrapDedupKey error. replayContext
//     Hash is the output of ReplayContextHash (always 48 bytes, so WritePreHash
//     at :138 cannot fail), and ReplayProof.ReplayWindowID is validated to
//     exactly 16 bytes by ReplayProof.ValidateStructural (:241), so
//     WriteOpaqueFixed(ReplayWindowID, 16) at :139 cannot fail.
//     Validated-always-48-and-16.
//
// validReplayVerificationInput is referenced by six tests, so there is no
// staticcheck U1000 surface. No context.Context (no SA1012 surface), no
// goroutines, no real cryptography (the lab proof carries no signature), no
// filesystem, and no FileReplayCache (both caches are in-memory, so the flaky
// TestRetentionFileReplayCacheMatchesFullReload is untouched).

import (
	"math"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// validReplayVerificationInput builds a ReplayVerificationInput whose admission
// and replay proofs both pass ValidateStructural and whose committed hashes
// match, with a valid retention epoch and two fresh in-memory caches. A first
// VerifyAndSpendReplay call on the returned input succeeds end to end. Each
// caller perturbs exactly one field to trip one guard.
func validReplayVerificationInput(t *testing.T, now uint64) ReplayVerificationInput {
	t.Helper()
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofLabStaticToken,
		IssuerID:              make([]byte, 16),
		TokenKeyID:            make([]byte, 32),
		RelayBucketID:         make([]byte, 16),
		TokenScopeID:          make([]byte, 16),
		ExpiryUnix:            now + 10000,
		TokenNonce:            make([]byte, 32),
		RedemptionContextHash: make([]byte, 48),
		// BindingProof empty: ProofLabStaticToken requires len 0.
		// TokenPublicMetadata nil: lab proofs skip metadata validation.
		// TokenAuthenticator nil: Opaque16 length 0 is valid.
	}
	tokenRedemptionHash, err := TokenRedemptionHash(proof)
	if err != nil {
		t.Fatalf("TokenRedemptionHash(construct) = %v, want nil", err)
	}
	admissionContextHash := make([]byte, 48)
	replay := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       1,
		TokenRedemptionHash: tokenRedemptionHash,
		ClientReplayNonce:   make([]byte, 32),
		ReplayWindowID:      make([]byte, 16),
	}
	replayContextHash, err := ReplayContextHash(tokenRedemptionHash, replay, 1, 0, nil, admissionContextHash)
	if err != nil {
		t.Fatalf("ReplayContextHash(construct) = %v, want nil", err)
	}
	replay.ReplayContextHash = replayContextHash
	return ReplayVerificationInput{
		AdmissionProof:            proof,
		ReplayProof:               replay,
		RouteInstanceID:           1,
		HopIndex:                  0,
		HandshakeBindingContext:   nil,
		AdmissionContextHash:      admissionContextHash,
		TokenSpentCache:           NewMemoryReplayCache(),
		BootstrapDedupCache:       NewMemoryReplayCache(),
		NowUnix:                   now,
		ReplayEpochValidUntilUnix: now + 1000000,
		RelayEpochValidUntilUnix:  now + 1000000,
		AllowLabProofs:            true,
	}
}

func TestVerifyAndSpendReplayRejectsTokenRedemptionHashMismatch(t *testing.T) {
	// 182-184: a structurally valid but mismatched replay token-redemption hash
	// fails the ConstantTimeCompare at :182 before the replay-context or
	// cache paths run. An all-zero 48-byte slice is structurally valid.
	in := validReplayVerificationInput(t, 1000)
	in.ReplayProof.TokenRedemptionHash = make([]byte, 48)
	_, _, err := VerifyAndSpendReplay(in)
	if err == nil ||
		!strings.Contains(err.Error(), "replay token_redemption_hash mismatch") {
		t.Fatalf("VerifyAndSpendReplay(mismatched token redemption) err = %v, want substring \"replay token_redemption_hash mismatch\"", err)
	}
}

func TestVerifyAndSpendReplayRejectsRouteInstanceOverflow(t *testing.T) {
	// 190-192: RouteInstanceID above wire.MaxVarint makes ReplayContextHash's
	// WriteVarint fail at :124, so :189-190 surfaces the error. The token-
	// redemption hashes still match, so :182 passes and the error originates
	// before the :193 comparison. The wire error string is version-dependent.
	in := validReplayVerificationInput(t, 1000)
	in.RouteInstanceID = ^uint64(0)
	_, _, err := VerifyAndSpendReplay(in)
	if err == nil {
		t.Fatal("VerifyAndSpendReplay(RouteInstanceID overflow) err = nil, want ReplayContextHash error")
	}
}

func TestVerifyAndSpendReplayRejectsReplayContextHashMismatch(t *testing.T) {
	// 193-195: with matching token-redemption hashes, an all-zero 48-byte
	// replay-context hash fails the ConstantTimeCompare at :193.
	// ReplayContextHash does not read ReplayProof.ReplayContextHash, so the
	// recomputed hash is unchanged and the mismatch is deterministic.
	in := validReplayVerificationInput(t, 1000)
	in.ReplayProof.ReplayContextHash = make([]byte, 48)
	_, _, err := VerifyAndSpendReplay(in)
	if err == nil ||
		!strings.Contains(err.Error(), "replay_context_hash mismatch") {
		t.Fatalf("VerifyAndSpendReplay(mismatched replay context) err = %v, want substring \"replay_context_hash mismatch\"", err)
	}
}

func TestVerifyAndSpendReplayRejectsExpiredRetentionDeadline(t *testing.T) {
	// 201-203: ExpiryUnix at the uint64 ceiling passes ValidateStructural (no
	// upper bound, only now < ExpiryUnix) but overflows RetentionDeadline at
	// :200. ExpiryUnix is part of the token-redemption hash (:98), so the two
	// committed hashes must be recomputed to keep :182/:193 passing.
	in := validReplayVerificationInput(t, 1000)
	in.AdmissionProof.ExpiryUnix = math.MaxUint64
	tokenRedemptionHash, err := TokenRedemptionHash(in.AdmissionProof)
	if err != nil {
		t.Fatalf("TokenRedemptionHash(MaxUint64 expiry) = %v, want nil", err)
	}
	in.ReplayProof.TokenRedemptionHash = tokenRedemptionHash
	replayContextHash, err := ReplayContextHash(tokenRedemptionHash, in.ReplayProof, in.RouteInstanceID, in.HopIndex, in.HandshakeBindingContext, in.AdmissionContextHash)
	if err != nil {
		t.Fatalf("ReplayContextHash(MaxUint64 expiry) = %v, want nil", err)
	}
	in.ReplayProof.ReplayContextHash = replayContextHash
	_, _, err = VerifyAndSpendReplay(in)
	if err == nil ||
		!strings.Contains(err.Error(), "admission: replay-cache retention deadline is invalid") {
		t.Fatalf("VerifyAndSpendReplay(MaxUint64 expiry) err = %v, want substring \"admission: replay-cache retention deadline is invalid\"", err)
	}
}

func TestVerifyAndSpendReplayRejectsBootstrapRetentionDeadlineOverflow(t *testing.T) {
	// 205-207: with ExpiryUnix normal (:200 passes), a ReplayEpochValidUntil
	// Unix at the uint64 ceiling makes MaximumRetentionDeadline's latest =
	// MaxUint64, so RetentionDeadline(latest) overflows at :204 and :205
	// surfaces it. The :175 epoch gate accepts it (now < MaxUint64), and the
	// proof hashes are unchanged.
	in := validReplayVerificationInput(t, 1000)
	in.ReplayEpochValidUntilUnix = math.MaxUint64
	_, _, err := VerifyAndSpendReplay(in)
	if err == nil ||
		!strings.Contains(err.Error(), "admission: replay-cache retention deadline is invalid") {
		t.Fatalf("VerifyAndSpendReplay(MaxUint64 replay epoch) err = %v, want substring \"admission: replay-cache retention deadline is invalid\"", err)
	}
}

func TestVerifyAndSpendReplayRejectsBootstrapAlreadySeen(t *testing.T) {
	// 219-221: a first call succeeds and seeds both caches. A second call with
	// a FRESH token-spent cache (so :208 re-accepts and :212 passes) but the
	// SAME bootstrap-dedup cache (which already holds the dedup key under a
	// still-valid deadline) makes :215 return false, so :219 fires. This
	// isolates :219 from :212: only the bootstrap key is a duplicate.
	in := validReplayVerificationInput(t, 1000)
	if _, _, err := VerifyAndSpendReplay(in); err != nil {
		t.Fatalf("first VerifyAndSpendReplay err = %v, want nil", err)
	}
	in.TokenSpentCache = NewMemoryReplayCache()
	_, _, err := VerifyAndSpendReplay(in)
	if err == nil ||
		!strings.Contains(err.Error(), "admission: bootstrap attempt already seen") {
		t.Fatalf("second VerifyAndSpendReplay err = %v, want substring \"admission: bootstrap attempt already seen\"", err)
	}
}
