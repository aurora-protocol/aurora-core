package admission

// Adversarial coverage for the access-hint spend and credential-set codec paths
// in access_hint.go and access_hint_codec.go that the existing
// access_hint_credential_test.go suite reaches only on its happy paths (or not
// at all). The uncovered blocks (measured count 0 before this file):
//
// access_hint.go:
//   - ComputeAccessHint (line 53): the binding-context-length (57-58) and
//     client-nonce-length (60-61) rejections. The existing suite only exercises
//     the happy MAC path and the validate() propagation.
//   - ComputeSpentHintKey (line 74): the validate() propagation (75-76). The
//     existing suite never calls ComputeSpentHintKey with an invalid credential.
//   - VerifyAndSpendAccessHintAt (line 95): the nil-cache guard (96-97), the
//     ComputeAccessHint error propagation (106-107), the retention-deadline
//     error propagation (121-123), the replay-cache error propagation (126-127),
//     and the already-spent rejection (129-130). The existing
//     TestVerifyAndSpendAccessHint* suite in admission_test.go covers the
//     expiry (99-100), epoch (102-103), and mismatch (109-110) branches, plus the
//     happy return-nil (132), so those are NOT duplicated here.
//
// access_hint_codec.go:
//   - EncodeAccessHintCredentialSet (line 35): the per-credential validate()
//     propagation inside the encode loop (42-44). The single-credential
//     encoder's validate path (codec 13-15) is already covered by
//     TestEncodeAccessHintCredentialRejectsInvalidCredential — NOT duplicated.
//   - DecodeAccessHintCredentialSet (line 51): the per-credential validate()
//     propagation inside the decode loop (63-65). The single-credential
//     decoder's post-decode validate path (codec 28-30) is already covered by
//     TestDecodeAccessHintCredentialRejectsInvalidDecodedFields — NOT duplicated.
//
// Reuses the in-package validHintCredential() (access_hint_credential_test.go)
// and rep(b,n) (admission_test.go) fixtures, and NewMemoryReplayCache
// (replay_cache.go) as a real RetentionReplayCache. A tiny errReplayCache double
// covers the cache-error path (126) via both the nowUnix==0 InsertIfAbsent branch
// and the nowUnix!=0 InsertIfAbsentRetained branch (it intentionally does NOT
// implement RetentionReplayCache, so InsertIfAbsentRetained surfaces the
// "does not support retention" error).
//
// Dead-by-design branches (documented, not contrived):
//   - DeriveHintSecret:47-49 (HKDFExtractSHA384 error). HKDF-Extract is HMAC-based
//     and never returns a non-nil error (see crypto/hkdf.go), so the error branch
//     is unreachable. The wire-layer error path of DeriveHintSecret is already
//     covered by TestDeriveHintSecretRejectsMalformedInputs.
//   - ComputeSpentHintKey:85-87 (encoder Bytes() error). validate() at 75-76
//     already guaranteed HintIssuerID/RelayBucketID/HintSelector are 16 bytes and
//     HintSecret is 32 bytes, so every WriteOpaqueFixed write succeeds and
//     wire.Encoder.Bytes() returns a nil error. The branch cannot fire.
//   - VerifyAndSpendAccessHintAt:113-115 (ComputeSpentHintKey error propagation).
//     ComputeAccessHint at line 105 already ran cred.validate() successfully
//     (it returns early on validate failure), and ComputeSpentHintKey at 112
//     runs the same validate() on the same cred. The second validate() cannot
//     fail once the first succeeded, so the propagation at 113-115 is
//     unreachable. (The ComputeSpentHintKey Bytes() sub-branch at 85 is itself
//     dead-by-design as noted above.)
//
// Coverage is re-measured per target to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one error so the
// failure is attributable to the perturbed input alone. New helpers are each
// referenced by >=2 tests so there is no U1000. No context.Context, no
// deprecated APIs.

import (
	"errors"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/wire"
)

func TestComputeAccessHintRejectsBindingContextAndNonceLengths(t *testing.T) {
	cred := validHintCredential()
	bindingContext := rep(0x61, 48)
	clientNonce := rep(0x62, 32)

	// Happy path: a valid credential with a 48-byte context and 32-byte nonce
	// produces a 16-byte truncated MAC (Truncate128).
	hint, err := ComputeAccessHint(cred, bindingContext, clientNonce)
	if err != nil {
		t.Fatalf("ComputeAccessHint happy path failed: %v", err)
	}
	if len(hint) != 16 {
		t.Fatalf("ComputeAccessHint hint length = %d, want 16 (Truncate128)", len(hint))
	}

	// 57-58: binding context not 48 bytes.
	_, err = ComputeAccessHint(cred, rep(0x61, 47), clientNonce)
	if err == nil || !strings.Contains(err.Error(), "want 48") {
		t.Fatalf("binding context length error = %v, want ...want 48", err)
	}

	// 60-61: client nonce not 32 bytes. The 48-byte context passes the 57 guard so
	// the nonce-length guard is the one that fires.
	_, err = ComputeAccessHint(cred, bindingContext, rep(0x62, 31))
	if err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Fatalf("client nonce length error = %v, want ...want 32", err)
	}
}

func TestComputeSpentHintKeyRejectsInvalidCredential(t *testing.T) {
	// Happy path: a valid credential produces a 48-byte SHA-384 prehash.
	key, err := ComputeSpentHintKey(validHintCredential())
	if err != nil {
		t.Fatalf("ComputeSpentHintKey happy path failed: %v", err)
	}
	if len(key) != 48 {
		t.Fatalf("ComputeSpentHintKey key length = %d, want 48 (SHA-384)", len(key))
	}

	// 75-76: an invalid credential (MaxUses != 1) fails validate() inside
	// ComputeSpentHintKey. This path is distinct from ComputeAccessHint's
	// validate() because ComputeSpentHintKey runs its own validate() on the
	// same credential.
	invalid := validHintCredential()
	invalid.MaxUses = 2
	_, err = ComputeSpentHintKey(invalid)
	if err == nil || !strings.Contains(err.Error(), "max_uses must be 1") {
		t.Fatalf("ComputeSpentHintKey(invalid) err = %v, want max_uses error", err)
	}
}

func TestVerifyAndSpendAccessHintAtRejectsNilCache(t *testing.T) {
	// 96-97: a nil replay cache is rejected before any credential work. The hint
	// need not match because the guard returns first.
	err := VerifyAndSpendAccessHint(nil, validHintCredential(), rep(0x61, 48), rep(0x62, 32), nil)
	if err == nil || !strings.Contains(err.Error(), "missing access hint replay cache") {
		t.Fatalf("nil cache error = %v, want missing-cache error", err)
	}
}

func TestVerifyAndSpendAccessHintAtPropagatesComputeAccessHintError(t *testing.T) {
	cred := validHintCredential() // ExpiryUnix 9999, valid fields.
	cache := NewMemoryReplayCache()
	nonce := rep(0x62, 32)

	// 106-107: with nowUnix=100 and epochValidUntilUnix=200 the expiry (99) and
	// epoch (102) guards pass (100 < 9999 and 100 < 200), so execution reaches
	// ComputeAccessHint at 105. A 47-byte binding context fails the 57 guard
	// inside ComputeAccessHint, and that error propagates out of
	// VerifyAndSpendAccessHintAt at 106-107.
	err := VerifyAndSpendAccessHintAt(cache, cred, rep(0x61, 47), nonce, rep(0xFF, 16), 100, 200)
	if err == nil || !strings.Contains(err.Error(), "want 48") {
		t.Fatalf("ComputeAccessHint propagation err = %v, want ...want 48", err)
	}
}

func TestVerifyAndSpendAccessHintAtRejectsRetentionDeadline(t *testing.T) {
	// To reach the retention-deadline guard at 120-121, every prior guard must
	// pass and the hint must match. Use a credential whose ExpiryUnix is 0:
	//   - 99: `cred.ExpiryUnix != 0` is false, so the expiry guard does not fire.
	//   - 102: nowUnix=100 < epochValidUntilUnix=200 and 200 != 0, so the epoch
	//     guard does not fire.
	//   - 105/109: ComputeAccessHint ignores ExpiryUnix, so a hint computed from
	//     the same credential matches.
	//   - 112: ComputeSpentHintKey validates successfully (ExpiryUnix is not a
	//     validate() field).
	// Then 120 calls MaximumRetentionDeadline(cred.ExpiryUnix=0, 200): a zero
	// value makes it return an error, propagated at 121-123.
	cred := validHintCredential()
	cred.ExpiryUnix = 0
	bindingContext := rep(0x61, 48)
	clientNonce := rep(0x62, 32)
	hint, err := ComputeAccessHint(cred, bindingContext, clientNonce)
	if err != nil {
		t.Fatalf("ComputeAccessHint: %v", err)
	}
	cache := NewMemoryReplayCache()

	err = VerifyAndSpendAccessHintAt(cache, cred, bindingContext, clientNonce, hint, 100, 200)
	if err == nil || !strings.Contains(err.Error(), "replay-cache retention time is invalid") {
		t.Fatalf("retention deadline err = %v, want retention-time-invalid error", err)
	}
}

func TestVerifyAndSpendAccessHintAtPropagatesCacheError(t *testing.T) {
	cred := validHintCredential()
	bindingContext := rep(0x61, 48)
	clientNonce := rep(0x62, 32)
	hint, err := ComputeAccessHint(cred, bindingContext, clientNonce)
	if err != nil {
		t.Fatalf("ComputeAccessHint: %v", err)
	}

	t.Run("nowUnix zero path: InsertIfAbsent error", func(t *testing.T) {
		// 126-127 via the nowUnix==0 branch (117-118): errReplayCache returns an
		// injected error from InsertIfAbsent, so `err != nil` fires at 126.
		err := VerifyAndSpendAccessHint(errReplayCache{err: errors.New("injected")}, cred, bindingContext, clientNonce, hint)
		if err == nil || !strings.Contains(err.Error(), "replay cache failed") {
			t.Fatalf("cache error propagation (nowUnix==0) err = %v, want replay cache failed", err)
		}
	})

	t.Run("nowUnix nonzero path: non-retention cache error", func(t *testing.T) {
		// 126-127 via the nowUnix!=0 branch (119-124): MaximumRetentionDeadline
		// succeeds (ExpiryUnix 9999, epoch 200, both nonzero), so execution reaches
		// InsertIfAbsentRetained at 124. errReplayCache does NOT implement
		// RetentionReplayCache, so InsertIfAbsentRetained returns the
		// "does not support retention" error, and `err != nil` fires at 126.
		err := VerifyAndSpendAccessHintAt(errReplayCache{}, cred, bindingContext, clientNonce, hint, 100, 200)
		if err == nil || !strings.Contains(err.Error(), "replay cache failed") {
			t.Fatalf("cache error propagation (nowUnix!=0) err = %v, want replay cache failed", err)
		}
		if err == nil || !strings.Contains(err.Error(), "does not support retention") {
			t.Fatalf("cache error propagation (nowUnix!=0) err = %v, want does-not-support-retention", err)
		}
	})
}

func TestVerifyAndSpendAccessHintAtRejectsAlreadySpent(t *testing.T) {
	cred := validHintCredential()
	bindingContext := rep(0x61, 48)
	clientNonce := rep(0x62, 32)
	hint, err := ComputeAccessHint(cred, bindingContext, clientNonce)
	if err != nil {
		t.Fatalf("ComputeAccessHint: %v", err)
	}
	cache := NewMemoryReplayCache()

	// First spend: the spent key is absent, InsertIfAbsent returns (true, nil),
	// so !inserted is false and the happy path returns nil at 132.
	if err := VerifyAndSpendAccessHint(cache, cred, bindingContext, clientNonce, hint); err != nil {
		t.Fatalf("first spend failed: %v", err)
	}

	// Second spend: the same spent key is now present, InsertIfAbsent returns
	// (false, nil), so 126 is skipped (err == nil) and !inserted fires at 129-130.
	err = VerifyAndSpendAccessHint(cache, cred, bindingContext, clientNonce, hint)
	if err == nil || !strings.Contains(err.Error(), "already spent") {
		t.Fatalf("second spend err = %v, want already spent", err)
	}
}

func TestEncodeAccessHintCredentialSetRejectsInvalidCredential(t *testing.T) {
	// 42-44: a set whose count is in range (2) but whose second credential fails
	// validate() surfaces the per-credential encode-loop error. The first
	// credential is valid so the loop advances past it, proving the validate is
	// per-credential rather than only-first.
	valid := validHintCredential()
	invalid := validHintCredential()
	invalid.MaxUses = 2
	_, err := EncodeAccessHintCredentialSet([]AccessHintCredential{valid, invalid})
	if err == nil || !strings.Contains(err.Error(), "max_uses must be 1") {
		t.Fatalf("EncodeAccessHintCredentialSet err = %v, want max_uses error", err)
	}
}

func TestDecodeAccessHintCredentialSetRejectsInvalidDecodedCredential(t *testing.T) {
	// 63-65: a wire blob that decodes cleanly (all fixed lengths correct, so
	// reader.Err is nil at 60) but whose MaxUses != 1 fails validate() at 63. The
	// blob is built with the low-level encodeAccessHintCredential (which writes
	// raw fields without validating) plus the set's varint count prefix, so the
	// single-credential decoder path (codec 28-30) is NOT exercised here.
	encoder := wire.NewEncoder()
	encoder.WriteVarint(1)
	encodeAccessHintCredential(encoder, AccessHintCredential{
		HintIssuerID:  rep(0x51, 16),
		RelayBucketID: rep(0x52, 16),
		HintEpochID:   7,
		HintSelector:  rep(0x53, 16),
		HintSecret:    rep(0x54, 32),
		ExpiryUnix:    9999,
		MaxUses:       2, // decodes cleanly but fails validate()
	})
	blob, err := encoder.Bytes()
	if err != nil {
		t.Fatalf("encode blob: %v", err)
	}
	_, err = DecodeAccessHintCredentialSet(blob)
	if err == nil || !strings.Contains(err.Error(), "max_uses must be 1") {
		t.Fatalf("DecodeAccessHintCredentialSet err = %v, want max_uses error", err)
	}
}

// errReplayCache is a minimal ReplayCache double whose InsertIfAbsent returns a
// configurable error. It intentionally does NOT implement RetentionReplayCache,
// so InsertIfAbsentRetained surfaces the "does not support retention" error
// when used on the nowUnix!=0 path. Used by both subtests of the cache-error
// propagation test, so it is not U1000.
type errReplayCache struct{ err error }

func (c errReplayCache) InsertIfAbsent([]byte) (bool, error) { return false, c.err }
func (errReplayCache) Has([]byte) bool                       { return false }
