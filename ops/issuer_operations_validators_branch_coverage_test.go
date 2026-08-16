package ops

// Adversarial white-box coverage for the pure validators of
// ops/issuer_operations.go. These are the deterministic, no-network,
// no-cryptography helpers that the issuer-operations harness delegates to:
// BuildAccessHintCredential (the access-hint credential builder, which derives
// a deterministic HKDF hint secret), the public-relay proof-policy gate, the
// issuer-metadata proof/verifier-service usability checks, and the small
// byte-repeat helper. Every branch below is reached with constructible value
// inputs and an explicit nowUnix — no signature verification, no live verifier
// service, no filesystem, no goroutines. validateHintEpochProvision (328-360)
// is already fully covered by the harness and is only re-entered transitively
// via BuildAccessHintCredential:96; its propagation at :97 is already covered
// and not claimed here.
//
// Targets covered:
//
//   - BuildAccessHintCredential:99-101 — the `len(hintSelector) != 16` guard.
//     The existing suite drives the builder only with a 16-byte selector, so
//     the "hint selector must be 16 bytes" return is unreached. A 3-byte
//     selector (with an otherwise-valid provision) hits it after
//     validateHintEpochProvision succeeds at :96.
//   - BuildAccessHintCredential:105-107 — the `expiryUnix <= nowUnix` guard.
//     The existing suite always passes a future expiry, so the "expiry is not
//     in the future" return is unreached. An expiry below now (but nonzero and
//     within the provision's ValidUntilUnix, so the :102 range guard passes)
//     hits it.
//   - verifyPublicRelayProofPolicy:394-396 — the `!PublicRelay ||
//     IssuerCoordinatedVOPRF` early return. The existing harness only exercises
//     the public-relay-not-coordinated path that proceeds to the Blind RSA
//     check, so the early-skip return is unreached. Both sub-conditions are
//     exercised: a non-public profile and a public-but-issuer-coordinated
//     profile both return true and add no finding.
//   - metadataHasUsableProof:423-424 — the `return false` when the proof type is
//     supported but no usable token-key mapping exists. The existing suite
//     drives this only with metadata that has a valid key, so the
//     supported-but-no-valid-key return is unreached. Metadata that advertises
//     the proof type with NO token-key mappings reaches :423 (the
//     TokenKeyMappings loop at :415 never executes). A contrast with an
//     unsupported proof type locks the semantic (both return false, but via
//     different branches — :412 for unsupported, :423 for supported-with-no-key).
//   - metadataHasUsableVerifierServiceForProof:428-430 — the
//     `len(activeScopes) == 0` guard. The existing suite drives this only with
//     metadata that has an active relay-bucket scope, so the no-active-scope
//     return is unreached. Both sub-paths are exercised: metadata with no
//     relay-bucket scopes at all, and metadata whose only scope is outside the
//     now-window (activeRelayBucketScopes :444 filters it out) — both produce an
//     empty active-scope slice and hit :428.
//   - repeatedOpsByte:455-460 — the byte-repeat helper. It is only referenced by
//     issuerOperationsHarnessProfile (the integration-gated harness
//     constructor at 123-249, which the suite never builds directly), so it is
//     entirely unreached. A direct call covers it.
//
// Dead-by-design (documented, NOT claimed):
//   - BuildAccessHintCredential:109-111 — the admission.DeriveHintSecret error
//     propagation. DeriveHintSecret (admission/access_hint.go:36) only errors
//     on context.Bytes() (its four WriteOpaqueFixed inputs — issuerID 16,
//     relayBucketID 16, hintSelector 16 — are all length-validated upstream by
//     validateHintEpochProvision :329 and BuildAccessHintCredential :99) and on
//     HKDFExtractSHA384 (HMAC, which cannot fail) / HKDFExpandLabelSHA384 (a
//     32-byte expand, far below the 255*HashLen ceiling). So a provision that
//     passes :96 and a selector that passes :99 cannot make DeriveHintSecret
//     fail, and :109 is unreachable. DeriveHintSecret-can't-fail-for-valid-
//     validated-inputs.
//
// validHintProvision is referenced by three tests (the BuildAccessHintCredential
// success lock and the :99/:105 guards), so there is no staticcheck U1000
// surface. No context.Context (no SA1012 surface), no goroutines, no
// cryptography beyond a deterministic HKDF, no real network or filesystem.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// validHintProvision returns a HintEpochProvision that passes
// validateHintEpochProvision at now=500 (ValidFrom 100 < 500 < 1000
// ValidUntil, with mutual auth, transport encryption, an audit record, no
// revocation, and no user-specific table).
func validHintProvision() HintEpochProvision {
	return HintEpochProvision{
		IssuerID:                     make([]byte, 16),
		RelayBucketID:                make([]byte, 16),
		HintEpochID:                  1,
		VerifierSecret:               make([]byte, 32),
		ValidFromUnix:                100,
		ValidUntilUnix:               1000,
		OperatorChannelAuthenticated: true,
		OperatorChannelEncrypted:     true,
		RotationAuditID:              "audit-rotation-0001",
	}
}

func TestBuildAccessHintCredentialRejectsHintSelectorLength(t *testing.T) {
	// 99-101: a 3-byte selector fails the length guard after the provision
	// validates at :96.
	_, err := BuildAccessHintCredential(validHintProvision(), []byte{0x01, 0x02, 0x03}, 800, 500)
	if err == nil ||
		!strings.Contains(err.Error(), "hint selector must be 16 bytes") {
		t.Fatalf("BuildAccessHintCredential(short selector) err = %v, want substring \"hint selector must be 16 bytes\"", err)
	}
}

func TestBuildAccessHintCredentialRejectsExpiredCredential(t *testing.T) {
	// 105-107: expiryUnix (400) is below nowUnix (500) but nonzero and within
	// ValidUntilUnix (1000), so the :102 range guard passes and the not-in-the-
	// future guard at :105 fires.
	_, err := BuildAccessHintCredential(validHintProvision(), make([]byte, 16), 400, 500)
	if err == nil ||
		!strings.Contains(err.Error(), "access hint credential expiry is not in the future") {
		t.Fatalf("BuildAccessHintCredential(past expiry) err = %v, want substring \"access hint credential expiry is not in the future\"", err)
	}
}

func TestBuildAccessHintCredentialSucceedsAndIsDeterministic(t *testing.T) {
	// Success lock for the non-nil path so the :99/:105 guards are meaningful
	// contrasts, and a determinism lock on the derived hint secret (HKDF over
	// fixed inputs is byte-identical across calls).
	cred, err := BuildAccessHintCredential(validHintProvision(), make([]byte, 16), 800, 500)
	if err != nil {
		t.Fatalf("BuildAccessHintCredential(valid) err = %v, want nil", err)
	}
	if cred.ExpiryUnix != 800 {
		t.Fatalf("ExpiryUnix = %d, want 800", cred.ExpiryUnix)
	}
	if len(cred.HintSelector) != 16 || len(cred.HintIssuerID) != 16 || len(cred.RelayBucketID) != 16 {
		t.Fatalf("credential field lengths: selector=%d issuer=%d bucket=%d, want 16/16/16",
			len(cred.HintSelector), len(cred.HintIssuerID), len(cred.RelayBucketID))
	}
	if len(cred.HintSecret) == 0 {
		t.Fatal("HintSecret is empty, want a derived HKDF secret")
	}
	if cred.MaxUses != 1 {
		t.Fatalf("MaxUses = %d, want 1", cred.MaxUses)
	}
	again, err := BuildAccessHintCredential(validHintProvision(), make([]byte, 16), 800, 500)
	if err != nil {
		t.Fatalf("BuildAccessHintCredential(valid, second) err = %v, want nil", err)
	}
	if !bytes.Equal(cred.HintSecret, again.HintSecret) {
		t.Fatal("HintSecret is non-deterministic across two calls with identical inputs")
	}
}

func TestVerifyPublicRelayProofPolicySkipsNonPublicAndCoordinated(t *testing.T) {
	// 394-396: both sub-conditions of the early-skip return true with no finding.

	// !PublicRelay: a zero-value profile is not a public relay.
	report := &IssuerOperationsReport{}
	if !verifyPublicRelayProofPolicy(IssuerOperationsProfile{}, report) {
		t.Fatal("verifyPublicRelayProofPolicy(non-public) = false, want true")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("non-public report findings = %v, want none", report.Findings)
	}

	// IssuerCoordinatedVOPRF: a public relay that is issuer-coordinated also skips.
	coordinated := &IssuerOperationsReport{}
	if !verifyPublicRelayProofPolicy(IssuerOperationsProfile{PublicRelay: true, IssuerCoordinatedVOPRF: true}, coordinated) {
		t.Fatal("verifyPublicRelayProofPolicy(coordinated) = false, want true")
	}
	if len(coordinated.Findings) != 0 {
		t.Fatalf("coordinated report findings = %v, want none", coordinated.Findings)
	}
}

func TestMetadataHasUsableProofRejectsSupportedTypeWithoutValidKey(t *testing.T) {
	// 423-424: the proof type is advertised but no token-key mapping exists, so
	// the TokenKeyMappings loop at :415 never runs and :423 returns false.
	supportedNoKey := protocol.IssuerMetadata{
		SupportedProofTypes: []uint64{registry.ProofVOPRFP384SHA384},
	}
	if metadataHasUsableProof(supportedNoKey, registry.ProofVOPRFP384SHA384, 500) {
		t.Fatal("metadataHasUsableProof(supported, no key) = true, want false")
	}

	// Contrast: an unsupported proof type returns false via the :412 branch
	// (already covered), locking the semantic that the supported case above
	// fails specifically because of the missing key, not because it is
	// unsupported.
	if metadataHasUsableProof(protocol.IssuerMetadata{}, registry.ProofVOPRFP384SHA384, 500) {
		t.Fatal("metadataHasUsableProof(unsupported) = true, want false")
	}
}

func TestMetadataHasUsableVerifierServiceRejectsNoActiveScopes(t *testing.T) {
	// 428-430: no active relay-bucket scopes -> activeRelayBucketScopes returns
	// an empty slice -> :428 returns false. Both sub-paths are exercised.

	// No relay-bucket scopes at all.
	if metadataHasUsableVerifierServiceForProof(protocol.IssuerMetadata{}, registry.ProofVOPRFP384SHA384, 500) {
		t.Fatal("metadataHasUsableVerifierServiceForProof(no scopes) = true, want false")
	}

	// A scope that exists but is outside the now-window (filtered out by
	// activeRelayBucketScopes :444), so the active slice is still empty.
	outOfWindow := protocol.IssuerMetadata{
		RelayBucketScopes: []protocol.RelayBucketScope{{
			ValidFromUnix:  10000,
			ValidUntilUnix: 20000,
		}},
	}
	if metadataHasUsableVerifierServiceForProof(outOfWindow, registry.ProofVOPRFP384SHA384, 500) {
		t.Fatal("metadataHasUsableVerifierServiceForProof(out-of-window scope) = true, want false")
	}
}

func TestRepeatedOpsByte(t *testing.T) {
	// 455-460: the harness-only byte-repeat helper, covered by a direct call.
	out := repeatedOpsByte(0xAB, 4)
	if !bytes.Equal(out, []byte{0xAB, 0xAB, 0xAB, 0xAB}) {
		t.Fatalf("repeatedOpsByte(0xAB, 4) = % x, want abababab", out)
	}
	if len(repeatedOpsByte(0x00, 0)) != 0 {
		t.Fatal("repeatedOpsByte(0x00, 0) is non-empty, want empty")
	}
}
