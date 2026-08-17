package handshake

// Adversarial white-box coverage for the five count-0 nil-context rejection
// guards in handshake/production_dependencies.go. Each is the FIRST statement
// of a public method and returns a distinct, ctx-specific error before
// touching any receiver field or external state, so it is reachable with a
// zero-valued receiver and a nil context, and the asserted error string
// (which only the ctx guard emits) proves it was the guard that fired — not
// a later receiver-nil or state check.
//
//   - 33-35  — BlindRSAAdmissionVerifier.VerifyAdmission(ctx, proof, _ uint64)
//              -> "handshake: nil Blind RSA verification context".
//   - 78-80  — StaticAccessHintResolver.ResolveAccessHint(ctx, issuerID,
//              relayBucketID, epochID, selector)
//              -> "handshake: nil static access hint context".
//   - 125-127 — FixedProxyPolicySelector.SelectPolicy(ctx, offer, hints)
//              -> "handshake: nil fixed proxy policy context".
//   - 221-223 — ecdsaP256TranscriptSigner.SignTranscript(ctx, transcript)
//              -> "handshake: nil P-256 transcript context".
//   - 278-280 — mldsa65TranscriptSigner.SignTranscript(ctx, transcript)
//              -> "handshake: nil ML-DSA-65 transcript context".
//
// All five methods satisfy exported interfaces (AdmissionVerifier,
// AccessHintResolver, PolicySelector, TranscriptSigner), so a caller passing
// a nil context is a programming error these guards exist to reject with a
// clear message rather than a nil-pointer panic. The two TranscriptSigner
// methods use UNEXPORTED receiver types (ecdsaP256TranscriptSigner,
// mldsa65TranscriptSigner), so this test lives in-package to construct them
// directly; the guard fires before the s.private deref at 227/284, so a
// zero-valued receiver is safe.
//
// Calling these with a literal nil context.Context triggers staticcheck SA1012
// (nil context literal). The codebase convention — established in
// evidence/egress_test.go, evidence/first_hop_test.go, evidence/session_test.go,
// transport/http2_client_test.go, transport/duplex_test.go,
// server/production_test.go, perf/load_branch_coverage_test.go, and
// cmd/aurorac/linux_tun_coverage_test.go — is to suppress it with a
// //lint:ignore SA1012 directive immediately before the call, documenting
// that the call intentionally verifies the public API's nil-context
// rejection. Each of the five calls below carries that directive.
//
// This file adds no package-level helpers: every test constructs its own
// zero-valued receiver inline and reuses exported types only. No goroutines,
// no network, no filesystem, no cryptography — every guard returns before any
// of that is reached.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestBlindRSAAdmissionVerifierRejectsNilContext(t *testing.T) {
	// 33-35: a nil context is rejected before the proof is inspected.
	v := &BlindRSAAdmissionVerifier{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err := v.VerifyAdmission(nil, protocol.AdmissionProof{}, 0)
	if err == nil {
		t.Fatal("VerifyAdmission(nil ctx) err = nil, want non-nil (:33 should fire)")
	}
	if !strings.Contains(err.Error(), "nil Blind RSA verification context") {
		t.Fatalf("VerifyAdmission(nil ctx) err = %v, want substring \"nil Blind RSA verification context\"", err)
	}
}

func TestStaticAccessHintResolverRejectsNilContext(t *testing.T) {
	// 78-80: a nil context is rejected before the selector is matched.
	r := &StaticAccessHintResolver{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := r.ResolveAccessHint(nil, nil, nil, 0, nil)
	if err == nil {
		t.Fatal("ResolveAccessHint(nil ctx) err = nil, want non-nil (:78 should fire)")
	}
	if !strings.Contains(err.Error(), "nil static access hint context") {
		t.Fatalf("ResolveAccessHint(nil ctx) err = %v, want substring \"nil static access hint context\"", err)
	}
}

func TestFixedProxyPolicySelectorRejectsNilContext(t *testing.T) {
	// 125-127: a nil context is rejected before the offer is validated.
	s := &FixedProxyPolicySelector{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := s.SelectPolicy(nil, protocol.PolicyOffer{}, protocol.ClientTransportHints{})
	if err == nil {
		t.Fatal("SelectPolicy(nil ctx) err = nil, want non-nil (:125 should fire)")
	}
	if !strings.Contains(err.Error(), "nil fixed proxy policy context") {
		t.Fatalf("SelectPolicy(nil ctx) err = %v, want substring \"nil fixed proxy policy context\"", err)
	}
}

func TestEcdsaP256TranscriptSignerRejectsNilContext(t *testing.T) {
	// 221-223: a nil context is rejected before the private key is touched
	// (the s.private nil check at 227 is downstream of the guard).
	s := &ecdsaP256TranscriptSigner{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := s.SignTranscript(nil, nil)
	if err == nil {
		t.Fatal("SignTranscript(nil ctx) err = nil, want non-nil (:221 should fire)")
	}
	if !strings.Contains(err.Error(), "nil P-256 transcript context") {
		t.Fatalf("SignTranscript(nil ctx) err = %v, want substring \"nil P-256 transcript context\"", err)
	}
}

func TestMldsa65TranscriptSignerRejectsNilContext(t *testing.T) {
	// 278-280: a nil context is rejected before the private key is touched
	// (the s.private nil check at 284 is downstream of the guard).
	s := &mldsa65TranscriptSigner{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := s.SignTranscript(nil, nil)
	if err == nil {
		t.Fatal("SignTranscript(nil ctx) err = nil, want non-nil (:278 should fire)")
	}
	if !strings.Contains(err.Error(), "nil ML-DSA-65 transcript context") {
		t.Fatalf("SignTranscript(nil ctx) err = %v, want substring \"nil ML-DSA-65 transcript context\"", err)
	}
}
