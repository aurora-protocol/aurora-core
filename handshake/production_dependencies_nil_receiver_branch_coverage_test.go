package handshake

// Adversarial white-box coverage for three count-0 nil-receiver safety guards
// in the production dependency implementations. Each method begins with a
// `ctx == nil` guard, a `ctx.Err()` guard, and then a nil-RECEIVER guard that
// returns a "missing" error before any field of the receiver (or any method
// argument) is dereferenced. The existing handshake tests only ever drive
// these methods on a constructed (non-nil) receiver, so the nil-receiver
// branch stayed count-0 even though each is plainly reachable by invoking the
// method through a nil pointer receiver.
//
//   - production_dependencies.go:39 (*BlindRSAAdmissionVerifier).VerifyAdmission
//     v == nil -> "handshake: Blind RSA admission verifier is missing" (fires
//     after the ctx == nil guard at :33 and the ctx.Err() guard at :36, before
//     admission.VerifyBlindRSA2048 dereferences v.verificationKeyDER at :42).
//   - production_dependencies.go:84 (*StaticAccessHintResolver).ResolveAccessHint
//     r == nil -> "handshake: static access hint resolver is missing" (fires
//     after the ctx == nil guard at :78 and the ctx.Err() guard at :81, before
//     r.credentials is indexed at :87).
//   - production_dependencies.go:131 (*FixedProxyPolicySelector).SelectPolicy
//     s == nil -> "handshake: fixed proxy policy selector is missing" (fires
//     after the ctx == nil guard at :125 and the ctx.Err() guard at :128,
//     before offer.ValidateStructural at :134 / s.accept() at :140).
//
// Proof technique: invoke each method through a typed nil pointer receiver
// (e.g. `var v *BlindRSAAdmissionVerifier; v.VerifyAdmission(...)`). A nil
// pointer receiver is a well-defined Go call — the method body runs with the
// receiver == nil — and the guard's condition is then satisfied, so the branch
// executes and returns the "missing" error. The "is missing" message uniquely
// identifies the nil-receiver guard: the fall-through paths return different
// errors (an admission-verification failure, "credential is unavailable", or
// an offer-validation failure).
//
// Each exercised guard is the nil-RECEIVER guard (the branch taken when the
// receiver is nil), NOT the ctx == nil guard (each method's own ctx == nil
// guard is earlier and already covered). To reach the nil-receiver guard the
// context must be non-nil and not canceled, so the test passes
// context.Background() (ctx.Err() == nil) and there is no SA1012 surface. No
// network, no goroutine, no real proof / credential / offer — each guard
// returns before any argument is dereferenced, so the test is pure.
// In-package (package handshake) because the receiver types are exported but
// the test constructs them only as nil receivers, and the package owns the
// method set.
//
// This test file adds only TestXxx entry points and references existing
// exported in-package symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestBlindRSAAdmissionVerifierNilReceiverGuard(t *testing.T) {
	// 39: a VerifyAdmission call through a nil receiver returns the
	// "admission verifier is missing" error at the nil-receiver guard, before
	// admission.VerifyBlindRSA2048 dereferences v.verificationKeyDER. A non-nil
	// context is required so the earlier ctx == nil / ctx.Err() guards do not
	// short-circuit. The proof argument is not touched before :39.
	var v *BlindRSAAdmissionVerifier
	err := v.VerifyAdmission(context.Background(), protocol.AdmissionProof{}, 0)
	if err == nil {
		t.Fatal("VerifyAdmission(nil receiver) err = nil, want non-nil (:39 should reject)")
	} else if !strings.Contains(err.Error(), "Blind RSA admission verifier is missing") {
		t.Fatalf("VerifyAdmission(nil receiver) err = %q, want substring \"Blind RSA admission verifier is missing\" (:39)", err.Error())
	}
}

func TestStaticAccessHintResolverNilReceiverGuard(t *testing.T) {
	// 84: a ResolveAccessHint call through a nil receiver returns the
	// "resolver is missing" error at the nil-receiver guard, before
	// r.credentials is indexed. A non-nil context is required so the earlier
	// ctx == nil / ctx.Err() guards do not short-circuit. The lookup arguments
	// are not touched before :84.
	var r *StaticAccessHintResolver
	_, err := r.ResolveAccessHint(context.Background(), nil, nil, 0, nil)
	if err == nil {
		t.Fatal("ResolveAccessHint(nil receiver) err = nil, want non-nil (:84 should reject)")
	} else if !strings.Contains(err.Error(), "static access hint resolver is missing") {
		t.Fatalf("ResolveAccessHint(nil receiver) err = %q, want substring \"static access hint resolver is missing\" (:84)", err.Error())
	}
}

func TestFixedProxyPolicySelectorNilReceiverGuard(t *testing.T) {
	// 131: a SelectPolicy call through a nil receiver returns the
	// "selector is missing" error at the nil-receiver guard, before
	// offer.ValidateStructural / s.accept() run. A non-nil context is required
	// so the earlier ctx == nil / ctx.Err() guards do not short-circuit. The
	// offer / hints arguments are not touched before :131.
	var s *FixedProxyPolicySelector
	_, err := s.SelectPolicy(context.Background(), protocol.PolicyOffer{}, protocol.ClientTransportHints{})
	if err == nil {
		t.Fatal("SelectPolicy(nil receiver) err = nil, want non-nil (:131 should reject)")
	} else if !strings.Contains(err.Error(), "fixed proxy policy selector is missing") {
		t.Fatalf("SelectPolicy(nil receiver) err = %q, want substring \"fixed proxy policy selector is missing\" (:131)", err.Error())
	}
}
