package client

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across client/provisioned_session.go. Each guard exists so a caller that
// holds a nil *IssuerWork / *ProvisionedSession — or passes a nil context / nil
// provisioning value to the zeroers — does not panic or proceed past an
// uninitialised state: the function returns at its very first statement, before
// any field is dereferenced (w.RequestBody, s.mu, s.established, value.IssuerMetadata)
// or any context method is called (ctx.Err). The existing client tests only ever
// drive a fully-built ProvisionedSession and populated provisioning/proof values
// along the live provision → complete path, so the nil guards stayed count-0 even
// though each is plainly reachable.
//
// The test is in-package because newProvisionedSession and the four zero* helpers
// are unexported. Eight of the nine guards are nil-RECEIVER / nil-ARGUMENT guards
// driven with context.Background (never a nil context literal), so they have no
// SA1012 surface. The remaining guard — :86 newProvisionedSession's ctx==nil reject
// — is a nil-CONTEXT guard and requires passing a nil context, which staticcheck
// flags as SA1012. This is the established codebase convention (see
// handshake/production_dependencies_nil_context_branch_coverage_test.go and 10+
// other usages, CI-proven on PR #264's production-evidence): the nil-context call
// is preceded immediately by
//
//	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
//
// so staticcheck suppresses the warning for that one intentional call. Local
// staticcheck is broken (go1.26 module), so SA1012 is verified only in CI's
// production-evidence staticcheck@v0.7.0; the directive is CI-proven across the repo.
//
//   - :37  IssuerWork.Zero()                            w == nil -> no-op return
//     (void; proven by absence of panic via a recover wrapper)
//   - :86  newProvisionedSession(ctx, provisioning, options)  ctx == nil
//     -> nil, IssuerWork{}, "client: nil provisioned session context" (UNEXPORTED;
//     the ctx==nil guard fires before ctx.Err at 90)
//   - :157 ProvisionedSession.Complete(ctx, issuerResponse)  s == nil
//     -> nil, "client: nil provisioned session" (ctx=Background; s==nil fires before
//     the ctx==nil guard at 161)
//   - :248 ProvisionedSession.Established()           s == nil -> nil
//   - :258 ProvisionedSession.Close()                 s == nil -> nil
//   - :445 zeroProvisioningForSession(value)          value == nil -> no-op return
//     (UNEXPORTED; void; no-panic proof)
//   - :475 zeroProvisionedProofRequest(value)         value == nil -> no-op return
//     (UNEXPORTED; void; no-panic proof)
//   - :485 zeroProvisionedAdmissionProof(value)       value == nil -> no-op return
//     (UNEXPORTED; void; no-panic proof)
//   - :508 zeroProvisionedReplayProof(value)           value == nil -> no-op return
//     (UNEXPORTED; void; no-panic proof)
//
// This test file adds only TestXxx entry points and uses existing exported (plus
// unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
)

func TestIssuerWorkZeroIsNilSafe(t *testing.T) {
	// 37: a nil *IssuerWork returns at the first statement of Zero rather than
	// dereferencing w.RequestBody / assigning through *w. Void; proven by absence
	// of panic via a recover wrapper.
	var w *IssuerWork
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.IssuerWork.Zero panicked = %v, want no-op return (:37 should guard the nil receiver)", r)
			}
		}()
		w.Zero()
	}()
}

func TestNewProvisionedSessionRejectsNilContext(t *testing.T) {
	// 86: newProvisionedSession rejects a nil context at its first statement with
	// "nil provisioned session context", before ctx.Err runs. The provisioning and
	// options args are never read. SA1012 is suppressed for this one intentional
	// nil-context call (established codebase convention, CI-proven on #264).
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	session, work, err := newProvisionedSession(nil, NativeProvisioning{}, ProvisionedSessionOptions{})
	if err == nil {
		t.Fatal("newProvisionedSession(nil ctx) err = nil, want non-nil (:86 should reject)")
	}
	if !strings.Contains(err.Error(), "nil provisioned session context") {
		t.Fatalf("newProvisionedSession(nil ctx) err = %q, want substring \"nil provisioned session context\" (:86)", err.Error())
	}
	if session != nil {
		t.Fatalf("newProvisionedSession(nil ctx) session = %v, want nil (:86)", session)
	}
	_ = work // IssuerWork zero value is the expected return; nothing to assert.
}

func TestProvisionedSessionNilReceiverGuards(t *testing.T) {
	// 157/248/258: a nil *ProvisionedSession returns at the first statement of
	// Complete / Established / Close rather than dereferencing s.mu / s.established.
	// Complete is driven with context.Background so the nil-receiver guard fires
	// before the ctx==nil guard at 161 (no SA1012).
	var s *ProvisionedSession
	ctx := context.Background()

	// 157: Complete returns "nil provisioned session".
	if session, err := s.Complete(ctx, nil); err == nil {
		t.Fatal("nil.Complete err = nil, want non-nil (:157 should reject)")
	} else if !strings.Contains(err.Error(), "nil provisioned session") {
		t.Fatalf("nil.Complete err = %q, want substring \"nil provisioned session\" (:157)", err.Error())
	} else if session != nil {
		t.Fatalf("nil.Complete session = %v, want nil (:157)", session)
	}

	// 248: Established returns nil.
	if established := s.Established(); established != nil {
		t.Fatalf("nil.Established = %v, want nil (:248)", established)
	}

	// 258: Close returns nil.
	if err := s.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:258 should return nil)", err)
	}
}

func TestProvisionedSessionZeroerNilArgumentGuards(t *testing.T) {
	// 445/475/485/508: the four unexported zeroers return at their first statement
	// when given a nil value pointer, before iterating the value's fields. Each is
	// void; the proof is that the call completes without panicking (a panic surfaces
	// as a test failure).
	zeroProvisioningForSession(nil)
	zeroProvisionedProofRequest(nil)
	zeroProvisionedAdmissionProof(nil)
	zeroProvisionedReplayProof(nil)
}
