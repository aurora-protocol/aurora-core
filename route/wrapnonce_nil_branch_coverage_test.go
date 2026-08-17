package route

// Adversarial white-box coverage for the count-0 nil-cache guard of
// OpenAndVerifyPrivatePreludeWithWrapNonceCache (route/route.go:271). After
// OpenPrivatePrelude successfully opens a valid sealed route prelude (:267-270),
// the function guards a nil wrapNonceCache before touching it at :274
// (InsertIfAbsent). The :271 body is COUNT 0 because the only existing caller
// tests (TestOpenAndVerifyPrivatePreludeRejectsDuplicateWrapNonceBeforeAccess
// HintSpend) always pass a real NewWrapNonceReplayCache.
//
// Coverage target (baseline measured on main; the body was COUNT 0 while its
// condition was already evaluated 4x):
//   - route.go:271.27,273.3 1 0  — wrapNonceCache == nil -> "missing route wrap
//     nonce replay cache"
//
// Reuses the exact valid-envelope setup proven by
// TestOpenAndVerifyPrivatePreludeRejectsDuplicateWrapNonceBeforeAccessHintSpend
// (route_test.go:258-286): a routeTestEnvelope + routeTestAccessHintCredential +
// routeTestPrivatePrelude whose RoutePreludeWrapContext + AccessHint are
// computed from the route hop binding, then SealPrivatePrelude. The ONLY change
// is passing nil for the wrapNonceCache argument, so OpenPrivatePrelude still
// succeeds (:267-270) and the :271 nil guard fires before any binding/access-hint
// work — proving the guard is reachable on its own, independent of the
// duplicate-nonce happy path.
//
// In-package (package route) because OpenAndVerifyPrivatePreludeWithWrapNonceCache,
// SealPrivatePrelude, RouteHopBinding, and the routeTest* helpers are unexported.
// No context is involved, so there is no SA1012 surface. This test file adds only
// a TestXxx entry point and references existing in-package helpers + the
// admission / auroracrypto packages already imported by route_test.go, so it
// adds no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
)

func TestOpenAndVerifyPrivatePreludeRejectsNilWrapNonceCache(t *testing.T) {
	// Build the same valid sealed route prelude the duplicate-wrap-nonce test
	// uses, so OpenPrivatePrelude succeeds and execution reaches :271.
	env := routeTestEnvelope()
	cred := routeTestAccessHintCredential(env)
	private := routeTestPrivatePrelude(t, env)
	context, err := auroracrypto.RoutePreludeWrapContext(env.routeWrapInput())
	if err != nil {
		t.Fatal(err)
	}
	private.RoutePreludeWrapContext = context
	binding, err := RouteHopBinding(HopBindingInput{
		RouteInstanceID:                private.RouteInstanceID,
		HopIndex:                       private.HopIndex,
		PreviousHopFullTranscriptHash:  private.PreviousHopFullTranscriptHash,
		PreviousHopRelayDescriptorHash: private.PreviousHopRelayDescriptorHash,
		NextRelayDescriptorHash:        private.NextRelayDescriptorHash,
		RoutePreludeWrapContext:        private.RoutePreludeWrapContext,
		ClientNonceForThisHop:          private.ClientNonceForThisHop,
	})
	if err != nil {
		t.Fatal(err)
	}
	private.AccessHint, err = admission.ComputeAccessHint(cred, binding, private.ClientNonceForThisHop)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealPrivatePrelude(env, private)
	if err != nil {
		t.Fatal(err)
	}
	// wrapNonceCache == nil: OpenPrivatePrelude still succeeds (:267-270), then
	// the :271 nil guard rejects before the :274 InsertIfAbsent dereference.
	_, _, err = OpenAndVerifyPrivatePreludeWithWrapNonceCache(admission.NewMemoryReplayCache(), nil, env, envelope, cred, 100, 300)
	if err == nil {
		t.Fatal("OpenAndVerifyPrivatePreludeWithWrapNonceCache(nil cache) err = nil, want non-nil (:271 should reject)")
	}
	if !strings.Contains(err.Error(), "missing route wrap nonce replay cache") {
		t.Fatalf("nil cache err = %q, want substring \"missing route wrap nonce replay cache\" (:272)", err.Error())
	}
}
