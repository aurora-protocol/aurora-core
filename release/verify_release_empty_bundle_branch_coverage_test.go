package release

// Adversarial white-box coverage for the two reachable count-0 branches in
// release/release.go's VerifyReleaseReadinessBundle: the two input-validation
// guards at the top of the function.
//
//   - 137-139 — `if bundle.BundleID == "" { return ..., "release: bundle id is
//     empty" }`. VerifyReleaseReadinessBundle is a PUBLIC function that accepts
//     any Bundle. A direct caller passing Bundle{} (zero value, BundleID="") has
//     no bundle identity, so :137 rejects it before any verification runs. The
//     14 existing tests in release_test.go all build a bundle via
//     ReleaseReadinessHarnessBundle(200) (whose BundleID is the hardcoded
//     "release-readiness-harness") and so never trip :137.
//   - 140-142 — `if bundle.NowUnix == 0 { return ..., "release: verification time
//     is empty" }`. A direct caller passing a bundle with a non-empty BundleID
//     but NowUnix==0 passes :137 and is rejected at :140, because release
//     verification is meaningless without a verification time (every time-bound
//     check in the bundle — signature validity windows, update-pipeline
//     freshness, incident-response staleness — is anchored to NowUnix). The
//     harness bundle always sets NowUnix to the caller's nowUnix (200 in the
//     existing tests), so :140 is never reached there.
//
// These are genuine input-validation guards on a public entry point, not the
// hardcoded-always-succeed error boilerplate that dominates the rest of
// release.go's count-0 surface. The dead-by-design count-0 blocks (NOT claimed
// here) are:
//   - 130-132 (RunReleaseReadinessHarness) and 194-196 / 224-226 / 228-230 /
//     235-237 (ReleaseReadinessHarnessBundle) — error propagations from
//     newSigner / artifactSignatureInput / sign / signedUpdatePipeline. The
//     harness builds every artifact and the update pipeline from hardcoded
//     valid inputs (releasePackagingTargets + a fresh in-memory signer), so
//     none of those calls error through this entry point; the guards are
//     defensive boilerplate, the same hardcoded-always-succeed shape as the
//     perf/impairment.go RunImpairmentHarness guards (PR #237) and the
//     transport/conformance.go guards.
//   - 551-553 / 555-557 / 559-561 (signedUpdatePipeline) and 705-707 / 709-711 /
//     718-720 / 730-732 / 742-744 (newSigner / sign / releaseSigningKeyID) —
//     error returns inside the harness's own signer/pipeline builders, again
//     fed only hardcoded-valid inputs, so unreachable through RunReleaseReadinessHarness.
//
// A happy-path lock first confirms a valid harness bundle (non-empty BundleID,
// NowUnix=200) passes both guards and returns a nil error, so the two
// rejections are meaningful contrasts, not just nil-checks.

import (
	"strings"
	"testing"
)

func TestVerifyReleaseReadinessRejectsEmptyBundleID(t *testing.T) {
	// 137-139: a zero-valued Bundle has no BundleID, so VerifyReleaseReadinessBundle
	// rejects it at the first guard before any verification runs.
	_, err := VerifyReleaseReadinessBundle(Bundle{})
	if err == nil {
		t.Fatal("VerifyReleaseReadinessBundle(Bundle{}) err = nil, want non-nil (:137 should fire)")
	}
	if !strings.Contains(err.Error(), "bundle id is empty") {
		t.Fatalf("VerifyReleaseReadinessBundle(Bundle{}) err = %v, want substring \"bundle id is empty\"", err)
	}
}

func TestVerifyReleaseReadinessRejectsZeroVerificationTime(t *testing.T) {
	// 140-142: a bundle with a non-empty BundleID but NowUnix==0 passes :137 and
	// is rejected at :140, because verification is meaningless without a time
	// anchor.
	_, err := VerifyReleaseReadinessBundle(Bundle{BundleID: "release-readiness-harness"})
	if err == nil {
		t.Fatal("VerifyReleaseReadinessBundle(non-empty ID, NowUnix=0) err = nil, want non-nil (:140 should fire)")
	}
	if !strings.Contains(err.Error(), "verification time is empty") {
		t.Fatalf("VerifyReleaseReadinessBundle(NowUnix=0) err = %v, want substring \"verification time is empty\"", err)
	}
}

func TestVerifyReleaseReadinessAcceptsValidBundle(t *testing.T) {
	// Happy-path lock so the :137/:140 rejections are meaningful contrasts: a
	// valid harness bundle (BundleID="release-readiness-harness", NowUnix=200)
	// passes both guards and VerifyReleaseReadinessBundle returns a nil error.
	// (The full pass-report assertions are covered by release_test.go's
	// TestReleaseReadinessHarnessCoversProductionGates; here we only lock the
	// nil-error guard contract.)
	bundle, err := ReleaseReadinessHarnessBundle(200)
	if err != nil {
		t.Fatalf("ReleaseReadinessHarnessBundle(200) err = %v, want nil", err)
	}
	_, err = VerifyReleaseReadinessBundle(bundle)
	if err != nil {
		t.Fatalf("VerifyReleaseReadinessBundle(valid) err = %v, want nil (both :137 and :140 should pass)", err)
	}
}
