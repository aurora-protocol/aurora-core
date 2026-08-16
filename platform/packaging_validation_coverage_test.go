package platform

// Adversarial white-box coverage for eight branches of platform/packaging.go
// that the existing packaging_test.go suite never reaches. packaging.go is
// pure stdlib (only "fmt") and every branch below is driven with crafted
// PackagingTarget inputs or a direct helper call — no network, no filesystem,
// no goroutine.
//
// Targets covered:
//
//   - VerifyPackagingBlueprints:64-66 — the `len(targets) == 0` guard. The
//     existing suite always passes PackagingBlueprints() (9 targets) or a
//     mutated copy, so an empty slice never reaches "no packaging targets".
//   - VerifyPackagingBlueprints:75-77 — the `target.Name == ""` guard. The
//     existing targets always carry a name, so "name is empty" is unreached.
//   - VerifyPackagingBlueprints:78-80 — the duplicate-name guard. The existing
//     targets are all uniquely named, so "duplicate packaging target" is
//     unreached; two same-named targets hit it.
//   - VerifyPackagingBlueprints:111-113 — the `!HasLocalProxyFallback`
//     failure. Every blueprint target sets HasLocalProxyFallback=true (release
//     targets via ProfileFor(...).HasNoKernelLocalInterface(), which is true
//     because every localModes(true) profile supports SOCKS5; CI targets set
//     it explicitly), so the local_proxy_fallback failure is unreached.
//   - VerifyPackagingBlueprints:114-116 — the `!UsesThinAdapter` failure. Every
//     blueprint target sets UsesThinAdapter=true, so the thin_adapter failure
//     is unreached.
//   - VerifyPackagingBlueprints:127-129 — the missing-release-target failure.
//     PackagingBlueprints() includes all six release kinds, so the
//     "missing_release_target" failure is unreached; a targets list with no
//     release targets fires it for all six kinds.
//   - VerifyPackagingBlueprints:132-134 — the missing-CI-target failure.
//     PackagingBlueprints() includes apple-ci, android-ci, and portable-ci
//     (KindCI), so the "missing_ci_target" failure is unreached; a targets list
//     with no CI targets fires it for KindApple, KindAndroid, and KindCI.
//   - requiredReleaseEntitlements:201-203 — the default branch returning nil.
//     Every release blueprint uses one of the cased kinds (Linux/FreeBSD/
//     OpenWrt/Windows/Apple/Android), so the default (nil) branch is unreached;
//     calling it with KindCI (a non-release kind) hits it.
//
// The existing packagingReportHasFailure helper (packaging_test.go:88) and
// PackagingBlueprints() are reused; no new package-level helpers or types are
// introduced (only test functions), so there is nothing for staticcheck U1000.
// No context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"strings"
	"testing"
)

func TestVerifyPackagingBlueprintsRejectsEmptyTargets(t *testing.T) {
	if _, err := VerifyPackagingBlueprints(nil); err == nil ||
		!strings.Contains(err.Error(), "no packaging targets") {
		t.Fatalf("VerifyPackagingBlueprints(nil) err = %v, want substring \"no packaging targets\"", err)
	}
	// An empty (non-nil) slice must hit the same guard.
	if _, err := VerifyPackagingBlueprints([]PackagingTarget{}); err == nil ||
		!strings.Contains(err.Error(), "no packaging targets") {
		t.Fatalf("VerifyPackagingBlueprints([]) err = %v, want substring \"no packaging targets\"", err)
	}
}

func TestVerifyPackagingBlueprintsRejectsEmptyTargetName(t *testing.T) {
	targets := []PackagingTarget{{Name: ""}}
	if _, err := VerifyPackagingBlueprints(targets); err == nil ||
		!strings.Contains(err.Error(), "name is empty") {
		t.Fatalf("VerifyPackagingBlueprints(empty name) err = %v, want substring \"name is empty\"", err)
	}
}

func TestVerifyPackagingBlueprintsRejectsDuplicateTargetName(t *testing.T) {
	// Two same-named, otherwise-inert targets: the first passes the name and
	// duplicate guards and is recorded; the second hits the duplicate guard.
	targets := []PackagingTarget{
		{Name: "dupe", UsesThinAdapter: true, HasLocalProxyFallback: true},
		{Name: "dupe", UsesThinAdapter: true, HasLocalProxyFallback: true},
	}
	_, err := VerifyPackagingBlueprints(targets)
	if err == nil || !strings.Contains(err.Error(), "duplicate packaging target dupe") {
		t.Fatalf("VerifyPackagingBlueprints(dupe) err = %v, want substring \"duplicate packaging target dupe\"", err)
	}
}

func TestVerifyPackagingBlueprintsFlagsMissingLocalProxyFallback(t *testing.T) {
	// A target without a local-proxy fallback hits the 111-113 failure. The
	// other invariants are held (thin adapter present, no crypto state) so the
	// local_proxy_fallback failure is attributable to this target alone.
	targets := []PackagingTarget{{
		Name:                  "no-fallback",
		UsesThinAdapter:       true,
		HasLocalProxyFallback: false,
	}}
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatalf("VerifyPackagingBlueprints: %v", err)
	}
	if report.Passed {
		t.Fatalf("target without local-proxy fallback passed: %+v", report)
	}
	if !packagingReportHasFailure(report, "no-fallback", "local_proxy_fallback") {
		t.Fatalf("report missing local_proxy_fallback failure: %+v", report.Failures)
	}
}

func TestVerifyPackagingBlueprintsFlagsMissingThinAdapter(t *testing.T) {
	targets := []PackagingTarget{{
		Name:                  "no-thin",
		UsesThinAdapter:       false,
		HasLocalProxyFallback: true,
	}}
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatalf("VerifyPackagingBlueprints: %v", err)
	}
	if report.Passed {
		t.Fatalf("target without thin adapter passed: %+v", report)
	}
	if !packagingReportHasFailure(report, "no-thin", "thin_adapter") {
		t.Fatalf("report missing thin_adapter failure: %+v", report.Failures)
	}
}

func TestVerifyPackagingBlueprintsFlagsMissingReleaseTargets(t *testing.T) {
	// A targets list containing only CI targets leaves releaseKinds empty, so
	// the post-loop check fires missing_release_target for all six release
	// kinds. CI kinds (Apple, Android, CI) are all present, so the CI check
	// does not fire.
	var targets []PackagingTarget
	for _, target := range PackagingBlueprints() {
		if target.CI {
			targets = append(targets, target)
		}
	}
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatalf("VerifyPackagingBlueprints: %v", err)
	}
	var missingRelease int
	for _, failure := range report.Failures {
		if failure.Field == "missing_release_target" {
			missingRelease++
		}
	}
	if missingRelease != 6 {
		t.Fatalf("missing_release_target failures = %d, want 6 (one per release kind): %+v", missingRelease, report.Failures)
	}
}

func TestVerifyPackagingBlueprintsFlagsMissingCITargets(t *testing.T) {
	// A targets list containing only release targets populates releaseKinds for
	// all six release kinds (so missing_release_target does not fire) but leaves
	// ciKinds empty, so the post-loop check fires missing_ci_target for KindApple,
	// KindAndroid, and KindCI.
	var targets []PackagingTarget
	for _, target := range PackagingBlueprints() {
		if target.Release {
			targets = append(targets, target)
		}
	}
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatalf("VerifyPackagingBlueprints: %v", err)
	}
	var missingCI int
	for _, failure := range report.Failures {
		if failure.Field == "missing_ci_target" {
			missingCI++
		}
	}
	if missingCI != 3 {
		t.Fatalf("missing_ci_target failures = %d, want 3 (Apple, Android, CI): %+v", missingCI, report.Failures)
	}
}

func TestRequiredReleaseEntitlementsReturnsEmptyForNonReleaseKind(t *testing.T) {
	// KindCI is not a cased release kind, so the default branch (line 201)
	// returns nil. Anchor: a cased release kind returns its entitlements.
	if got := requiredReleaseEntitlements(KindCI); got != nil {
		t.Fatalf("requiredReleaseEntitlements(KindCI) = %v, want nil", got)
	}
	if got := requiredReleaseEntitlements(KindLinux); len(got) != 1 || got[0] != "tun-device" {
		t.Fatalf("requiredReleaseEntitlements(KindLinux) = %v, want [tun-device]", got)
	}
}
