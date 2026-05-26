package platform

import "testing"

func TestPackagingBlueprintsCoverReleaseAndCITargets(t *testing.T) {
	report, err := VerifyPackagingBlueprints(PackagingBlueprints())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("packaging conformance failed: %+v", report)
	}
	if report.ReleaseTargets != 6 || report.EntitlementFreeCITargets < 3 {
		t.Fatalf("unexpected release/CI target counts: %+v", report)
	}
	if report.ThinAdapterTargets != len(report.Targets) || report.NoCryptoTargets != len(report.Targets) {
		t.Fatalf("packaging targets are not thin/no-crypto: %+v", report)
	}
	for _, want := range []string{"apple-release", "apple-ci", "android-release", "android-ci", "portable-ci"} {
		if !packagingReportHasTarget(report, want) {
			t.Fatalf("packaging report missing target %s: %+v", want, report)
		}
	}
}

func TestPackagingBlueprintVerificationRejectsAppleReleaseWithoutNetworkExtension(t *testing.T) {
	targets := PackagingBlueprints()
	for i := range targets {
		if targets[i].Name == "apple-release" {
			targets[i].RequiredEntitlements = []string{"app-group", "keychain-sharing"}
		}
	}
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("Apple release without Network Extension entitlement passed: %+v", report)
	}
	if !packagingReportHasFailure(report, "apple-release", "required_entitlement") {
		t.Fatalf("report missing Apple entitlement failure: %+v", report.Failures)
	}
}

func TestPackagingBlueprintVerificationRejectsEntitledCITarget(t *testing.T) {
	targets := PackagingBlueprints()
	for i := range targets {
		if targets[i].Name == "apple-ci" {
			targets[i].RequiredEntitlements = []string{"network-extension"}
		}
	}
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("CI target with entitlements passed: %+v", report)
	}
	if !packagingReportHasFailure(report, "apple-ci", "ci_entitlements") {
		t.Fatalf("report missing CI entitlement failure: %+v", report.Failures)
	}
}

func TestPackagingBlueprintVerificationRejectsCryptoInPlatformTarget(t *testing.T) {
	targets := PackagingBlueprints()
	targets[0].ContainsCryptoState = true
	report, err := VerifyPackagingBlueprints(targets)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("platform target with crypto state passed: %+v", report)
	}
	if !packagingReportHasFailure(report, targets[0].Name, "no_crypto_state") {
		t.Fatalf("report missing crypto-state failure: %+v", report.Failures)
	}
}

func packagingReportHasTarget(report PackagingConformanceReport, name string) bool {
	for _, target := range report.Targets {
		if target.Name == name {
			return true
		}
	}
	return false
}

func packagingReportHasFailure(report PackagingConformanceReport, name, field string) bool {
	for _, failure := range report.Failures {
		if failure.TargetName == name && failure.Field == field {
			return true
		}
	}
	return false
}
