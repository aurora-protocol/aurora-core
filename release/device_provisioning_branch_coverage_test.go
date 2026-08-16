package release

// Adversarial white-box coverage for verifyDeviceProvisioning
// (release/release.go 451-498), the device-provisioning evidence gate of the
// release-readiness harness. verifyDeviceProvisioning walks a set of release
// packaging targets and checks that each one has exactly one matching
// DeviceProvisioningEvidence whose platform, entitlements, provisioning
// identity/profile, and policy checks all agree with the target. Every branch
// below is reached with plain struct literals — no cryptography, no network,
// no filesystem, no goroutines. The existing readiness harness exercises the
// matching-evidence happy path and the unknown/duplicate/missing-evidence
// guards (459/464/473, already covered), so the four per-target rejection
// checks are the count-0 surface.
//
// Targets covered (previously count-0):
//
//   - :478-481 — the platform mismatch. The evidence targets a packaging
//     target whose platform.Kind differs from the evidence's Platform. Reached
//     by keeping the evidence valid in every other respect but flipping its
//     Platform to a different platform.Kind.
//   - :482-486 — the missing-entitlement check. The target declares a required
//     entitlement that the evidence's Entitlements slice does not contain
//     (hasString returns false). Reached by dropping one entitlement from the
//     evidence while the target still requires it.
//   - :488-490 — the identity/profile incompleteness check, an OR of three
//     disjuncts. Each disjunct is exercised in turn so the branch is covered
//     for every reason it can fire:
//       * ProvisioningProfile length != 48,
//       * SigningIdentity == "",
//       * ReleaseChannel != "production".
//   - :492-494 — the policy-checks incompleteness check, an OR of two
//     disjuncts. Each disjunct is exercised in turn:
//       * DevicePolicyValidated == false,
//       * RevocationPathVerified == false.
//
// verifyDeviceProvisioningSucceedsForMatchingEvidence grounds the happy path:
// a single target with a fully-matching evidence returns true with no
// findings, so the four rejection tests above are meaningful contrasts (each
// flips exactly one field from the matching baseline).
//
// validProvisioningPair is referenced by five tests (the four rejection tests
// and the success lock), so there is no staticcheck U1000 surface. No
// context.Context (no SA1012 surface), no goroutines, no cryptography, no real
// network or filesystem.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
)

// validProvisioningPair returns a single packaging target and a matching
// DeviceProvisioningEvidence: the same name and platform, every required
// entitlement present, a 48-byte provisioning profile, a non-empty signing
// identity, the "production" release channel, and both policy checks
// verified. verifyDeviceProvisioning returns true on this pair. Each rejection
// test mutates exactly one field of the evidence to trip exactly one check.
func validProvisioningPair() (platform.PackagingTarget, DeviceProvisioningEvidence) {
	target := platform.PackagingTarget{
		Name:                 "aurora-core-linux-amd64",
		Kind:                 platform.KindLinux,
		RequiredEntitlements: []string{"ent-a", "ent-b"},
	}
	evidence := DeviceProvisioningEvidence{
		TargetName:             target.Name,
		Platform:               target.Kind,
		Entitlements:           []string{"ent-a", "ent-b"},
		ProvisioningProfile:    make([]byte, 48),
		SigningIdentity:        "aurora-release-signing",
		ReleaseChannel:         "production",
		DevicePolicyValidated:  true,
		RevocationPathVerified: true,
	}
	return target, evidence
}

// runProvisioning builds the target/evidence slices from the pair, runs the
// gate, and reports the result and the joined findings for substring checks.
func runProvisioning(target platform.PackagingTarget, evidence DeviceProvisioningEvidence) (bool, string) {
	report := &ReadinessReport{}
	ok := verifyDeviceProvisioning([]platform.PackagingTarget{target}, []DeviceProvisioningEvidence{evidence}, report)
	return ok, strings.Join(report.Findings, "\n")
}

func TestVerifyDeviceProvisioningRejectsPlatformMismatch(t *testing.T) {
	// 478-481: the evidence targets the right target name but a different
	// platform. Every other field stays valid so only the platform check fires.
	target, evidence := validProvisioningPair()
	evidence.Platform = platform.KindOpenWrt
	ok, findings := runProvisioning(target, evidence)
	if ok {
		t.Fatal("verifyDeviceProvisioning(platform mismatch) = true, want false")
	}
	if !strings.Contains(findings, "device provisioning platform mismatch") {
		t.Fatalf("findings = %q, want substring \"device provisioning platform mismatch\"", findings)
	}
}

func TestVerifyDeviceProvisioningRejectsMissingEntitlement(t *testing.T) {
	// 482-486: the target requires "ent-b" but the evidence omits it, so
	// hasString(evidence.Entitlements, "ent-b") is false.
	target, evidence := validProvisioningPair()
	evidence.Entitlements = []string{"ent-a"}
	ok, findings := runProvisioning(target, evidence)
	if ok {
		t.Fatal("verifyDeviceProvisioning(missing entitlement) = true, want false")
	}
	if !strings.Contains(findings, "device provisioning entitlement missing") {
		t.Fatalf("findings = %q, want substring \"device provisioning entitlement missing\"", findings)
	}
}

func TestVerifyDeviceProvisioningRejectsIncompleteIdentityOrProfile(t *testing.T) {
	// 488-490: the identity/profile check is an OR of three disjuncts. Each
	// sub-case flips exactly one disjunct from the valid baseline so the branch
	// is covered for every reason it can fire.
	cases := []struct {
		name    string
		mutate  func(e *DeviceProvisioningEvidence)
		wantSub string
	}{
		{
			name:    "provisioning profile wrong length",
			mutate:  func(e *DeviceProvisioningEvidence) { e.ProvisioningProfile = []byte{0x01, 0x02, 0x03} },
			wantSub: "device provisioning identity/profile incomplete",
		},
		{
			name:    "empty signing identity",
			mutate:  func(e *DeviceProvisioningEvidence) { e.SigningIdentity = "" },
			wantSub: "device provisioning identity/profile incomplete",
		},
		{
			name:    "non-production release channel",
			mutate:  func(e *DeviceProvisioningEvidence) { e.ReleaseChannel = "staging" },
			wantSub: "device provisioning identity/profile incomplete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, evidence := validProvisioningPair()
			tc.mutate(&evidence)
			ok, findings := runProvisioning(target, evidence)
			if ok {
				t.Fatalf("%s: verifyDeviceProvisioning = true, want false", tc.name)
			}
			if !strings.Contains(findings, tc.wantSub) {
				t.Fatalf("%s: findings = %q, want substring %q", tc.name, findings, tc.wantSub)
			}
		})
	}
}

func TestVerifyDeviceProvisioningRejectsIncompletePolicyChecks(t *testing.T) {
	// 492-494: the policy-checks gate is an OR of two disjuncts. Each sub-case
	// flips exactly one disjunct from the valid baseline.
	cases := []struct {
		name    string
		mutate  func(e *DeviceProvisioningEvidence)
		wantSub string
	}{
		{
			name:    "device policy not validated",
			mutate:  func(e *DeviceProvisioningEvidence) { e.DevicePolicyValidated = false },
			wantSub: "device provisioning policy checks incomplete",
		},
		{
			name:    "revocation path not verified",
			mutate:  func(e *DeviceProvisioningEvidence) { e.RevocationPathVerified = false },
			wantSub: "device provisioning policy checks incomplete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, evidence := validProvisioningPair()
			tc.mutate(&evidence)
			ok, findings := runProvisioning(target, evidence)
			if ok {
				t.Fatalf("%s: verifyDeviceProvisioning = true, want false", tc.name)
			}
			if !strings.Contains(findings, tc.wantSub) {
				t.Fatalf("%s: findings = %q, want substring %q", tc.name, findings, tc.wantSub)
			}
		})
	}
}

func TestVerifyDeviceProvisioningSucceedsForMatchingEvidence(t *testing.T) {
	// Happy-path lock: a single target with a fully-matching evidence returns
	// true with no findings, so the four rejection tests above are meaningful
	// contrasts (each flips exactly one field from this baseline).
	target, evidence := validProvisioningPair()
	ok, findings := runProvisioning(target, evidence)
	if !ok {
		t.Fatalf("verifyDeviceProvisioning(matching) = false, want true (findings: %q)", findings)
	}
	if findings != "" {
		t.Fatalf("verifyDeviceProvisioning(matching) findings = %q, want none", findings)
	}
}
