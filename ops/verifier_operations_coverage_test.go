package ops

// Adversarial coverage for verifyVerifierOperations (issuer_operations.go:362,
// ~65% before) and verifyHintProvisioning (line 252, ~70% before), the two
// profile-level validation helpers the existing
// TestVerifyIssuerOperationsProfile* suite reaches only indirectly through
// the signed-metadata VerifyIssuerOperationsProfile path. Driving each helper
// directly with the existing issuerOperationsProfileFixture (a signed, valid
// base) and a single-field mutation isolates every rejection branch without
// re-running the metadata-signature verification (the helpers read profile
// fields directly and never check the signature).
//
// verifyVerifierOperations branches covered:
//   - VOPRF advertised without a usable verifier service (364-367): clear the
//     service's AllowedProofTypes so metadataHasUsableVerifierServiceForProof
//     returns false while metadataHasUsableProof stays true.
//   - empty VerifierServices early return (369-370): drop both the verifier
//     services and the VOPRF proof advertisement so the VOPRF-without-service
//     guard does not fire and the function returns passed=true.
//   - verifier outage does not fail closed (372-374).
//   - latency exceeds the configured budget (380-382) and exceeds the default
//     250 ms budget derived when MaxVerifierServiceRTTMillis==0 (376-378).
//   - verifier service request auth policy unavailable (384-388): empty the
//     ImplementedVerifierRequestAuthPolicyIDs map.
//
// verifyHintProvisioning branches covered:
//   - maxEpochSeconds==0 default (254-256): the production fixture sets
//     MaxHintEpochSeconds=86400, so the 24h default arm is only reachable here.
//   - no active relay bucket scope (258-260): bump NowUnix past the scope's
//     ValidUntilUnix so activeRelayBucketScopes returns empty.
//   - active scope lacks hint epoch provisioning (274-277): drop HintEpochs.
//   - matching provision fails controls (270-272): shorten the fixture's
//     matching HintEpoch verifier secret so verifyHintEpochProvisionControls
//     fails (attributed via the controls finding; matched stays true so no
//     lacks-provisioning finding fires).
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one finding so
// the failure is attributable to the perturbed field alone. No new helpers are
// introduced (reuses issuerOperationsProfileFixture and reportHasFinding), so
// there is no U1000 risk.

import (
	"bytes"
	"testing"
)

func TestVerifyVerifierOperationsRejectsEachInvalidCondition(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(profile *IssuerOperationsProfile)
		wantFinding string
	}{
		{
			name:        "voprf advertised without usable verifier service",
			mutate:      func(p *IssuerOperationsProfile) { p.Metadata.VerifierServices[0].AllowedProofTypes = nil },
			wantFinding: "VOPRF proof advertised without usable verifier service",
		},
		{
			name:        "verifier outage does not fail closed",
			mutate:      func(p *IssuerOperationsProfile) { p.VerifierOutageFailsClosed = false },
			wantFinding: "verifier service outages do not fail closed",
		},
		{
			name:        "latency exceeds configured budget",
			mutate:      func(p *IssuerOperationsProfile) { p.VerifierServiceRTTMillis = 300 },
			wantFinding: "verifier service latency exceeds configured budget",
		},
		{
			name:        "latency exceeds default budget",
			mutate:      func(p *IssuerOperationsProfile) { p.MaxVerifierServiceRTTMillis = 0; p.VerifierServiceRTTMillis = 300 },
			wantFinding: "verifier service latency exceeds configured budget",
		},
		{
			name:        "verifier service request auth policy unavailable",
			mutate:      func(p *IssuerOperationsProfile) { p.ImplementedVerifierRequestAuthPolicyIDs = map[uint64]bool{} },
			wantFinding: "verifier service request auth policy is unavailable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile, _ := issuerOperationsProfileFixture(t)
			tc.mutate(&profile)
			report := IssuerOperationsReport{}
			passed := verifyVerifierOperations(profile, &report)
			if passed {
				t.Fatalf("verifyVerifierOperations accepted %s", tc.name)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("%s findings = %v, want exactly 1 (%q)", tc.name, report.Findings, tc.wantFinding)
			}
			if !reportHasFinding(report, tc.wantFinding) {
				t.Fatalf("%s findings = %v, want %q", tc.name, report.Findings, tc.wantFinding)
			}
		})
	}
}

func TestVerifyVerifierOperationsAcceptsValid(t *testing.T) {
	profile, _ := issuerOperationsProfileFixture(t)
	report := IssuerOperationsReport{}
	if passed := verifyVerifierOperations(profile, &report); !passed {
		t.Fatalf("valid profile rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid profile produced findings: %v", report.Findings)
	}
}

func TestVerifyVerifierOperationsReturnsEarlyWithoutVerifierServices(t *testing.T) {
	// No verifier services AND no VOPRF proof advertised -> nothing to verify,
	// so the function returns passed=true via the early return at line 370
	// without firing the VOPRF-without-service guard (which requires a usable
	// VOPRF proof). Dropping SupportedProofTypes keeps that guard quiet.
	profile, _ := issuerOperationsProfileFixture(t)
	profile.Metadata.VerifierServices = nil
	profile.Metadata.SupportedProofTypes = nil
	report := IssuerOperationsReport{}
	if passed := verifyVerifierOperations(profile, &report); !passed {
		t.Fatalf("expected passed=true, findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %v", report.Findings)
	}
}

func TestVerifyHintProvisioningRejectsMissingScopeAndProvisioning(t *testing.T) {
	t.Run("no active relay bucket scope", func(t *testing.T) {
		profile, _ := issuerOperationsProfileFixture(t)
		profile.NowUnix = 2000 // past the scope's ValidUntilUnix(1000)
		report := IssuerOperationsReport{}
		passed := verifyHintProvisioning(profile, &report)
		if passed {
			t.Fatal("verifyHintProvisioning accepted a profile with no active scope")
		}
		if len(report.Findings) != 1 {
			t.Fatalf("findings = %v, want exactly 1", report.Findings)
		}
		if !reportHasFinding(report, "issuer metadata has no active relay bucket scope") {
			t.Fatalf("findings = %v", report.Findings)
		}
	})
	t.Run("active scope lacks hint epoch provisioning", func(t *testing.T) {
		profile, _ := issuerOperationsProfileFixture(t)
		profile.HintEpochs = nil
		report := IssuerOperationsReport{}
		passed := verifyHintProvisioning(profile, &report)
		if passed {
			t.Fatal("verifyHintProvisioning accepted an active scope without provisioning")
		}
		if len(report.Findings) != 1 {
			t.Fatalf("findings = %v, want exactly 1", report.Findings)
		}
		if !reportHasFinding(report, "active relay bucket lacks hint epoch provisioning") {
			t.Fatalf("findings = %v", report.Findings)
		}
	})
	t.Run("matching provision fails controls", func(t *testing.T) {
		// The fixture's HintEpochs[0] matches the active scope; break its
		// verifier secret so verifyHintEpochProvisionControls fails. matched
		// stays true, so the lacks-provisioning finding does not fire and the
		// only finding is the controls' verifier-secret finding.
		profile, _ := issuerOperationsProfileFixture(t)
		profile.HintEpochs[0].VerifierSecret = bytes.Repeat([]byte{0x86}, 31)
		report := IssuerOperationsReport{}
		passed := verifyHintProvisioning(profile, &report)
		if passed {
			t.Fatal("verifyHintProvisioning accepted a provision that fails controls")
		}
		if len(report.Findings) != 1 {
			t.Fatalf("findings = %v, want exactly 1", report.Findings)
		}
		if !reportHasFinding(report, "ops: hint epoch verifier secret must be 32 bytes") {
			t.Fatalf("findings = %v", report.Findings)
		}
	})
}

func TestVerifyHintProvisioningAcceptsValid(t *testing.T) {
	profile, _ := issuerOperationsProfileFixture(t)
	report := IssuerOperationsReport{}
	if passed := verifyHintProvisioning(profile, &report); !passed {
		t.Fatalf("valid profile rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid profile produced findings: %v", report.Findings)
	}
}

func TestVerifyHintProvisioningSkipsNonMatchingProvision(t *testing.T) {
	// Prepend a provision whose IssuerID and RelayBucketID do not match the
	// active scope so the inner loop's continue (line 267) executes. The
	// original matching provision still follows, so matched becomes true and
	// the report stays clean — isolating the skip branch from any finding.
	profile, _ := issuerOperationsProfileFixture(t)
	nonMatching := HintEpochProvision{
		IssuerID:                     bytes.Repeat([]byte{0x00}, 16), // != metadata.IssuerID
		RelayBucketID:                bytes.Repeat([]byte{0x09}, 16), // != scope.RelayBucketID
		VerifierSecret:               bytes.Repeat([]byte{0x33}, 32),
		ValidFromUnix:                100,
		ValidUntilUnix:               500,
		OperatorChannelAuthenticated: true,
		OperatorChannelEncrypted:     true,
		RotationAuditID:              "rotation-99",
	}
	profile.HintEpochs = append([]HintEpochProvision{nonMatching}, profile.HintEpochs...)
	report := IssuerOperationsReport{}
	if passed := verifyHintProvisioning(profile, &report); !passed {
		t.Fatalf("valid profile with a non-matching provision rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("non-matching provision produced findings: %v", report.Findings)
	}
}

func TestVerifyHintProvisioningDefaultsMaxEpochSecondsWhenZero(t *testing.T) {
	// MaxHintEpochSeconds==0 triggers the 24h default (line 254-256), a path
	// the production fixture (MaxHintEpochSeconds=86400) does not reach. The
	// provision's 100..500 window (delta 400) is within 24h, so it still passes.
	profile, _ := issuerOperationsProfileFixture(t)
	profile.MaxHintEpochSeconds = 0
	report := IssuerOperationsReport{}
	if passed := verifyHintProvisioning(profile, &report); !passed {
		t.Fatalf("valid profile (max=0) rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid profile (max=0) produced findings: %v", report.Findings)
	}
}
