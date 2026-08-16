package ops

// Adversarial coverage for the two pure hint-epoch validation helpers in
// issuer_operations.go that the existing TestVerifyIssuerOperationsProfile*
// suite (issuer_operations_test.go) reaches only indirectly through the
// signed-metadata VerifyIssuerOperationsProfile path:
//   - verifyHintEpochProvisionControls (line 282, ~50% before): the report
//     form, which accumulates findings (no early return) — every rejection
//     branch and the maxEpochSeconds==0 skip arm stay uncovered.
//   - validateHintEpochProvision (line 328, ~57.1% before): the error form,
//     which returns on the first failure — the later rejection branches
//     (revoked, operator auth/encrypt, rotation audit, user-specific table,
//     exceeds-max) are only reachable from a provision that passes all
//     earlier checks.
//
// Both helpers take a crafted HintEpochProvision plus nowUnix/maxEpochSeconds
// scalars — no signed metadata, TLS, or live crypto is required, so each
// rejection branch can be isolated by perturbing exactly one field of an
// otherwise-valid base provision. The two functions emit identical finding
// strings, so one shared case table drives both (the report form asserts the
// finding via reportHasFinding; the error form asserts err.Error() matches).
//
// The maxEpochSeconds==0 arm (verifyHintEpochProvisionControls line 300 and
// validateHintEpochProvision line 356) is unreachable via verifyHintProvisioning
// (which substitutes a non-zero default at line 254-256), so it is covered
// here by calling the helpers directly with maxEpochSeconds=0.
//
// Deferred to a follow-up (need a crafted IssuerOperationsProfile.Metadata
// with VerifierServices and usable-proof state):
//   - verifyVerifierOperations (line 362, ~65%)
//   - verifyHintProvisioning (line 252, ~70%)
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one finding
// (report form) / exactly one error (error form) so the failure is
// attributable to the perturbed field alone.

import (
	"bytes"
	"testing"
)

const (
	hintEpochNowDefault uint64 = 150
	hintEpochMaxDefault uint64 = 86400
	hintEpochValidFrom  uint64 = 100
	hintEpochValidUntil uint64 = 200
)

func TestVerifyHintEpochProvisionControlsRejectsEachInvalidField(t *testing.T) {
	cases := hintEpochRejectionCases()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provision := validHintEpochProvisionForCoverage()
			if tc.mutate != nil {
				tc.mutate(&provision)
			}
			report := IssuerOperationsReport{}
			passed := verifyHintEpochProvisionControls(provision, tc.nowUnix, tc.maxEpoch, &report)
			if passed {
				t.Fatalf("verifyHintEpochProvisionControls accepted %s", tc.name)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("%s findings = %v, want exactly 1 (%q)", tc.name, report.Findings, tc.wantFinding)
			}
			if !reportHasFinding(report, tc.wantFinding) {
				t.Fatalf("%s finding = %v, want %q", tc.name, report.Findings, tc.wantFinding)
			}
		})
	}
}

func TestVerifyHintEpochProvisionControlsAcceptsValid(t *testing.T) {
	t.Run("max epoch enforced", func(t *testing.T) {
		provision := validHintEpochProvisionForCoverage()
		report := IssuerOperationsReport{}
		if passed := verifyHintEpochProvisionControls(provision, hintEpochNowDefault, hintEpochMaxDefault, &report); !passed {
			t.Fatalf("valid provision rejected: findings=%v", report.Findings)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("valid provision produced findings: %v", report.Findings)
		}
	})
	t.Run("max epoch disabled", func(t *testing.T) {
		// maxEpochSeconds==0 skips the exceeds-max check (line 300 guard),
		// a path unreachable via verifyHintProvisioning (which defaults 0 ->
		// 24h). The provision interval is well within any bound, so this is
		// a happy path that also exercises the skip arm.
		provision := validHintEpochProvisionForCoverage()
		report := IssuerOperationsReport{}
		if passed := verifyHintEpochProvisionControls(provision, hintEpochNowDefault, 0, &report); !passed {
			t.Fatalf("valid provision (max disabled) rejected: findings=%v", report.Findings)
		}
		if len(report.Findings) != 0 {
			t.Fatalf("valid provision (max disabled) produced findings: %v", report.Findings)
		}
	})
}

func TestValidateHintEpochProvisionRejectsEachInvalidField(t *testing.T) {
	cases := hintEpochRejectionCases()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provision := validHintEpochProvisionForCoverage()
			if tc.mutate != nil {
				tc.mutate(&provision)
			}
			err := validateHintEpochProvision(provision, tc.nowUnix, tc.maxEpoch)
			if err == nil {
				t.Fatalf("validateHintEpochProvision accepted %s", tc.name)
			}
			if err.Error() != tc.wantFinding {
				t.Fatalf("%s err = %q, want %q", tc.name, err, tc.wantFinding)
			}
		})
	}
}

func TestValidateHintEpochProvisionAcceptsValid(t *testing.T) {
	t.Run("max epoch enforced", func(t *testing.T) {
		provision := validHintEpochProvisionForCoverage()
		if err := validateHintEpochProvision(provision, hintEpochNowDefault, hintEpochMaxDefault); err != nil {
			t.Fatalf("valid provision rejected: %v", err)
		}
	})
	t.Run("max epoch disabled", func(t *testing.T) {
		provision := validHintEpochProvisionForCoverage()
		if err := validateHintEpochProvision(provision, hintEpochNowDefault, 0); err != nil {
			t.Fatalf("valid provision (max disabled) rejected: %v", err)
		}
	})
}

// hintEpochRejectionCase describes a single-field perturbation of an
// otherwise-valid HintEpochProvision, plus the nowUnix/maxEpochSeconds scalars
// to pass to the helpers. wantFinding is the exact finding/error string both
// helpers emit for that branch.
type hintEpochRejectionCase struct {
	name        string
	mutate      func(p *HintEpochProvision) // nil = perturbation is in the scalars
	nowUnix     uint64
	maxEpoch    uint64
	wantFinding string
}

// hintEpochRejectionCases returns the shared table of single-field rejection
// cases for the two hint-epoch validation helpers. Each case perturbs exactly
// one aspect of a valid base provision so that exactly one finding/error
// fires, making the failure attributable to that branch alone.
func hintEpochRejectionCases() []hintEpochRejectionCase {
	return []hintEpochRejectionCase{
		{
			name:        "issuer and relay bucket ids wrong length",
			mutate:      func(p *HintEpochProvision) { p.IssuerID = bytes.Repeat([]byte{0x11}, 15) },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "ops: hint epoch issuer and relay bucket ids must be 16 bytes",
		},
		{
			name:        "verifier secret wrong length",
			mutate:      func(p *HintEpochProvision) { p.VerifierSecret = bytes.Repeat([]byte{0x33}, 31) },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "ops: hint epoch verifier secret must be 32 bytes",
		},
		{
			name:        "empty validity interval",
			mutate:      func(p *HintEpochProvision) { p.ValidUntilUnix = p.ValidFromUnix },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "ops: hint epoch validity interval is empty",
		},
		{
			name:        "now before validity interval",
			mutate:      nil,
			nowUnix:     50, // < ValidFromUnix(100)
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "ops: hint epoch outside validity interval",
		},
		{
			name:        "validity exceeds configured maximum",
			mutate:      nil,
			nowUnix:     hintEpochNowDefault, // in interval
			maxEpoch:    50,                  // delta(100) > 50
			wantFinding: "hint epoch validity exceeds configured maximum",
		},
		{
			name:        "revoked",
			mutate:      func(p *HintEpochProvision) { p.Revoked = true },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "ops: hint epoch is revoked",
		},
		{
			name:        "operator channel not authenticated",
			mutate:      func(p *HintEpochProvision) { p.OperatorChannelAuthenticated = false },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "hint epoch operator channel lacks mutual authentication",
		},
		{
			name:        "operator channel not encrypted",
			mutate:      func(p *HintEpochProvision) { p.OperatorChannelEncrypted = false },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "hint epoch operator channel lacks transport encryption",
		},
		{
			name:        "empty rotation audit id",
			mutate:      func(p *HintEpochProvision) { p.RotationAuditID = "" },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "hint epoch lacks audited rotation record",
		},
		{
			name:        "user specific hint table",
			mutate:      func(p *HintEpochProvision) { p.UserSpecificHintTable = true },
			nowUnix:     hintEpochNowDefault,
			maxEpoch:    hintEpochMaxDefault,
			wantFinding: "hint epoch uses user-specific hint table",
		},
	}
}

// validHintEpochProvisionForCoverage returns a HintEpochProvision that passes
// every verifyHintEpochProvisionControls / validateHintEpochProvision check at
// nowUnix=150 with maxEpochSeconds=86400: 16-byte ids, 32-byte verifier secret,
// a 100..200 validity window containing now=150, authenticated+encrypted
// operator channel, non-empty rotation audit, not revoked, no user-specific
// table. Each rejection subtest perturbs exactly one field so the rejection
// is attributable to that field alone.
func validHintEpochProvisionForCoverage() HintEpochProvision {
	return HintEpochProvision{
		IssuerID:                     bytes.Repeat([]byte{0x11}, 16),
		RelayBucketID:                bytes.Repeat([]byte{0x22}, 16),
		VerifierSecret:               bytes.Repeat([]byte{0x33}, 32),
		ValidFromUnix:                hintEpochValidFrom,
		ValidUntilUnix:               hintEpochValidUntil,
		OperatorChannelAuthenticated: true,
		OperatorChannelEncrypted:     true,
		RotationAuditID:              "audit-1",
		Revoked:                      false,
		UserSpecificHintTable:        false,
	}
}
