package ops

// Adversarial white-box coverage for the three count-0 baseline-control
// addFinding guards of VerifyIssuerOperationsProfile
// (ops/issuer_operations.go:60/:68/:73). This rotates the pillar to the ops
// package: VerifyIssuerOperationsProfile is a PURE report builder over a
// value-type IssuerOperationsProfile (no crypto of its own, no network, no
// goroutine) that records one finding per failed baseline control and then
// ANDs the per-control booleans into report.Passed.
//
// VerifyIssuerOperationsProfile evaluates three independent baseline controls:
//   - :60  VerifyIssuerMetadataSignature(Metadata, AuthorityKeys, NowUnix) err
//        -> addFinding("issuer metadata verification failed: <err>")
//        -> report.MetadataVerified stays false
//   - :68  !profile.ReplayStoreAtomicInsertIfAbsent
//        -> addFinding("replay store does not promise atomic insert-if-absent")
//        -> report.AtomicReplayStore = false
//   - :73  !profile.OperationalLogsRedactSensitiveMaterial
//        -> addFinding("operational logs do not redact token/capsule/hint material")
//        -> report.SensitiveLogsRedacted = false
//
// The existing ops tests drive VerifyIssuerOperationsProfile only via the
// all-valid harness profile (TestVerifyIssuerOperationsProfileAcceptsProduction
// Controls, ReplayStoreAtomicInsertIfAbsent=true, Redacted=true, valid signed
// Metadata) or via profiles that keep these three booleans true and fail a
// sub-policy instead (RejectsUnsafeHintProvisioning / RequiresBlindRSA... /
// RejectsAdvertisedVOPRFWithoutVerifierService). So :60/:68/:73 stayed COUNT 0
// in the baseline (confirmed: each block count=0 on a clean tree; ops 87.4%).
//
// Coverage targets (baseline measured on a clean tree; bodies COUNT 0):
//   - issuer_operations.go:60.124,62.3 0 — metadata verification failed
//   - issuer_operations.go:68.31,70.3  0 — replay store not atomic
//   - issuer_operations.go:73.35,75.3  0 — logs not redacted
//
// Reachability: a zero-value IssuerOperationsProfile{} is fully nil-safe
// through VerifyIssuerOperationsProfile:
//   - VerifyIssuerMetadataMetadata(Metadata{}, nil, 0) returns the
//     ValidateStructural error (empty IssuerID etc.) at trust/issuer.go:41 ->
//     no panic, :60 fires.
//   - verifyHintProvisioning -> activeRelayBucketScopes(Metadata{}, 0) iterates
//     the nil RelayBucketScopes slice -> empty -> addFinding("issuer metadata
//     has no active relay bucket scope") -> returns false (an incidental finding,
//     NOT one of the three targets; never matches the negative-assertion
//     substrings below).
//   - verifyVerifierOperations -> metadataHasUsableProof(Metadata{}, ...) = false
//     (nil SupportedProofTypes) and len(Metadata.VerifierServices)==0 -> returns
//     true with no finding.
//   - verifyPublicRelayProofPolicy -> !profile.PublicRelay (zero) -> returns true.
// So a zero-value profile yields exactly the :60 finding plus the incidental
// :66 finding, and the :68/:73 guards fire iff their booleans are false.
//
// The three controls are INDEPENDENT if-statements (no short-circuit between
// them), and :60 cannot be suppressed without a crypto-signed valid Metadata,
// so the table toggles ONE of the two cheap booleans per subtest to ISOLATE one
// target's addFinding and asserts the OTHER target's substring is ABSENT (proof
// that each guard is driven by exactly its own boolean, not a side effect).
// Error substring asserted present/absent per subtest (self-validating); the
// per-line coverage flip (0->1 per guard) is the rigorous proof. In-package
// (package ops) matches the existing issuer_operations test family. Distinct
// filename + test name, a local reportContains helper (no collision with
// existing ops tests), no shared helpers. One TestXxx with three t.Run subtests;
// imports strings/testing (all used) -> no U1000 surface.

import (
	"strings"
	"testing"
)

// reportContains reports whether any finding in rep contains sub.
func reportContains(rep IssuerOperationsReport, sub string) bool {
	for _, f := range rep.Findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestVerifyIssuerOperationsProfileReportsMissingBaselineControls(t *testing.T) {
	const (
		metaFail = "issuer metadata verification failed"
		replay   = "replay store does not promise atomic insert-if-absent"
		redact   = "operational logs do not redact token/capsule/hint material"
	)

	cases := []struct {
		name    string
		profile IssuerOperationsProfile
		// wantPresent is the substring of the ONE guard this subtest isolates.
		wantPresent string
		// wantAbsent is the substring of the OTHER toggled guard, proving it
		// does not fire when its boolean is true.
		wantAbsent string
		// wantBool is the report boolean that must be false for this control.
		wantBool func(IssuerOperationsReport) bool
	}{
		{
			// :60 — zero-value Metadata fails ValidateStructural, so
			// VerifyIssuerMetadataSignature returns an err and addFinding fires.
			// Both cheap booleans are true, so :68/:73 must NOT fire.
			name: "metadata verification fails",
			profile: IssuerOperationsProfile{
				ReplayStoreAtomicInsertIfAbsent:        true,
				OperationalLogsRedactSensitiveMaterial: true,
			},
			wantPresent: metaFail,
			wantAbsent:  replay,
			wantBool:    func(r IssuerOperationsReport) bool { return r.MetadataVerified },
		},
		{
			// :68 — ReplayStoreAtomicInsertIfAbsent=false. Logs redacted (true)
			// so :73 must NOT fire.
			name: "replay store not atomic",
			profile: IssuerOperationsProfile{
				OperationalLogsRedactSensitiveMaterial: true,
			},
			wantPresent: replay,
			wantAbsent:  redact,
			wantBool:    func(r IssuerOperationsReport) bool { return r.AtomicReplayStore },
		},
		{
			// :73 — OperationalLogsRedactSensitiveMaterial=false. Atomic replay
			// (true) so :68 must NOT fire.
			name: "operational logs not redacted",
			profile: IssuerOperationsProfile{
				ReplayStoreAtomicInsertIfAbsent: true,
			},
			wantPresent: redact,
			wantAbsent:  replay,
			wantBool:    func(r IssuerOperationsReport) bool { return r.SensitiveLogsRedacted },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report, err := VerifyIssuerOperationsProfile(c.profile)
			if err != nil {
				t.Fatalf("VerifyIssuerOperationsProfile(%s) err = %v, want nil (the report builder never returns an error)", c.name, err)
			}
			if !reportContains(report, c.wantPresent) {
				t.Fatalf("VerifyIssuerOperationsProfile(%s): want a finding containing %q, got findings=%v", c.name, c.wantPresent, report.Findings)
			}
			if reportContains(report, c.wantAbsent) {
				t.Fatalf("VerifyIssuerOperationsProfile(%s): want NO finding containing %q (its boolean is true), got findings=%v", c.name, c.wantAbsent, report.Findings)
			}
			if c.wantBool(report) {
				t.Fatalf("VerifyIssuerOperationsProfile(%s): want the corresponding report boolean false, got report=%+v", c.name, report)
			}
			if report.Passed {
				t.Fatalf("VerifyIssuerOperationsProfile(%s): want Passed=false (metadata never verifies without a signed profile), got Passed=true", c.name)
			}
		})
	}
}
