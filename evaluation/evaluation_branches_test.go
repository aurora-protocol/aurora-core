package evaluation

import (
	"strings"
	"testing"
)

// bundleMutation applies a single defect to an otherwise-complete harness
// bundle so the verifier under test fails in exactly one way.
type bundleMutation func(*EvidenceBundle)

// rejectBundleCase runs the verifier against a harness bundle with one defect
// applied and asserts the run fails and records the expected finding. It is
// the shared body of the per-verifier rejection table tests.
func rejectBundleCase(t *testing.T, mutate bundleMutation, wantFinding string) {
	t.Helper()
	bundle := ExternalEvaluationHarnessBundle()
	mutate(&bundle)
	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatalf("bundle unexpectedly passed: %+v", report)
	}
	if !evaluationReportHasFinding(report, wantFinding) {
		t.Fatalf("report missing %q: %+v", wantFinding, report)
	}
}

// TestVerifyRejectsInvalidBundleMetadata covers the two pre-verification error
// guards in VerifyExternalEvaluationEvidence (empty bundle id, wrong vector
// hash length) that return an error before computing a report.
func TestVerifyRejectsInvalidBundleMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"empty bundle id", func(b *EvidenceBundle) { b.BundleID = "" }, "evaluation: bundle id is empty"},
		{"wrong vector hash length", func(b *EvidenceBundle) { b.VectorPackageHash = repeatedByte(0x40, 47) }, "evaluation: vector package hash must be 48 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := ExternalEvaluationHarnessBundle()
			tc.mutate(&bundle)
			_, err := VerifyExternalEvaluationEvidence(bundle)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: err = %q, want substring %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestVerifyInteroperabilityRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"fewer than two implementations", func(b *EvidenceBundle) { b.Interoperability.IndependentImplementations = 1 }, "fewer than two independent implementations passed vectors"},
		{"missing fast-1", func(b *EvidenceBundle) { b.Interoperability.Fast1Interop = false }, "fast-1 interoperability evidence is missing"},
		{"missing split-2", func(b *EvidenceBundle) { b.Interoperability.Split2Interop = false }, "split-2 interoperability evidence is missing"},
		{"missing real crypto outputs", func(b *EvidenceBundle) { b.Interoperability.RealCryptoOutputs = false }, "real cryptographic output interoperability is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectBundleCase(t, tc.mutate, tc.want) })
	}
}

func TestVerifyClassifierRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"missing report", func(b *EvidenceBundle) { b.ClassifierReports = nil }, "classifier report is missing"},
		{"missing report id", func(b *EvidenceBundle) { b.ClassifierReports[0].ReportID = "" }, "classifier report id is missing"},
		{"no ordinary samples", func(b *EvidenceBundle) { b.ClassifierReports[0].OrdinarySamples = 0 }, "classifier report lacks ordinary or candidate samples"},
		{"no candidate samples", func(b *EvidenceBundle) { b.ClassifierReports[0].CandidateSamples = 0 }, "classifier report lacks ordinary or candidate samples"},
		{"forbidden markers", func(b *EvidenceBundle) { b.ClassifierReports[0].ForbiddenMarkers = 1 }, "classifier report found distinguishers or forbidden markers"},
		{"distinguishers", func(b *EvidenceBundle) { b.ClassifierReports[0].Distinguishers = 1 }, "classifier report found distinguishers or forbidden markers"},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectBundleCase(t, tc.mutate, tc.want) })
	}
}

// TestClassifierAdvantageDefaultsToThresholdWhenAllowedZero covers the
// AllowedAdvantage<=0 fallback that substitutes the 0.02 deployment threshold.
// An advantage below the defaulted threshold must not be flagged; one above it
// must be.
func TestClassifierAdvantageDefaultsToThresholdWhenAllowedZero(t *testing.T) {
	// Below the defaulted threshold: not flagged, classifier evidence passes.
	bundle := ExternalEvaluationHarnessBundle()
	bundle.ClassifierReports[0].AllowedAdvantage = 0
	bundle.ClassifierReports[0].ClassifierAdvantage = 0.01
	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if evaluationReportHasFinding(report, "classifier advantage exceeds deployment threshold") {
		t.Fatalf("advantage 0.01 flagged under default 0.02 threshold: %+v", report)
	}
	if !report.ClassifierEvidence {
		t.Fatalf("classifier evidence unexpectedly failed: %+v", report)
	}

	// Above the defaulted threshold: flagged.
	bundle.ClassifierReports[0].ClassifierAdvantage = 0.03
	report, err = VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !evaluationReportHasFinding(report, "classifier advantage exceeds deployment threshold") {
		t.Fatalf("advantage 0.03 not flagged under default 0.02 threshold: %+v", report)
	}
}

func TestVerifyActiveProbeRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"missing report", func(b *EvidenceBundle) { b.ActiveProbeReports = nil }, "active-probe report is missing"},
		{"missing report id", func(b *EvidenceBundle) { b.ActiveProbeReports[0].ReportID = "" }, "active-probe report id is missing"},
		{"not independent", func(b *EvidenceBundle) { b.ActiveProbeReports[0].IndependentLab = false }, "active-probe report is not independent"},
		{"incomplete probe coverage", func(b *EvidenceBundle) { b.ActiveProbeReports[0].ProbeCases = 13 }, "active-probe report has incomplete probe coverage"},
		{"no ordinary origin control", func(b *EvidenceBundle) { b.ActiveProbeReports[0].OrdinaryOriginControl = false }, "active-probe report lacks ordinary-origin control"},
		{"forbidden public markers", func(b *EvidenceBundle) { b.ActiveProbeReports[0].ForbiddenPublicMarkers = 1 }, "active-probe report found forbidden public markers"},
		{"not cover neutral", func(b *EvidenceBundle) { b.ActiveProbeReports[0].CoverNeutralFailureBodies = false }, "active-probe failures were not cover-neutral"},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectBundleCase(t, tc.mutate, tc.want) })
	}
}

func TestVerifySecurityReviewRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"missing review id", func(b *EvidenceBundle) { b.SecurityReviews[0].ReviewID = "" }, "security review id is missing"},
		{"not independent", func(b *EvidenceBundle) { b.SecurityReviews[0].Independent = false }, "security review is not independent"},
		{"incomplete", func(b *EvidenceBundle) { b.SecurityReviews[0].Complete = false }, "security review is incomplete"},
		{"open high findings", func(b *EvidenceBundle) { b.SecurityReviews[0].HighOpen = 1 }, "security review has open high-severity findings"},
		{"open critical findings", func(b *EvidenceBundle) { b.SecurityReviews[0].CriticalOpen = 1 }, "security review has open high-severity findings"},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectBundleCase(t, tc.mutate, tc.want) })
	}

	// A missing required area (cryptography) is flagged even when the other two
	// reviews are otherwise valid; an unknown area is silently ignored (the
	// review still counts toward no required slot).
	t.Run("missing required cryptography review", func(t *testing.T) {
		bundle := ExternalEvaluationHarnessBundle()
		bundle.SecurityReviews[0].Area = "other" // was "cryptography"
		report, err := VerifyExternalEvaluationEvidence(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if report.Passed {
			t.Fatalf("unexpectedly passed: %+v", report)
		}
		if !evaluationReportHasFinding(report, "required security review missing: cryptography") {
			t.Fatalf("missing required-area finding: %+v", report)
		}
		if report.SecurityReviewEvidence {
			t.Fatalf("security review evidence unexpectedly passed: %+v", report)
		}
	})
}

func TestVerifyReleaseGateRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"no reproducible builds", func(b *EvidenceBundle) { b.ReleaseGates.ReproducibleBuilds = false }, "reproducible build evidence is missing"},
		{"no incident response plan", func(b *EvidenceBundle) { b.ReleaseGates.IncidentResponsePlan = false }, "incident-response plan evidence is missing"},
		{"no operational abuse review", func(b *EvidenceBundle) { b.ReleaseGates.OperationalAbuseReview = false }, "operational abuse review gate is missing"},
		{"no platform security review", func(b *EvidenceBundle) { b.ReleaseGates.PlatformSecurityReview = false }, "platform security review gate is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectBundleCase(t, tc.mutate, tc.want) })
	}
}

func TestVerifyDeploymentSecurityRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate bundleMutation
		want   string
	}{
		{"missing assessment id", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.AssessmentID = "" }, "deployment security assessment id is missing"},
		{"missing deployment id", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.DeploymentID = "" }, "deployment security assessment deployment id is missing"},
		{"not independent assessor", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.IndependentAssessor = false }, "deployment security assessment is not independent"},
		{"missing issuer scope", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.IssuerScope = false }, "deployment security assessment missing issuer scope"},
		{"missing relay scope", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.RelayScope = false }, "deployment security assessment missing relay scope"},
		{"missing directory scope", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.DirectoryScope = false }, "deployment security assessment missing directory scope"},
		{"missing client update scope", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.ClientUpdateScope = false }, "deployment security assessment missing client update scope"},
		{"missing outage drill", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.VerifierOutageDrill = false }, "deployment security assessment missing outage or replay drills"},
		{"missing failover drill", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.CoverOriginFailoverDrill = false }, "deployment security assessment missing outage or replay drills"},
		{"missing replay drill", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.ReplayAbuseDrill = false }, "deployment security assessment missing outage or replay drills"},
		{"telemetry not redacted", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.OperationalTelemetryRedacted = false }, "deployment security assessment missing telemetry redaction review"},
		{"no incident response link", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.IncidentResponseLinked = false }, "deployment security assessment missing incident-response linkage"},
		{"open critical findings", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.CriticalOpen = 1 }, "deployment security assessment has open critical findings"},
		{"missing completion timestamp", func(b *EvidenceBundle) { b.DeploymentSecurityAssessment.CompletedUnix = 0 }, "deployment security assessment completion timestamp is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) { rejectBundleCase(t, tc.mutate, tc.want) })
	}
}
