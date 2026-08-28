package evaluation

import (
	"math"
	"testing"
)

func TestVerifyExternalEvaluationEvidenceAcceptsCompleteBundle(t *testing.T) {
	report, err := VerifyExternalEvaluationEvidence(ExternalEvaluationHarnessBundle())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("external evaluation evidence failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"classifier":          report.ClassifierEvidence,
		"active_probe":        report.ActiveProbeEvidence,
		"interop":             report.InteroperabilityEvidence,
		"security_reviews":    report.SecurityReviewEvidence,
		"release_gates":       report.ReleaseGateEvidence,
		"deployment_security": report.DeploymentSecurityAssessmentEvidence,
	} {
		if !passed {
			t.Fatalf("%s evidence was not covered: %+v", name, report)
		}
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsNonIndependentClassifier(t *testing.T) {
	bundle := ExternalEvaluationHarnessBundle()
	bundle.ClassifierReports[0].IndependentLab = false

	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("non-independent classifier evidence passed: %+v", report)
	}
	if !evaluationReportHasFinding(report, "classifier report is not independent") {
		t.Fatalf("report missing classifier independence finding: %+v", report)
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsWeakClassifierComparison(t *testing.T) {
	bundle := ExternalEvaluationHarnessBundle()
	bundle.ClassifierReports[0].SameCoverTemplate = false
	bundle.ClassifierReports[0].ClassifierAdvantage = bundle.ClassifierReports[0].AllowedAdvantage + 0.01

	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("weak classifier evidence passed: %+v", report)
	}
	for _, want := range []string{
		"classifier report does not compare against the same cover template",
		"classifier advantage exceeds deployment threshold",
	} {
		if !evaluationReportHasFinding(report, want) {
			t.Fatalf("report missing %q: %+v", want, report)
		}
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsDistinguishableActiveProbe(t *testing.T) {
	bundle := ExternalEvaluationHarnessBundle()
	bundle.ActiveProbeReports[0].DistinguishableFailures = 1

	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("distinguishable active-probe evidence passed: %+v", report)
	}
	if !evaluationReportHasFinding(report, "active-probe report found distinguishable failures") {
		t.Fatalf("report missing active-probe finding: %+v", report)
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsMissingProductionReleaseGate(t *testing.T) {
	bundle := ExternalEvaluationHarnessBundle()
	bundle.ReleaseGates.SignedUpdatePipeline = false

	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("missing signed update gate passed: %+v", report)
	}
	if !evaluationReportHasFinding(report, "signed update pipeline evidence is missing") {
		t.Fatalf("report missing release gate finding: %+v", report)
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsIncompleteDeploymentSecurityAssessment(t *testing.T) {
	bundle := ExternalEvaluationHarnessBundle()
	bundle.DeploymentSecurityAssessment.RealDeployment = false
	bundle.DeploymentSecurityAssessment.HighOpen = 1
	bundle.DeploymentSecurityAssessment.CoverOriginScope = false

	report, err := VerifyExternalEvaluationEvidence(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("incomplete deployment security assessment passed: %+v", report)
	}
	for _, want := range []string{
		"deployment security assessment must cover a real deployment",
		"deployment security assessment has open high-severity findings",
		"deployment security assessment missing cover-origin scope",
	} {
		if !evaluationReportHasFinding(report, want) {
			t.Fatalf("report missing %q: %+v", want, report)
		}
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsNonFiniteClassifierAdvantage(t *testing.T) {
	for _, advantage := range []float64{math.NaN(), math.Inf(-1), math.Inf(1)} {
		bundle := ExternalEvaluationHarnessBundle()
		bundle.ClassifierReports[0].ClassifierAdvantage = advantage

		report, err := VerifyExternalEvaluationEvidence(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if report.ClassifierEvidence || report.Passed {
			t.Fatalf("non-finite classifier advantage %v passed: %+v", advantage, report)
		}
	}
}

func TestVerifyExternalEvaluationEvidenceRejectsNonFiniteAllowedAdvantage(t *testing.T) {
	for _, allowed := range []float64{math.NaN(), math.Inf(1)} {
		bundle := ExternalEvaluationHarnessBundle()
		bundle.ClassifierReports[0].AllowedAdvantage = allowed
		bundle.ClassifierReports[0].ClassifierAdvantage = 0.5

		report, err := VerifyExternalEvaluationEvidence(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if report.ClassifierEvidence || report.Passed {
			t.Fatalf("allowed advantage %v let advantage 0.5 through: %+v", allowed, report)
		}
		if !evaluationReportHasFinding(report, "classifier advantage exceeds deployment threshold") {
			t.Fatalf("report missing threshold finding for allowed %v: %+v", allowed, report)
		}
	}
}

func evaluationReportHasFinding(report EvidenceReport, want string) bool {
	for _, finding := range report.Findings {
		if finding == want {
			return true
		}
	}
	return false
}
