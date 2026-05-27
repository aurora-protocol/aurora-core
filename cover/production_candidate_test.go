package cover

import "testing"

func TestEvaluateProductionCandidateClearsThresholdForIndistinguishableBaseline(t *testing.T) {
	samples, err := DefaultClassifierBaseline()
	if err != nil {
		t.Fatalf("DefaultClassifierBaseline failed: %v", err)
	}
	report, err := EvaluateClassifierBaseline(samples)
	if err != nil {
		t.Fatalf("EvaluateClassifierBaseline failed: %v", err)
	}
	decision := EvaluateProductionCandidate(report, 0.02)
	if !decision.ProductionCandidate {
		t.Fatalf("indistinguishable baseline should be production-candidate: %+v", decision)
	}
	if decision.ClassifierAdvantage != 0 {
		t.Fatalf("expected zero advantage, got %.4f", decision.ClassifierAdvantage)
	}
	if decision.ComparisonCount == 0 {
		t.Fatalf("expected non-zero comparisons")
	}
}

func TestEvaluateProductionCandidateRejectsSeparableSurface(t *testing.T) {
	samples, err := DefaultClassifierBaseline()
	if err != nil {
		t.Fatalf("DefaultClassifierBaseline failed: %v", err)
	}
	// Make one candidate surface distinguishable from its ordinary origin.
	samples[0].Candidate.TLSFingerprintFamily = "aurora-distinct-tls-family"
	report, err := EvaluateClassifierBaseline(samples)
	if err != nil {
		t.Fatalf("EvaluateClassifierBaseline failed: %v", err)
	}
	decision := EvaluateProductionCandidate(report, 0.0)
	if decision.ProductionCandidate {
		t.Fatalf("separable surface must not be production-candidate: %+v", decision)
	}
	if decision.DistinguisherCount == 0 {
		t.Fatalf("expected at least one distinguisher")
	}
}
