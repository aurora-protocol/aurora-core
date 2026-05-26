package admission

import "testing"

func TestProductionProofHarnessVerifiesAndRejectsProductionProofs(t *testing.T) {
	report, err := RunProductionProofHarness(100)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("production proof harness failed: %+v", report)
	}
	if !report.BlindRSA2048Verified ||
		!report.BlindRSAAuthenticatorTamperRejected ||
		!report.BlindRSAOriginPolicyRejected ||
		!report.VOPRFProofOnlyRejected ||
		!report.LabStaticTokenRejected {
		t.Fatalf("production proof harness did not cover all required checks: %+v", report)
	}
}
