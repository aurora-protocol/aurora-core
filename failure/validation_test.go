package failure

import (
	"strings"
	"testing"
)

// TestRunActiveProbeHarnessRejectsEmptyCases covers the len(cases)==0 input
// guard that the existing tests (which always pass ActiveProbeCases()) skip.
func TestRunActiveProbeHarnessRejectsEmptyCases(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cases []ProbeCase
	}{
		{"nil", nil},
		{"empty", []ProbeCase{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RunActiveProbeHarness(tc.cases)
			if err == nil {
				t.Fatalf("RunActiveProbeHarness(%s) unexpectedly succeeded", tc.name)
			}
			if !strings.Contains(err.Error(), "no active-probe cases") {
				t.Fatalf("RunActiveProbeHarness(%s) err = %q, want substring %q", tc.name, err, "no active-probe cases")
			}
		})
	}
}

// TestVerifyProbeNeutralityRejectsEmptyCases covers the propagation path where
// VerifyProbeNeutrality surfaces RunActiveProbeHarness's empty-cases error
// instead of passing.
func TestVerifyProbeNeutralityRejectsEmptyCases(t *testing.T) {
	if err := VerifyProbeNeutrality(nil); err == nil {
		t.Fatal("VerifyProbeNeutrality(nil) unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), "no active-probe cases") {
		t.Fatalf("VerifyProbeNeutrality(nil) err = %q, want substring %q", err, "no active-probe cases")
	}
}