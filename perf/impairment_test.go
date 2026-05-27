package perf

import "testing"

func TestRunImpairmentHarnessPasses(t *testing.T) {
	report, err := RunImpairmentHarness()
	if err != nil {
		t.Fatalf("RunImpairmentHarness failed: %v", err)
	}
	if !report.Passed {
		t.Fatalf("impairment report failed: %+v", report.Findings)
	}
	if !report.InteractivePrioritized ||
		!report.UDPStalePolicy ||
		!report.DowngradeNoReconnectStorm ||
		!report.TupleCooldownActivates ||
		!report.PaddingReducesUnderCongestion {
		t.Fatalf("missing acceptance coverage: %+v", report)
	}
	if len(report.Scenarios) < 12 {
		t.Fatalf("expected the full impairment scenario matrix, got %d scenarios", len(report.Scenarios))
	}
	for _, scenario := range report.Scenarios {
		if !scenario.Passed {
			t.Fatalf("scenario %s failed: %s", scenario.Name, scenario.Detail)
		}
	}
}
