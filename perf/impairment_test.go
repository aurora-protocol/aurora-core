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

func TestProtectThroughputWithinBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		opsPerSec float64
		floor     float64
		want      bool
	}{
		{"well above floor", 900_000, 10_000, true},
		{"at floor", 10_000, 10_000, true},
		{"just below floor", 9_999, 10_000, false},
		{"far below floor", 500, 10_000, false},
		{"zero measurement", 0, 10_000, false},
	} {
		if got := protectThroughputWithinBudget(tc.opsPerSec, tc.floor); got != tc.want {
			t.Fatalf("%s: protectThroughputWithinBudget(%v, %v) = %t, want %t", tc.name, tc.opsPerSec, tc.floor, got, tc.want)
		}
	}
}

func TestPacketProtectThroughputScenarioPasses(t *testing.T) {
	report, err := RunImpairmentHarness()
	if err != nil {
		t.Fatalf("RunImpairmentHarness failed: %v", err)
	}
	for _, scenario := range report.Scenarios {
		if scenario.Name == "packet-protect-throughput" {
			if !scenario.Passed {
				t.Fatalf("packet-protect-throughput scenario failed: %s", scenario.Detail)
			}
			return
		}
	}
	t.Fatal("packet-protect-throughput scenario missing from report")
}
