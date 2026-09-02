package perf

import (
	"strings"
	"testing"
	"time"
)

func TestCheckBudgets(t *testing.T) {
	report := LoadReport{
		Errors:            2,
		LatencyP50:        10 * time.Millisecond,
		LatencyP95:        50 * time.Millisecond,
		LatencyP99:        90 * time.Millisecond,
		RequestsPerSecond: 750,
	}
	tests := []struct {
		name    string
		budgets Budgets
		want    []string
	}{
		{name: "zero budgets assert nothing", budgets: Budgets{}},
		{
			name:    "p50 at limit",
			budgets: Budgets{MaxP50: 10 * time.Millisecond},
		},
		{
			name:    "p50 exceeded",
			budgets: Budgets{MaxP50: 10*time.Millisecond - time.Nanosecond},
			want:    []string{"latency p50 10ms exceeds budget 9.999999ms"},
		},
		{
			name:    "p95 at limit",
			budgets: Budgets{MaxP95: 50 * time.Millisecond},
		},
		{
			name:    "p95 exceeded",
			budgets: Budgets{MaxP95: 49 * time.Millisecond},
			want:    []string{"latency p95 50ms exceeds budget 49ms"},
		},
		{
			name:    "p99 at limit",
			budgets: Budgets{MaxP99: 90 * time.Millisecond},
		},
		{
			name:    "p99 exceeded",
			budgets: Budgets{MaxP99: 89 * time.Millisecond},
			want:    []string{"latency p99 90ms exceeds budget 89ms"},
		},
		{
			name:    "rps at limit",
			budgets: Budgets{MinRPS: 750},
		},
		{
			name:    "rps below budget",
			budgets: Budgets{MinRPS: 750.01},
			want:    []string{"requests per second 750.00 below budget 750.01"},
		},
		{
			name:    "errors at limit",
			budgets: Budgets{MaxErrors: 2},
		},
		{
			name:    "errors exceeded",
			budgets: Budgets{MaxErrors: 1},
			want:    []string{"errors 2 exceed budget 1"},
		},
		{
			name:    "unset budgets ignore bad measurements",
			budgets: Budgets{MaxP95: time.Second},
		},
		{
			name: "multiple violations all reported in order",
			budgets: Budgets{
				MaxP50:    time.Millisecond,
				MaxP95:    time.Millisecond,
				MaxP99:    time.Millisecond,
				MinRPS:    1000,
				MaxErrors: 1,
			},
			want: []string{
				"latency p50 10ms exceeds budget 1ms",
				"latency p95 50ms exceeds budget 1ms",
				"latency p99 90ms exceeds budget 1ms",
				"requests per second 750.00 below budget 1000.00",
				"errors 2 exceed budget 1",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := report.CheckBudgets(tc.budgets)
			if len(got) != len(tc.want) {
				t.Fatalf("violations = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("violations[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestCheckBudgetsZeroReport(t *testing.T) {
	violations := LoadReport{}.CheckBudgets(Budgets{
		MaxP50: time.Second,
		MaxP95: time.Second,
		MaxP99: time.Second,
	})
	if len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}
	// A zero-measurement report still violates a positive throughput budget.
	violations = LoadReport{}.CheckBudgets(Budgets{MinRPS: 1})
	if len(violations) != 1 || !strings.Contains(violations[0], "requests per second") {
		t.Fatalf("violations = %v", violations)
	}
}
