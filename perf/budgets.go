package perf

import (
	"fmt"
	"time"
)

// Budgets declares optional numeric budgets checked against a LoadReport.
// A zero field disables that budget, so a zero Budgets asserts nothing.
type Budgets struct {
	MaxP50    time.Duration `json:"max_p50_ns"`
	MaxP95    time.Duration `json:"max_p95_ns"`
	MaxP99    time.Duration `json:"max_p99_ns"`
	MinRPS    float64       `json:"min_rps"`
	MaxErrors int           `json:"max_errors"`
}

// CheckBudgets returns a description of each violated budget. An empty result
// means the report satisfies every asserted budget.
func (r LoadReport) CheckBudgets(budgets Budgets) []string {
	var violations []string
	if budgets.MaxP50 > 0 && r.LatencyP50 > budgets.MaxP50 {
		violations = append(violations, fmt.Sprintf("latency p50 %s exceeds budget %s", r.LatencyP50, budgets.MaxP50))
	}
	if budgets.MaxP95 > 0 && r.LatencyP95 > budgets.MaxP95 {
		violations = append(violations, fmt.Sprintf("latency p95 %s exceeds budget %s", r.LatencyP95, budgets.MaxP95))
	}
	if budgets.MaxP99 > 0 && r.LatencyP99 > budgets.MaxP99 {
		violations = append(violations, fmt.Sprintf("latency p99 %s exceeds budget %s", r.LatencyP99, budgets.MaxP99))
	}
	if budgets.MinRPS > 0 && r.RequestsPerSecond < budgets.MinRPS {
		violations = append(violations, fmt.Sprintf("requests per second %.2f below budget %.2f", r.RequestsPerSecond, budgets.MinRPS))
	}
	if budgets.MaxErrors > 0 && r.Errors > budgets.MaxErrors {
		violations = append(violations, fmt.Sprintf("errors %d exceed budget %d", r.Errors, budgets.MaxErrors))
	}
	return violations
}
