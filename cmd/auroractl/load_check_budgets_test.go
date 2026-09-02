package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	auroraperf "github.com/aurora-protocol/aurora-core/perf"
)

func passingLoadReport(report auroraperf.LoadReport) carrierLoadRunner {
	return func(context.Context, *http.Client, string, auroraperf.LoadOptions) (auroraperf.LoadReport, error) {
		return report, nil
	}
}

func TestLoadCheckBudgetViolationFails(t *testing.T) {
	var out bytes.Buffer
	err := loadCheckWithRunner([]string{
		"--url", "http://example.invalid/load",
		"--max-p95", "10ms",
		"--min-rps", "1000",
	}, &out, passingLoadReport(auroraperf.LoadReport{
		Passed:            true,
		LatencyP95:        50 * time.Millisecond,
		RequestsPerSecond: 500,
	}))
	if err == nil || !strings.HasPrefix(err.Error(), "load-check: budget exceeded: ") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "latency p95 50ms exceeds budget 10ms") ||
		!strings.Contains(err.Error(), "requests per second 500.00 below budget 1000.00") ||
		!strings.Contains(err.Error(), "; ") {
		t.Fatalf("error does not list both violations: %v", err)
	}
	// The JSON report is still emitted before the budget failure.
	var report auroraperf.LoadReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("load-check output is not JSON: %v", err)
	}
	if !report.Passed || report.LatencyP95 != 50*time.Millisecond {
		t.Fatalf("report = %+v", report)
	}
}

func TestLoadCheckBudgetsSatisfiedPass(t *testing.T) {
	var out bytes.Buffer
	err := loadCheckWithRunner([]string{
		"--url", "http://example.invalid/load",
		"--max-p50", "10ms",
		"--max-p95", "50ms",
		"--max-p99", "90ms",
		"--min-rps", "750",
		"--max-errors", "0",
	}, &out, passingLoadReport(auroraperf.LoadReport{
		Passed:            true,
		LatencyP50:        10 * time.Millisecond,
		LatencyP95:        50 * time.Millisecond,
		LatencyP99:        90 * time.Millisecond,
		RequestsPerSecond: 750,
	}))
	if err != nil {
		t.Fatalf("at-limit budgets should pass: %v", err)
	}
	var report auroraperf.LoadReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("load-check output is not JSON: %v", err)
	}
}

func TestLoadCheckDefaultBudgetsUnchanged(t *testing.T) {
	// With no budget flags, measurements that would violate any budget still
	// pass exactly as before.
	var out bytes.Buffer
	err := loadCheckWithRunner([]string{"--url", "http://example.invalid/load"}, &out, passingLoadReport(auroraperf.LoadReport{
		Passed:            true,
		LatencyP50:        time.Hour,
		LatencyP95:        time.Hour,
		LatencyP99:        time.Hour,
		RequestsPerSecond: 0.01,
	}))
	if err != nil {
		t.Fatalf("default behavior changed: %v", err)
	}
}

func TestLoadCheckRejectsInvalidBudgetFlag(t *testing.T) {
	var out bytes.Buffer
	err := loadCheckWithRunner([]string{"--url", "http://example.invalid", "--max-p95", "soon"}, &out, nil)
	if err == nil || err.Error() != "load-check: invalid options" {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("load-check wrote output for invalid flags: %q", out.String())
	}
}
