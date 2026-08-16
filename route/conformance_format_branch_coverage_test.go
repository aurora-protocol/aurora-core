package route

// Adversarial white-box coverage for route/conformance.go's report formatter
// FormatSplitRouteConformanceReport (465-475), which is real production code
// (cmd/auroractl/main.go:1053 writes the formatted report to a writer) but is
// exercised only through that CLI entry point, so the route package's own
// coverage profile reports it at 0.0% — none of the route-package tests ever
// call it. The function is a pure bytes.Buffer formatter (no crypto, no
// network, no filesystem, no goroutines): it writes a header line, one line
// per case, and one line per finding, then returns the accumulated string.
//
// A single report with two cases (one passing, one failing) and one finding
// drives every statement: the header Fprintf (passed/cases/failures), the
// per-case loop body (both the passed=true and passed=false renders of
// detail=%q), the per-finding loop body, and the return. The exact formatted
// output is asserted (golden-value byte-identity lock) so a future change to
// the wire/CLI format is caught here, and substring checks make the failure
// attributable to a specific line if the golden string drifts.
//
// This file adds no helpers (one test function, inline report literal), so
// there is no staticcheck U1000 surface. No context.Context (no SA1012
// surface), no goroutines, no cryptography, no network, no filesystem.

import (
	"strings"
	"testing"
)

func TestFormatSplitRouteConformanceReportRendersAllLines(t *testing.T) {
	// A report with a passing case, a failing case, and a finding exercises
	// every statement of FormatSplitRouteConformanceReport: the header line
	// (passed=%t, cases=%d, failures=%d), both the passed=true and passed=false
	// renders of the per-case line (detail=%q), the per-finding line, and the
	// return. The exact output is the golden-value byte-identity lock.
	report := SplitRouteConformanceReport{
		Passed: false,
		Cases: []SplitRouteConformanceCase{
			{Name: "forward-opaque-entry", Passed: true, Detail: "ok"},
			{Name: "backward-opaque-entry", Passed: false, Detail: "trailing bytes"},
		},
		Findings: []string{"backward-opaque-entry failed"},
	}
	got := FormatSplitRouteConformanceReport(report)

	want := "route_check passed=false cases=2 failures=1\n" +
		"route_case forward-opaque-entry passed=true detail=\"ok\"\n" +
		"route_case backward-opaque-entry passed=false detail=\"trailing bytes\"\n" +
		"route_finding backward-opaque-entry failed\n"
	if got != want {
		t.Fatalf("FormatSplitRouteConformanceReport = %q\nwant %q", got, want)
	}

	// Substring checks so a drift points at the specific line that changed.
	for _, sub := range []string{
		"route_check passed=false cases=2 failures=1\n",
		"route_case forward-opaque-entry passed=true detail=\"ok\"\n",
		"route_case backward-opaque-entry passed=false detail=\"trailing bytes\"\n",
		"route_finding backward-opaque-entry failed\n",
	} {
		if !strings.Contains(got, sub) {
			t.Fatalf("FormatSplitRouteConformanceReport output missing %q; got %q", sub, got)
		}
	}
}

func TestFormatSplitRouteConformanceReportRendersEmptyReport(t *testing.T) {
	// A fully-passing report with no cases and no findings formats to just the
	// header line: passed=true, cases=0, failures=0, no case or finding lines.
	// This exercises the loops with zero iterations (the range setups run but
	// the bodies do not) and locks the empty-report path as a contrast to the
	// two-case report above.
	got := FormatSplitRouteConformanceReport(SplitRouteConformanceReport{Passed: true})
	want := "route_check passed=true cases=0 failures=0\n"
	if got != want {
		t.Fatalf("FormatSplitRouteConformanceReport(empty) = %q, want %q", got, want)
	}
}
