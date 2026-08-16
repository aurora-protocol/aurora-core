package transport

// Adversarial coverage for transport/conformance.go.
//
// The happy path through RunCarrierConformance — every add*Case helper
// succeeding and every report.addCase recording passed=true — is already
// asserted end-to-end by conformance_test.go
// (TestRunCarrierConformanceCoversP7Requirements). That test covers the
// success returns of all six add*Case helpers, the addCase passed=true
// append path (50-55), and the RunCarrierConformance success return at 46.
//
// This file covers the residual count-0 blocks:
//   - addCase 56-59: the !passed branch (Passed=false + Findings append). Every
//     production caller feeds a passed value computed from a hardcoded
//     happy-path input, and RunCarrierConformance asserts all six pass, so
//     56-59 is only reachable via a direct in-package addCase call with
//     passed=false (the white-box call below).
//   - FormatCarrierConformanceReport 306-315: the entire function body is
//     count-0 (no existing caller). Covered by a direct call with a report
//     containing both passing and failing cases plus findings, so the header
//     (308), per-case loop (309-310), finding loop (312-313), and return (315)
//     all execute.
//
// Dead-by-design (documented, not covered):
//   - RunCarrierConformance err-propagations 28-30, 31-33, 34-36, 37-39,
//     40-42, 43-45. Each fires only when its add*Case helper returns an error.
//     The helpers take only *CarrierConformanceReport (no varied input) and
//     build their calls from hardcoded constants, and RunCarrierConformance
//     reaches the success return at 46 (proven by the existing test), so no
//     helper ever errors through this entry point. With no parameter to
//     perturb, the propagations cannot fire.
//   - addH2BaselineCase 64-66 (policy.ProfileByID err) and 77-79
//     (SelectCarrierPlan err). PolicyAdversarialDPI is a registered profile
//     and the hardcoded full-capability Capabilities always select a plan,
//     so neither errors.
//   - addH1FallbackCase 91-93 (ProfileByID err) and 103-105 (SelectCarrierPlan
//     err). Same registered profile; the H1-fallback capabilities (H2
//     intentionally absent) always select a WebSocket fallback plan.
//   - addShadowOriginSlotCase 131-133 (BuildCarrierRequest err). The
//     conformanceTemplate + shadow-origin plan + NeedCapsule=true input is a
//     fixed valid combination that always builds.
//   - addH3ExtDatagramCase 145-147 (ProfileByID err), 155-157 (SelectCarrierPlan
//     err), 172-174 (BuildCarrierRequest err). PolicyFastWeb is registered;
//     the H3-only capabilities select an extended-datagram plan; the first
//     BuildCarrierRequest uses H3DatagramSettingsOK=true which always builds
//     (the false variant is exercised on the success path at 175-176 and only
//     feeds the passed computation).
//   - addMasqueVisibleOptInCase 191-193 / 195-197 / 199-201 (ProfileByID errs
//     for PolicyFastWeb, PolicyBalancedWeb, PolicyLab). All three are
//     registered profiles.
//   - addSharedOpaqueCorePathCase 226-228 / 230-232 / 234-236 (NewCarrierSession
//     errs for H2, H1, H3 method IDs) and 238-240 / 242-244 / 246-248
//     (SendDatagram errs). The three hardcoded method IDs each construct a
//     valid carrier session and SendDatagram on a non-empty payload always
//     succeeds for those carriers.
//
// The dead-by-design blocks are defensive error-return boilerplate around
// inputs the helpers hardcode; there is no caller-controllable path that
// makes the underlying call fail. They are left uncovered deliberately.
//
// Not duplicated: the RunCarrierConformance happy path and per-case pass
// assertions are covered by conformance_test.go and are not re-asserted here.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). This file adds no package-level helpers, so there is no
// U1000 surface. No context.Context, no goroutines, no deprecated APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestAddCaseFailureBranch flips a report to Passed=false and records a
// finding, exercising the !passed branch (56-59) that the all-passing
// RunCarrierConformance path never reaches. A preceding passing case proves
// the passed=true append path (50-55) leaves Passed untouched.
func TestAddCaseFailureBranch(t *testing.T) {
	// Mirror RunCarrierConformance: the report starts Passed=true and addCase
	// only ever flips it monotonically to false (it never sets true).
	report := CarrierConformanceReport{Passed: true}

	// Passing case: append only, Passed stays true, no finding recorded.
	report.addCase("ok_case", true, methodName(registry.MethodWebH2Stream), "baseline ok")
	if !report.Passed {
		t.Fatal("passed=true addCase must not flip report.Passed")
	}
	if len(report.Cases) != 1 || report.Cases[0].Name != "ok_case" || !report.Cases[0].Passed {
		t.Fatalf("passing case not recorded: %+v", report.Cases)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("passing case recorded a finding: %+v", report.Findings)
	}

	// Failing case: the !passed branch (56-59) flips Passed and appends a finding.
	report.addCase("fail_case", false, methodName(registry.MethodWebH1WS), "fallback broken")
	if report.Passed {
		t.Fatal("passed=false addCase must flip report.Passed to false")
	}
	if len(report.Findings) != 1 || report.Findings[0] != "fail_case failed" {
		t.Fatalf("findings = %+v, want [fail_case failed]", report.Findings)
	}
	if len(report.Cases) != 2 {
		t.Fatalf("case count = %d, want 2", len(report.Cases))
	}
	if report.Cases[1].Name != "fail_case" || report.Cases[1].Passed {
		t.Fatalf("failing case not recorded as failed: %+v", report.Cases[1])
	}

	// A second failing case appends another finding without resetting Passed.
	report.addCase("fail_case_2", false, methodName(registry.MethodShadowOrigin), "shadow broken")
	if report.Passed {
		t.Fatal("report.Passed must stay false after a second failure")
	}
	if len(report.Findings) != 2 || report.Findings[1] != "fail_case_2 failed" {
		t.Fatalf("findings = %+v, want two findings", report.Findings)
	}
}

// TestFormatCarrierConformanceReportRendersAllSections exercises the whole
// FormatCarrierConformanceReport body (306-315), which has no existing caller.
// The report carries one passing case, one failing case, and a finding so the
// header, per-case loop, finding loop, and return all execute.
func TestFormatCarrierConformanceReportRendersAllSections(t *testing.T) {
	report := CarrierConformanceReport{
		Passed: false,
		Cases: []CarrierConformanceCase{
			{Name: "h2_baseline_first", Passed: true, Method: "h2_stream", Detail: "adversarial profile selects mandatory H2 baseline"},
			{Name: "h1_websocket_fallback", Passed: false, Method: "h1_ws", Detail: "fallback failed"},
		},
		Findings: []string{"h1_websocket_fallback failed"},
	}
	out := FormatCarrierConformanceReport(report)

	// Header (308): passed, cases count, failures count.
	if !strings.Contains(out, "transport_check passed=false cases=2 failures=1") {
		t.Fatalf("header line missing or wrong:\n%s", out)
	}
	// Per-case loop (309-310): passing case rendered with passed=true.
	if !strings.Contains(out, `transport_case h2_baseline_first passed=true method=h2_stream detail="adversarial profile selects mandatory H2 baseline"`) {
		t.Fatalf("passing-case line missing:\n%s", out)
	}
	// Per-case loop: failing case rendered with passed=false.
	if !strings.Contains(out, `transport_case h1_websocket_fallback passed=false method=h1_ws detail="fallback failed"`) {
		t.Fatalf("failing-case line missing:\n%s", out)
	}
	// Finding loop (312-313).
	if !strings.Contains(out, "transport_finding h1_websocket_fallback failed") {
		t.Fatalf("finding line missing:\n%s", out)
	}
	// Empty-report degenerate path: no cases, no findings, passed=true. Exercises
	// the loops with zero iterations and the return (315) with the zero-count
	// header.
	empty := FormatCarrierConformanceReport(CarrierConformanceReport{Passed: true})
	if !strings.Contains(empty, "transport_check passed=true cases=0 failures=0") {
		t.Fatalf("empty header missing:\n%s", empty)
	}
	if strings.Contains(empty, "transport_case") || strings.Contains(empty, "transport_finding") {
		t.Fatalf("empty report must not render cases or findings:\n%s", empty)
	}
}
