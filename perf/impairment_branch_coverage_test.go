package perf

// Adversarial white-box coverage for the two reachable count-0 branches in
// perf/impairment.go: the failure-recording blocks of the ImpairmentReport
// helpers scenario (40-43) and require (47-50). Both are methods on
// *ImpairmentReport that record a passing result silently and, on a failing
// result, flip r.Passed to false and append a finding. RunImpairmentHarness
// drives them only with passing inputs (its fixed scenario matrix is built to
// pass), so the !passed blocks are never entered and report at 0%.
//
// scenario(name, passed, detail) always appends a ScenarioResult (so the
// Scenarios slice and the passed-path are covered by the harness), then on
// !passed flips Passed and appends fmt.Sprintf("%s: %s", name, detail). require
// (passed, finding) only acts on !passed: it flips Passed and appends the raw
// finding string. The two !passed blocks are reachable by a direct call with
// passed=false on a fresh ImpairmentReport, and each is asserted to record
// exactly one finding and flip Passed. Happy-path locks (passed=true) confirm
// the helpers do NOT record on a pass, so the rejection tests are meaningful
// contrasts.
//
// Dead-by-design (documented, NOT covered — hardcoded-always-succeed /
// hardcoded-always-pass):
//   - RunImpairmentHarness:97-99 — the policy.ProfileByID(PolicyAdversarialDPI)
//     error guard. The harness hardcodes a known policy id, so ProfileByID
//     always resolves; the guard cannot fire.
//   - RunImpairmentHarness:102-104 — the transport.SelectCarrierPlan(dpiProfile,
//     udpBlockedCaps) error guard. The harness hardcodes a valid DPI profile
//     and a capabilities set SelectCarrierPlan accepts, so the plan always
//     selects; the guard cannot fire.
//   - checkUDPStalePolicy:205-211 — the three return-false branches (OpenWithOptions
//     error, stale datagram accepted, fresh datagram rejected). The function
//     hardcodes a valid FlowOpen that always opens and datagram timing that
//     always drops the stale datagram and accepts the fresh one, so the
//     function always returns true; the false branches cannot fire.
//   - checkTupleCooldown:220-222 — the return-false branches (cooldown not
//     activated, cooldown score not zero). The function hardcodes a
//     PathScoreRecord with BlockSuspectScore 0.9 that always activates a
//     cooldown whose Score is zero, so it always returns true; the false
//     branches cannot fire.
// RunImpairmentHarness and the two check functions take no parameters and use
// these hardcoded inputs, so their guard/failure branches are uncontrollable
// from a test and are not contrived here.
//
// This file adds no helpers (inline ImpairmentReport literals), so there is no
// staticcheck U1000 surface. No context.Context (no SA1012 surface), no
// goroutines, no cryptography, no network, no filesystem: scenario/require are
// pure slice-append and bool-set on the report struct.

import "testing"

func TestImpairmentReportScenarioRecordsFailure(t *testing.T) {
	// 40-43: scenario with passed=false appends the ScenarioResult, flips
	// Passed to false, and appends a "name: detail" finding.
	report := ImpairmentReport{Passed: true}
	report.scenario("udp-stale", false, "datagram accepted despite stale")

	if report.Passed {
		t.Fatal("scenario(passed=false) did not flip report.Passed to false")
	}
	if len(report.Scenarios) != 1 {
		t.Fatalf("scenario(passed=false) Scenarios = %d, want 1", len(report.Scenarios))
	}
	if got := report.Scenarios[0]; got.Name != "udp-stale" || got.Passed || got.Detail != "datagram accepted despite stale" {
		t.Fatalf("scenario(passed=false) Scenarios[0] = %+v, want {udp-stale false \"datagram accepted despite stale\"}", got)
	}
	if len(report.Findings) != 1 || report.Findings[0] != "udp-stale: datagram accepted despite stale" {
		t.Fatalf("scenario(passed=false) Findings = %v, want [\"udp-stale: datagram accepted despite stale\"]", report.Findings)
	}
}

func TestImpairmentReportScenarioDoesNotRecordPass(t *testing.T) {
	// Happy-path lock so the :40 rejection is a meaningful contrast: a passing
	// scenario still records the ScenarioResult but does NOT flip Passed or
	// append a finding.
	report := ImpairmentReport{Passed: true}
	report.scenario("interactive-priority", true, "ok")

	if !report.Passed {
		t.Fatal("scenario(passed=true) flipped report.Passed to false, want unchanged")
	}
	if len(report.Scenarios) != 1 || report.Scenarios[0].Name != "interactive-priority" || !report.Scenarios[0].Passed {
		t.Fatalf("scenario(passed=true) Scenarios = %+v, want one passing interactive-priority entry", report.Scenarios)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("scenario(passed=true) Findings = %v, want none", report.Findings)
	}
}

func TestImpairmentReportRequireRecordsFailure(t *testing.T) {
	// 47-50: require with passed=false flips Passed to false and appends the raw
	// finding string.
	report := ImpairmentReport{Passed: true}
	report.require(false, "tuple-cooldown: did not activate")

	if report.Passed {
		t.Fatal("require(passed=false) did not flip report.Passed to false")
	}
	if len(report.Findings) != 1 || report.Findings[0] != "tuple-cooldown: did not activate" {
		t.Fatalf("require(passed=false) Findings = %v, want [\"tuple-cooldown: did not activate\"]", report.Findings)
	}
}

func TestImpairmentReportRequireDoesNotRecordPass(t *testing.T) {
	// Happy-path lock so the :47 rejection is a meaningful contrast: a passing
	// require does NOT flip Passed or append a finding.
	report := ImpairmentReport{Passed: true}
	report.require(true, "should-not-record")

	if !report.Passed {
		t.Fatal("require(passed=true) flipped report.Passed to false, want unchanged")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("require(passed=true) Findings = %v, want none", report.Findings)
	}
}
