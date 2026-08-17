package server

// Adversarial white-box coverage for the count-0 failure-recording branch of
// ClientInteropReport.require in server/client_interop.go (99-105):
//
//	func (r *ClientInteropReport) require(ok bool, finding string) {
//	    if ok {                 // 100 — true branch, already covered (every
//	        return              // 101-102   passing assertion returns here)
//	    }
//	    r.Passed = false        // 103 — count-0: a failed assertion flips Passed
//	    r.Findings = append(r.Findings, finding) // 104 — count-0: and records why
//	}
//
// require is the assertion helper RunClientInteropHarness uses to record each
// failed cover-neutral / carrier check. The harness only ever calls it after a
// probe returns ok (the success path) or after a probe returns false (the
// failure path). The existing client_interop_test.go drives the harness end
// to end with a passing configuration, so every require call takes the ok=true
// early-return at 100-102 and the 103-104 failure body stayed count-0 — even
// though it is plainly reachable: any single failed assertion records a
// finding and flips the report's Passed flag.
//
// This test exercises require directly (in-package — it is unexported) with
// ok=false to record the failure path, plus a contrast with ok=true to lock
// the early-return, and a second ok=false call to prove Findings accumulates
// (append, not replace). No network, no harness, no goroutine, no helpers.

import (
	"testing"
)

func TestClientInteropReportRequireRecordsFailureAndFlipsPassed(t *testing.T) {
	// 103-104: a failed assertion (ok=false) flips Passed to false and appends
	// the finding string to Findings. Start from Passed=true so the flip is
	// observable, and use two distinct findings to prove append accumulates.
	r := &ClientInteropReport{Passed: true}
	r.require(false, "issuer metadata carrier failed over HTTP")
	if r.Passed {
		t.Fatal("require(false, ...) left Passed=true, want false (:103 should flip)")
	}
	if len(r.Findings) != 1 || r.Findings[0] != "issuer metadata carrier failed over HTTP" {
		t.Fatalf("require(false, ...) Findings = %v, want [\"issuer metadata carrier failed over HTTP\"] (:104 should append)", r.Findings)
	}

	// A second failure appends rather than replaces — Findings is an append,
	// so the report accumulates every failed check.
	r.require(false, "token spend carrier failed over HTTP")
	if len(r.Findings) != 2 || r.Findings[0] != "issuer metadata carrier failed over HTTP" || r.Findings[1] != "token spend carrier failed over HTTP" {
		t.Fatalf("after second require(false, ...) Findings = %v, want two accumulated findings (:104 appends)", r.Findings)
	}
	if r.Passed {
		t.Fatal("after second failure Passed=true, want still false")
	}
}

func TestClientInteropReportRequireNoOpOnSuccess(t *testing.T) {
	// 100-102 lock: a passing assertion (ok=true) returns early without
	// touching Passed or Findings, so the 103-104 body is provably NOT taken
	// on the success path — making the failure-path coverage above a
	// meaningful contrast.
	r := &ClientInteropReport{Passed: true}
	r.require(true, "must not be recorded")
	if !r.Passed {
		t.Fatal("require(true, ...) flipped Passed to false, want unchanged (early return at 100-102)")
	}
	if len(r.Findings) != 0 {
		t.Fatalf("require(true, ...) Findings = %v, want empty (early return must not append)", r.Findings)
	}
}
