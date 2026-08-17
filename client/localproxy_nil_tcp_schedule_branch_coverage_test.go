package client

// Adversarial white-box coverage for the count-0 first-statement nil-field
// safety guard on the local TCP proxy frame reader. NextTCPFrame begins with
// `if p.tcpSchedule == nil { return protocol.AuroraFrame{}, false, nil }` so a
// caller that drives a zero-value LocalProxy (no flow.Scheduler configured)
// does not dereference the nil scheduler at p.tcpSchedule.Next(). The existing
// client tests only ever drive a LocalProxy whose tcpSchedule is populated
// (the EnqueueTCP path lazily initializes it at client.go:293, and the
// integration tests always enqueue before reading), so the nil-field guard
// stayed count-0 even though it is plainly reachable with a zero-value proxy.
//
//   - client.go:305 (*LocalProxy).NextTCPFrame()
//     p.tcpSchedule == nil -> (zero protocol.AuroraFrame{}, false, nil)
//     (fires before p.tcpSchedule.Next()). The proof that the :305 guard ran
//     (rather than the exhausted-schedule path at :308, which returns the same
//     (zero, false, nil)) is that the call does not panic: a nil tcpSchedule
//     reaching .Next() would panic, so a no-panic (zero, false, nil) return
//     confirms the guard intercepted at the first statement.
//
// This is a nil-FIELD first-statement guard (on a field of the receiver). No
// context is involved, so there is no SA1012 surface. No network, no goroutine,
// no real flow — the guard returns before the scheduler is touched, so the test
// is pure and cannot perturb the client package's timing-sensitive TCP/UDP
// proxy integration tests. The test is in-package (package client).
//
// This test file adds only a TestXxx entry point and uses an existing exported
// in-package symbol, so it adds no U1000 surface.

import "testing"

func TestLocalProxyNextTCPFrameNilTcpScheduleGuard(t *testing.T) {
	// 305: a zero-value *LocalProxy has tcpSchedule == nil, so the
	// first-statement guard returns before p.tcpSchedule.Next(). The proof
	// that the :305 guard ran (not the exhausted-schedule path at :308, which
	// returns the same (zero, false, nil)) is that the call does not panic: a
	// nil scheduler reaching .Next() would panic, so a no-panic (false, nil)
	// return confirms the guard intercepted.
	p := &LocalProxy{}
	_, ok, err := p.NextTCPFrame()
	if ok {
		t.Fatal("NextTCPFrame() ok = true, want false (:305 nil-schedule guard returns false)")
	}
	if err != nil {
		t.Fatalf("NextTCPFrame() err = %v, want nil (:305)", err)
	}
}
