package relay

// Adversarial white-box coverage for the count-0 nil-receiver/nil-argument
// first-statement safety guards across the relay package's Close/teardown
// paths. Each guard exists so a caller that holds a nil *ExitSession /
// *SocketEgress / *socketFlow pointer — or passes a nil flow to closeFlow —
// does not panic: the method returns at its very first statement, before any
// field is dereferenced or any once-guard/closure runs. The existing relay
// tests only ever drive non-nil exit sessions and socket-egress instances built
// by the live relay path (which never hand a nil pointer to these methods), so
// the guards stayed count-0 even though each is plainly reachable.
//
// These are the nil-RECEIVER / nil-ARGUMENT analogues of the nil-context guards
// covered elsewhere; they have no ctx==nil surface, so there is no SA1012
// surface (no nil context literal is passed anywhere). No network, no
// goroutine, no crypto — each call returns at the first statement.
//
//   - egress.go:151        ExitSession.Close        s == nil       -> return nil
//     (exported; a nil *ExitSession.Close returns nil rather than touching
//     s.closeOnce / s.closing / s.egress)
//   - socket_egress.go:748 SocketEgress.closeFlow    flow == nil   -> return (no-op)
//     (unexported method, nil-ARGUMENT guard; flow==nil fires before the
//     receiver is dereferenced, so the call is safe even though it walks the
//     flow's cancel/close path on the non-nil branch)
//   - socket_egress.go:771 socketFlow.finish         f == nil      -> return (no-op)
//     (unexported; a nil *socketFlow.finish returns rather than touching
//     f.doneOnce / f.done)
//   - socket_egress.go:882 SocketEgress.Close        e == nil      -> return nil
//     (exported; a nil *SocketEgress.Close returns nil rather than touching
//     e.closeOnce / e.flows / e.cancel)
//
// The test is in-package because closeFlow and socketFlow are unexported. The
// two void guards (closeFlow nil flow, finish nil receiver) are proven by
// absence of panic: each returns at the first statement and never reaches the
// once-guard / closure body, so calling it must complete without panicking.

import (
	"testing"
)

func TestExitSessionCloseIsNilSafe(t *testing.T) {
	// 151: a nil *ExitSession.Close returns nil at its first statement rather
	// than dereferencing s.closeOnce / s.closing / s.egress.
	var s *ExitSession
	if err := s.Close(); err != nil {
		t.Fatalf("nil.ExitSession.Close err = %v, want nil (:151 should return nil)", err)
	}
}

func TestSocketEgressCloseIsNilSafe(t *testing.T) {
	// 882: a nil *SocketEgress.Close returns nil at its first statement rather
	// than dereferencing e.closeOnce / e.flows / e.cancel.
	var e *SocketEgress
	if err := e.Close(); err != nil {
		t.Fatalf("nil.SocketEgress.Close err = %v, want nil (:882 should return nil)", err)
	}
}

func TestSocketEgressCloseFlowNilArgumentIsSafe(t *testing.T) {
	// 748: closeFlow(flowID, flow) with a nil flow returns at its first
	// statement before touching flow.cancel / flow.closeOnce / the receiver e.
	// A zero-valued SocketEgress is a safe receiver because the nil-flow guard
	// fires before e is dereferenced; the call must complete without panicking.
	// (Wrap in a recover so a panic — the failure mode the guard prevents —
	// surfaces as a test failure rather than aborting the test binary.)
	var e SocketEgress
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("closeFlow(0, nil) panicked = %v, want no-op return (:748 should guard the nil flow)", r)
			}
		}()
		(&e).closeFlow(0, nil)
	}()
}

func TestSocketFlowFinishIsNilSafe(t *testing.T) {
	// 771: a nil *socketFlow.finish returns at its first statement rather than
	// dereferencing f.doneOnce / f.done. The call must complete without
	// panicking; a recover surfaces a panic as a test failure.
	var f *socketFlow
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.socketFlow.finish panicked = %v, want no-op return (:771 should guard the nil receiver)", r)
			}
		}()
		f.finish()
	}()
}
