package relay

// Adversarial white-box coverage for the count-0 nil-safety guard in
// (*SocketEgress).activeFlow: the unknown-flow branch of the compound :587
// guard.
//
//   - socket_egress.go:587 (*SocketEgress).activeFlow
//     flow == nil || flow.conn == nil || flow.kind != kind -> ErrExitFlowUnknown
//     (the first clause; an empty/nil flows map returns nil for an unknown
//     flowID, so flow == nil short-circuits the compound guard before flow.conn
//     and flow.kind are dereferenced).
//
// The existing relay tests drive activeFlow only on a fully-installed flow (a
// real socketFlow with conn + kind), so the unknown-flow nil clause stayed
// count-0 even though it is plainly reachable with an empty egress.
//
// Proof: (&SocketEgress{ctx: context.Background()}).activeFlow(1, 0) — a
// non-errored ctx skips the :583 closed/cancelled guard; the nil flows map
// returns nil at :586; flow == nil short-circuits :587 before flow.conn /
// flow.kind; :588 returns ErrExitFlowUnknown.
//
// No context.Context is passed as a nil argument (context.Background is used),
// so there is no SA1012 surface. No network, no goroutine, no file IO — the guard
// returns before any conn / dialer / resolver is touched. activeFlow acquires
// e.mu itself (it is not a "Locked"-suffix method), so calling it on a
// zero-value SocketEgress without external locking is safe and does not
// deadlock. In-package (package relay) because activeFlow is unexported.
//
// This test file adds only a TestXxx entry point and references existing
// in-package (SocketEgress, activeFlow, ErrExitFlowUnknown) symbols and the
// standard library context / errors / testing packages, so it adds no U1000
// surface.

import (
	"context"
	"errors"
	"testing"
)

func TestSocketEgressActiveFlowUnknownFlowGuard(t *testing.T) {
	// 587: an empty flows map returns nil for an unknown flowID; flow == nil
	// short-circuits the compound :587 guard before flow.conn / flow.kind are
	// dereferenced; :588 returns ErrExitFlowUnknown. A non-errored ctx skips the
	// :583 closed guard.
	e := &SocketEgress{ctx: context.Background()}
	_, err := e.activeFlow(1, 0)
	if !errors.Is(err, ErrExitFlowUnknown) {
		t.Fatalf("activeFlow(unknown flow) err = %v, want ErrExitFlowUnknown (:588)", err)
	}
}
