package route

// Adversarial white-box coverage for the uncovered branches of
// route/session.go. session.go is a single-goroutine state machine over
// ClientSession (the preludeVerified flag, the active route id/hop, and a
// draining-routes map keyed by route id). It performs no cryptography and no
// network or filesystem access; every time-dependent decision takes an
// explicit nowUnix argument (there are no time.Now calls), so the machine is
// fully deterministic. The uncovered branches are its state-precondition
// guards and one error-propagation return.
//
// Targets covered:
//
//   - ClientSession.VerifyRoutePrelude1:27-29 — the
//     VerifyRoutePrelude1Signatures error propagation. The existing suite
//     drives VerifyRoutePrelude1Signatures directly (route/route.go), never
//     through the ClientSession wrapper, so the wrapper's propagation return
//     is unreached. A PrivatePrelude with a wrong MsgType fails
//     ValidatePrivatePreludeHeader at route.go:366 (the first check inside
//     VerifyRoutePrelude1Signatures), so the wrapper surfaces the error and
//     never reaches the ActivateRoute call at session.go:30 (the session
//     stays unverified, asserted via AcceptsRouteInstance).
//   - ClientSession.RotateRoute:55-57 — the `!s.preludeVerified` guard. The
//     existing suite rotates only after activation, so the no-active-route
//     return is unreached. A freshly constructed session is unverified.
//   - ClientSession.RotateRoute:62-64 — the `s.routeInstanceID ==
//     routeInstanceID` duplicate guard, reached after the prelude-verified
//     and not-currently-draining checks pass. The existing suite rotates to a
//     different route instance, so the duplicate return is unreached. After
//     ActivateRoute(1), RotateRoute(1, ...) hits it before the draining-map
//     initialization.
//   - ClientSession.AcceptsRouteInstance:79-81 — the `!s.preludeVerified`
//     guard. The existing suite queries only an activated session, so the
//     unverified return is unreached. A freshly constructed session is
//     unverified.
//
// Dead-by-design (documented, NOT claimed):
//   - ClientSession.RotateRoute:65-67 — the `if s.drainingRoutes == nil` map
//     initialization. preludeVerified is set true only by ActivateRoute
//     (session.go:45), and ActivateRoute always initializes drainingRoutes to
//     a non-nil map alongside it (session.go:48-49). RotateRoute reaches 65
//     only after the prelude-verified check at 55 passes, so drainingRoutes is
//     always non-nil here and the nil-check is always false. Shadowed-by-
//     earlier-check (the map is initialized by the same call that sets the
//     flag RotateRoute just checked).
//
// No new package-level helpers or types are introduced (only test functions),
// so there is nothing for staticcheck U1000. No context.Context (no SA1012
// surface), no goroutines, no cryptography, no real network or filesystem.

import (
	"strings"
	"testing"
)

func TestClientSessionVerifyRoutePrelude1PropagatesHeaderError(t *testing.T) {
	// 27-29: a PrivatePrelude with a wrong MsgType fails
	// ValidatePrivatePreludeHeader (route.go:366) as the first check inside
	// VerifyRoutePrelude1Signatures, so the ClientSession wrapper surfaces the
	// error and never activates the session.
	s := NewClientSession()
	in := RoutePreludeVerificationInput{
		Suite:    0,
		Prelude0: PrivatePrelude{MsgType: 0xBAD},
	}
	if _, err := s.VerifyRoutePrelude1(in); err == nil ||
		!strings.Contains(err.Error(), "malformed private prelude message type") {
		t.Fatalf("VerifyRoutePrelude1(bad MsgType) err = %v, want substring \"malformed private prelude message type\"", err)
	}
	// The session must remain unverified: ActivateRoute (session.go:30) only
	// runs after a successful verification.
	if s.AcceptsRouteInstance(1, 0) {
		t.Fatal("AcceptsRouteInstance = true after failed VerifyRoutePrelude1, want false (session was not activated)")
	}
}

func TestClientSessionRotateRouteRejectsUnverified(t *testing.T) {
	// 55-57: a freshly constructed session is unverified, so RotateRoute
	// rejects the rotation before inspecting the draining map.
	s := NewClientSession()
	if err := s.RotateRoute(1, 0, 100, 10); err == nil ||
		!strings.Contains(err.Error(), "no active route to rotate") {
		t.Fatalf("RotateRoute(unverified) err = %v, want substring \"no active route to rotate\"", err)
	}
}

func TestClientSessionRotateRouteRejectsDuplicateRouteInstance(t *testing.T) {
	// 62-64: after ActivateRoute(1), the session is verified and not draining,
	// so RotateRoute reaches the duplicate-instance guard and rejects a
	// rotation to the same route instance (1) it already activated.
	s := NewClientSession()
	s.ActivateRoute(1, 0)
	if err := s.RotateRoute(1, 0, 100, 10); err == nil ||
		!strings.Contains(err.Error(), "duplicate active route instance") {
		t.Fatalf("RotateRoute(same instance) err = %v, want substring \"duplicate active route instance\"", err)
	}
}

func TestClientSessionAcceptsRouteInstanceRejectsUnverified(t *testing.T) {
	// 79-81: a freshly constructed session is unverified, so
	// AcceptsRouteInstance returns false before inspecting the route id.
	s := NewClientSession()
	if s.AcceptsRouteInstance(1, 100) {
		t.Fatal("AcceptsRouteInstance(unverified) = true, want false")
	}
}
