package route

// Adversarial white-box coverage for the count-0 nil-field lazy-init guard in
// ClientSession.RotateRoute. RotateRoute begins with a preludeVerified gate,
// a purgeDrained sweep, an "already draining" guard, and a duplicate-instance
// guard, and then initializes drainingRoutes when it is nil before recording
// the new route instance.
//
//   - session.go:65 (*ClientSession).RotateRoute
//     s.drainingRoutes == nil -> s.drainingRoutes = make(map[uint64]drainingRoute)
//     (fires after the preludeVerified gate at :55, purgeDrained at :58, the
//     "route rotation already draining" guard at :59, and the duplicate-active
//     route instance guard at :62, before the drainSeconds entry append at :68
//     and the routeInstanceID / hopIndex assignment at :73).
//
// The existing route tests drive RotateRoute only on a ClientSession that was
// first activated via ActivateRoute, and ActivateRoute already initializes
// drainingRoutes at :48 (so :48 is covered). A subsequent RotateRoute therefore
// always sees a non-nil drainingRoutes, so the :65 nil-field lazy-init branch
// stayed count-0 even though it is plainly reachable by rotating a route on a
// ClientSession whose drainingRoutes is still nil — i.e. a ClientSession with
// preludeVerified set but drainingRoutes left at its zero value (bypassing
// ActivateRoute).
//
// Proof technique (nil-field lazy-init): construct a ClientSession with
// preludeVerified = true and drainingRoutes left nil, then call RotateRoute
// with a distinct routeInstanceID (so the :62 duplicate-instance guard does
// not short-circuit) and drainSeconds = 0 (so the :68 append path is skipped and
// the map stays empty). The proof that the :65 branch ran is that
// s.drainingRoutes is non-nil afterward: it was nil on input and the only site
// in RotateRoute that populates drainingRoutes is :65 (purgeDrained at :58 only
// ranges / deletes over the nil map — a no-op — and never allocates), so a
// non-nil output uniquely identifies the :65 lazy-init.
//
// No context is involved (RotateRoute takes none), so there is no SA1012
// surface. No network, no goroutine, no real route envelope — the guard only
// allocates an empty map, so the test is pure. purgeDrained ranging over a nil
// map is a well-defined no-op (zero iterations), so the :58 sweep is safe.
// In-package (package route) because RotateRoute and the drainingRoutes /
// preludeVerified fields are unexported.
//
// This test file adds only a TestXxx entry point and references existing
// unexported in-package symbols, so it adds no U1000 surface.

import (
	"testing"
)

func TestClientSessionRotateRouteDrainingRoutesLazyInit(t *testing.T) {
	// 65: a RotateRoute call on a ClientSession whose drainingRoutes is still
	// nil (preludeVerified set, ActivateRoute bypassed) initializes the map at
	// the :65 lazy-init. A distinct routeInstanceID (1, vs the zero default)
	// passes the :62 duplicate-instance guard, and drainSeconds = 0 skips the
	// :68 append so the map stays empty but non-nil. The proof is that
	// s.drainingRoutes is non-nil afterward: it was nil on input and :65 is the
	// only site in RotateRoute that populates it.
	s := &ClientSession{preludeVerified: true}
	err := s.RotateRoute(1, 0, 0, 0)
	if err != nil {
		t.Fatalf("RotateRoute err = %v, want nil (distinct instance, no active drain)", err)
	}
	if s.drainingRoutes == nil {
		t.Fatal("RotateRoute left drainingRoutes = nil, want non-nil (:65 lazy-init should make the map)")
	}
}
