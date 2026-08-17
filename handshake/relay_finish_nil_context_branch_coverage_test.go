package handshake

// Adversarial white-box coverage for the count-0 nil-context guard of
// (*RelayHandshake).Finish (handshake/relay.go:205). The guard sits BEHIND three
// earlier guards (:195 h==nil, :200 h.terminal||h.driver==nil) and is reached
// only with a non-nil receiver whose driver is non-nil and terminal is false.
// The prior relay nil-safety PR (#347, relay_nil_safety_branch_coverage_test.go)
// covered :195 by passing a nil receiver (which returns at :195 before :205),
// so :205 stayed COUNT 0. No existing Finish caller passes a nil context: the
// real callers in relay_test.go all use context.Background() and return at
// :206 (contextError) or later.
//
// Coverage target (baseline measured on main; body COUNT 0):
//   - relay.go:205.16,207.3 0 — Finish: ctx==nil
//     -> "handshake: nil relay context"
//
// Reachability: construct &RelayHandshake{driver: &RelayDriver{}} — terminal is
// the zero value (false), driver is non-nil, so :200 passes; :202 flips terminal
// true; :203 defers destroyLocked; :205 ctx==nil returns the error. The deferred
// destroyLocked then runs on a zero-value handshake: it calls zeroBindingBytes
// on nil slices (range over nil = zero iterations) and zeroHandshakeSecrets on a
// zero-value HandshakeSecrets (nil-guarded + zeroBindingBytes(nil) no-ops) and
// sets h.driver=nil — a safe no-op, no panic. h.driver is never dereferenced
// (the first deref is at :215 driver.deployment, after :205 returns).
//
// Error string is asserted (self-validating); the per-line coverage flip is the
// rigorous proof. SA1012 (nil Context literal) is suppressed per the established
// codebase convention (//lint:ignore SA1012 Verifies the public API's explicit
// nil-context rejection.) on the intentional nil-context call (CI-proven on
// #264/#346/#349/#350/#353/#354/#356). The driver field is unexported -> in-package
// (package handshake) test. One TestXxx; imports strings/testing -> no U1000
// surface.

import (
	"strings"
	"testing"
)

func TestRelayHandshakeFinishRejectsNilContext(t *testing.T) {
	// :205 — Finish with a nil context. The receiver is a non-nil
	// &RelayHandshake{driver: &RelayDriver{}}: terminal is false (zero value) and
	// driver is non-nil, so :200 passes; the deferred destroyLocked (:203) runs on
	// the return and is a safe no-op on this zero-value handshake.
	h := &RelayHandshake{driver: &RelayDriver{}}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, _, _, err := h.Finish(nil, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "nil relay context") {
		t.Fatalf("Finish(nil ctx) err = %v, want non-nil containing \"nil relay context\" (:205)", err)
	}
}
