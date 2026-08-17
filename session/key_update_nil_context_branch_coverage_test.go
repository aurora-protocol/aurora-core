package session

// Adversarial white-box coverage for the count-0 nil-context guard of
// Application.InitiateKeyUpdate (session/key_update.go:41). The method's first
// statement rejects a nil context with "session: nil context" before reading
// the reason, ctx.Err(), or any Application field, so a bare non-nil
// *Application suffices (no key state, no harness).
//
// Coverage target (baseline measured on main; body COUNT 0 while the :41
// condition was already evaluated — every existing session test passes a real
// context.Background(), so the nil-context body is never taken):
//   - key_update.go:41.16,43.3 0  — InitiateKeyUpdate nil-context body
//
// SA1012 (nil Context literal) is suppressed for the one intentional
// nil-context call via the established codebase convention
// (//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
// — see provisioned_session_nil_safety_branch_coverage_test.go, CI-proven on
// #264 and many successors).
//
// In-package (package session) because InitiateKeyUpdate is a method on the
// in-package Application type. No real network, no goroutines. This file adds
// one TestXxx entry point and references stdlib strings/testing only -> no U1000
// surface.

import (
	"strings"
	"testing"
)

func TestInitiateKeyUpdateRejectsNilContext(t *testing.T) {
	// :41 — a bare non-nil *Application is enough: the ctx==nil guard is the
	// first statement and returns before any field is read.
	application := &Application{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if err := application.InitiateKeyUpdate(nil, 0); err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("InitiateKeyUpdate(nil ctx) err = %v, want non-nil containing \"nil context\" (:41)", err)
	}
}
