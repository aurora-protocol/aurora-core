package main

// Adversarial white-box coverage for the count-0 nil-context guard of
// nativeSessionRegistry.nextLocalPacket (mobile/auroracore/session.go:482). The
// method's very first statement is `if ctx == nil { return ... }`; every existing
// caller passes a real context, so the nil-context body is COUNT 0 on main.
//
// Coverage target (baseline measured on main; body COUNT 0):
//   - session.go:483.16,485.3 0 — nextLocalPacket ctx==nil
//     -> "auroracore: native local packet context is nil"
//
// The guard is the first statement, so nil ctx returns before the receiver `r`
// is ever read — a non-nil zero-value &nativeSessionRegistry{} passes nothing
// and is never dereferenced. Error string is asserted (self-validating); the
// per-line coverage flip is the rigorous proof.
//
// This is a plain Go method (NOT a //export cgo wrapper) — in-process testable,
// same as the #340 nil-receiver and #341 lifecycle guards. SA1012 (nil Context
// literal) is suppressed per the established codebase convention
// (//lint:ignore SA1012 Verifies the public API's explicit nil-context
// rejection.) on the intentional nil-context call (CI-proven on
// #264/#346/#349/#350/#353/#354). No goroutine, no network, no cgo. One TestXxx;
// imports strings/testing -> no U1000 surface.

import (
	"strings"
	"testing"
)

func TestNextLocalPacketRejectsNilContext(t *testing.T) {
	// :483 — nextLocalPacket. The receiver is a non-nil zero-value
	// &nativeSessionRegistry{} but is never read (ctx==nil returns first).
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	if _, err := (&nativeSessionRegistry{}).nextLocalPacket(nil, 0); err == nil || !strings.Contains(err.Error(), "native local packet context is nil") {
		t.Fatalf("nextLocalPacket(nil ctx) err = %v, want non-nil containing \"native local packet context is nil\" (:483)", err)
	}
}
