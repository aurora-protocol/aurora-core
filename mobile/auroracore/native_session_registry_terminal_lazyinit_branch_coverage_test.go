package main

// Adversarial white-box coverage for the count-0 nil-field lazy-init guard in
// nativeSessionRegistry.rememberTerminalLocked. rememberTerminalLocked begins
// with a zero-handle guard and a nil-err default, and then initializes the
// terminals map when it is nil before recording the terminal error.
//
//   - session.go:669 (*nativeSessionRegistry).rememberTerminalLocked
//     r.terminals == nil -> r.terminals = make(map[uint64]error)
//     (fires after the handle == 0 guard at :663 and the err == nil default at
//     :666, before the duplicate-handle check at :672, the capacity check at
//     :676, the terminalOrder append at :683, and the terminals[handle] record
//     at :684).
//
// The existing mobile/auroracore tests drive rememberTerminalLocked only on a
// registry that was first initialized via the normal session-allocation path
// (which already populates terminals), so :669 is reached with terminals
// non-nil and the :669 lazy-init branch body stayed count-0 (the condition was
// evaluated but the make() body never ran) even though it is plainly reachable
// on a zero-value nativeSessionRegistry whose terminals map is still nil.
//
// Proof technique (nil-field lazy-init): construct a zero-value
// nativeSessionRegistry (terminals == nil), then call rememberTerminalLocked
// with a non-zero handle (so the :663 handle == 0 guard passes) and a nil err
// (so :666 sets err = session.ErrClosed). The :669 guard sees terminals == nil
// and makes the map. len(terminalOrder) == 0 != maximumNativeSessions (64), so
// the :676 capacity branch is skipped (no nil-slice index), the handle is
// appended to terminalOrder at :683 (append to a nil slice is safe), and
// terminals[handle] = err is recorded at :684. The proof that the :669 branch
// ran is that r.terminals is non-nil afterward: it was nil on input and :670 is
// the only site in rememberTerminalLocked that allocates it, so a non-nil map
// uniquely identifies the :669 lazy-init; the recorded terminals[1] ==
// session.ErrClosed confirms the full path reached :684.
//
// rememberTerminalLocked is an unexported "Locked"-suffix method (the caller
// holds r.mu) but does not acquire the lock itself, so calling it directly in a
// single-goroutine test is safe (no deadlock, no race). The method is pure Go
// (it only manipulates maps and slices), so no cgo / native FFI surface is
// exercised and the test does not touch the C runtime. No context is involved,
// so there is no SA1012 surface.
//
// This test file adds only a TestXxx entry point and references existing
// unexported in-package (nativeSessionRegistry, rememberTerminalLocked) symbols
// and the exported session.ErrClosed value, so it adds no U1000 surface.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/session"
)

func TestNativeSessionRegistryRememberTerminalLockedTerminalsLazyInit(t *testing.T) {
	// 669: a zero-value nativeSessionRegistry has terminals == nil, so the :669
	// lazy-init branch runs and makes the map before recording the terminal. A
	// non-zero handle (1) passes the :663 guard; a nil err makes :666 set
	// err = session.ErrClosed. len(terminalOrder) == 0 != maximumNativeSessions
	// (64), so the :676 capacity branch is skipped and the handle is appended at
	// :683 and recorded at :684. The proof is that r.terminals is non-nil
	// afterward (it was nil and :670 is the only allocation site) and
	// terminals[1] == session.ErrClosed.
	r := &nativeSessionRegistry{}
	r.rememberTerminalLocked(1, nil)
	if r.terminals == nil {
		t.Fatal("rememberTerminalLocked left terminals = nil, want non-nil (:669 lazy-init should make the map)")
	}
	if got, ok := r.terminals[1]; !ok || got != session.ErrClosed {
		t.Fatalf("terminals[1] = (%v, ok=%v), want (session.ErrClosed, true) (:666 default + :684 record)", got, ok)
	}
}
