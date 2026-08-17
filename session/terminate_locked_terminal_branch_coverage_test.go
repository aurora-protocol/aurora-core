package session

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guard on the application termination path. terminateLocked begins with
// `if a.terminal != nil { return }` so a second termination call on an
// Application that already carries a terminal error is an idempotent no-op
// rather than re-running the lifecycle-cancel / queue-destroy path. The
// existing session tests only ever drive terminateLocked once per Application
// (the first call sets a.terminal from nil), so the != nil branch stayed
// count-0 even though it is plainly reachable by terminating an already
// terminated Application.
//
//   - application.go:434 (*Application).terminateLocked(err error)
//     a.terminal != nil -> void no-op return (fires before the
//     `if err == nil { err = ErrClosed }` default / `a.terminal = err`
//     assignment / `a.lifecycleCancel()` / `a.stopDrainTimersLocked()` /
//     `a.queue` destroy loop). The proof that the :434 guard ran (rather than
//     the fall-through that would overwrite a.terminal) is that a.terminal is
//     unchanged after the call: passing a distinct non-nil error would, in the
//     fall-through path, set a.terminal to that error, so a.terminal still
//     equaling ErrClosed afterward confirms the guard returned at the first
//     statement.
//
// terminateLocked carries the "Locked" suffix (the caller is expected to hold
// a.mu), but the :434 guard returns at the very first statement before any
// shared state is touched, so a minimal &Application{terminal: ErrClosed} with
// no lock held is safe in a single-goroutine test. This is a != nil
// first-statement guard (the branch taken when the field is already non-nil).
// No context is involved, so there is no SA1012 surface. No network, no
// goroutine, no real packet — the guard returns before the lifecycle-cancel /
// queue path, so the test is pure. The test is in-package (package session)
// because terminateLocked and the terminal field are unexported.
//
// This test file adds only a TestXxx entry point and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"errors"
	"testing"
)

func TestApplicationTerminateLockedTerminalGuard(t *testing.T) {
	// 434: an Application whose terminal is already set returns at the first
	// statement of terminateLocked rather than overwriting a.terminal /
	// running the lifecycle-cancel path. The proof that the :434 guard ran
	// (not the fall-through that would set a.terminal = err) is that a.terminal
	// is still ErrClosed after passing a distinct non-nil error: the
	// fall-through would overwrite a.terminal with that error.
	a := &Application{terminal: ErrClosed}
	a.terminateLocked(errors.New("session-test: distinct terminal error"))
	if a.terminal != ErrClosed {
		t.Fatalf("terminateLocked overwrote a.terminal = %v, want ErrClosed (:434 should be an idempotent no-op)", a.terminal)
	}
}
