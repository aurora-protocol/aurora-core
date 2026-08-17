package packet

// Adversarial white-box coverage for the count-0 first-statement nil-field
// safety guard on the receiver packet-number marker. markPacketNumberKeyLocked
// begins with `if r.windows == nil { return }` so a caller that drives a
// zero-value Receiver (no replay windows configured) does not proceed into
// the window lookup / creation path or dereference the nil map. The existing
// packet tests only ever drive a Receiver constructed via the production
// constructor (which initializes r.windows), so the nil-field guard stayed
// count-0 even though it is plainly reachable with a zero-value receiver.
//
//   - receiver.go:324 (*Receiver).markPacketNumberKeyLocked(key)
//     r.windows == nil -> void no-op return (fires before
//     r.windows[key.Space] / the replayWindow creation at :327). The proof
//     that the :324 early-return ran (rather than the :327 window-creation
//     path) is that r.windows is still nil after the call: a non-nil map with
//     a missing Space would fall through to :327 and create a window, so a
//     nil map afterward confirms the guard returned at the first statement.
//
// markPacketNumberKeyLocked carries the "Locked" suffix (the caller is
// expected to hold r.mu), but the guard returns at the very first statement
// before any shared state is touched, so a zero-value *Receiver with no lock
// held is safe in a single-goroutine test. This is a nil-FIELD first-statement
// guard (on a field of the receiver). No context is involved, so there is no
// SA1012 surface. No network, no goroutine, no real packet — the guard returns
// before the map is read, so the test is pure. The test is in-package
// (package packet) because markPacketNumberKeyLocked and receiverPacketNumberKey
// are unexported.
//
// This test file adds only a TestXxx entry point and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import "testing"

func TestReceiverMarkPacketNumberKeyLockedNilWindowsGuard(t *testing.T) {
	// 324: a zero-value *Receiver has windows == nil, so the first-statement
	// guard returns before r.windows[key.Space] / the replayWindow creation.
	// The proof that the :324 early-return ran (not the :327 window-creation
	// path) is that r.windows is still nil afterward: a non-nil map with a
	// missing Space would fall through to :327 and create a window.
	r := &Receiver{}
	r.markPacketNumberKeyLocked(receiverPacketNumberKey{})
	if r.windows != nil {
		t.Fatalf("markPacketNumberKeyLocked left r.windows = %v, want nil (:324 should return before window creation)", r.windows)
	}
}
