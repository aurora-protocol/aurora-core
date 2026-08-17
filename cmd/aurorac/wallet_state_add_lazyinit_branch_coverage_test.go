package main

// Adversarial white-box coverage for the count-0 nil-field lazy-init guard in
// provisioningWalletState.Add. Add begins with a nil-receiver guard and an
// argument-validity guard, and then initializes the reservations map when it is
// nil before recording the new entry.
//
//   - wallet_state.go:137 (*provisioningWalletState).Add
//     state.reservations == nil -> state.reservations = make(map[string]uint64)
//     (fires after the nil-receiver guard at :131 and the spentHintKey / expiry
//     validity guard at :134, before the duplicate-key guard at :141, the
//     entry-count guard at :143, and the entry append at :145).
//
// The existing wallet-state nil-safety test covers the nil-receiver guard at
// :131 (Add on a nil state). It never drives Add on a non-nil state whose
// reservations map is still nil, so the :137 nil-field lazy-init branch stayed
// count-0 even though it is plainly reachable by Adding a valid reservation
// to a zero-value provisioningWalletState (whose reservations map is nil).
//
// Proof technique (nil-field lazy-init): construct a zero-value
// provisioningWalletState (reservations == nil), Add a valid reservation
// (a spentHintKey of exactly provisioningWalletSpentHintKeyBytes and a non-zero
// expiry, so the :134 validity guard passes), and assert the map is non-nil
// afterward with the entry recorded. The map was nil on input and :137 is the
// only site in Add that allocates it, so a non-nil map uniquely proves the
// :137 lazy-init ran; the recorded entry confirms the full Add path reached
// the append at :145.
//
// No context is involved (Add takes none), so there is no SA1012 surface. No
// network, no goroutine, no file IO — Add only touches the in-memory map.
// In-package (package main) because provisioningWalletState, Add, and the
// reservations field are unexported. This file has no build constraint so it
// runs on every platform (Add is defined in the build-tag-free wallet_state.go).
//
// This test file adds only a TestXxx entry point and references existing
// unexported in-package symbols, so it adds no U1000 surface.

import (
	"testing"
)

func TestProvisioningWalletStateAddReservationsLazyInit(t *testing.T) {
	// 137: a zero-value provisioningWalletState has reservations == nil, so the
	// :137 lazy-init branch runs and makes the map before recording the entry.
	// A valid-length spentHintKey and a non-zero expiry pass the :134 validity
	// guard. The proof is that state.reservations is non-nil afterward and the
	// entry is recorded: it was nil on input and :137 is the only site in Add
	// that allocates the map.
	state := &provisioningWalletState{}
	key := make([]byte, provisioningWalletSpentHintKeyBytes)
	if err := state.Add(key, 1); err != nil {
		t.Fatalf("Add err = %v, want nil (valid key + non-zero expiry)", err)
	}
	if state.reservations == nil {
		t.Fatal("Add left reservations = nil, want non-nil (:137 lazy-init should make the map)")
	}
	if got, ok := state.reservations[string(key)]; !ok || got != 1 {
		t.Fatalf("reservations[key] = (%d, ok=%v), want (1, true) (entry should be recorded after Add)", got, ok)
	}
}
