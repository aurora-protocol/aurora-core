package main

// Adversarial white-box coverage for the count-0 validation guards of
// provisioningWalletState.Encode (cmd/aurorac/wallet_state.go:92) and
// provisioningWalletState.Add (:130). Both functions guard against over-size /
// malformed wallet state; existing tests only exercise the happy path, so the
// four bodies below are COUNT 0 on main.
//
// Coverage targets (baseline measured on main; all bodies COUNT 0):
//   - wallet_state.go:96.69,98.3 0   — Encode: reservations > max -> "entry count is invalid"
//   - wallet_state.go:101.73,103.4 0 — Encode: a reservation with a wrong-length key / zero expiry
//                                      -> "entry is invalid"
//   - wallet_state.go:134.81,136.3 0— Add: wrong-length key / zero expiry -> "reservation is invalid"
//   - wallet_state.go:144.70,146.3 0— Add: reservations already at max -> "entry count is invalid"
//
// :96 and :144 are the DoS-protection count-boundary guards. Add() caps growth at
// maximumProvisioningWalletStateEntries (:144), so Encode's :96 (> max) is only
// reachable by mutating the in-package reservations map past the cap directly;
// the :96 subtest does exactly that. Encode's :120 (encoder.Bytes err) is
// dead-by-design (valid writes never error) and :123 (encoded > 4 MiB) is
// dominated by :96 (<=65536 entries of 56 bytes = ~3.5 MiB < 4 MiB) — neither is
// a pillar.
//
// Each subtest perturbs exactly one thing so the target guard is the first to
// fail; error strings are asserted per subtest (self-validating), and the
// per-line coverage flip is the rigorous proof. Encode/Add are unexported
// methods, so this is an in-package (package main) test. No filesystem, no
// store, no goroutines. One TestXxx with four t.Run subtests; references
// in-package constants + stdlib bytes/strconv/strings/testing -> no U1000
// surface.

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// fillWalletReservations inserts n arbitrary-key reservations directly into
// state's in-package map, bypassing Add()'s per-entry validation and count cap.
// Used to drive the Encode :96 (n > max) and Add :144 (n == max) boundary guards.
func fillWalletReservations(state *provisioningWalletState, n int) {
	for i := 0; i < n; i++ {
		state.reservations[strconv.Itoa(i)] = 1
	}
}

func TestProvisioningWalletStateEncodeAddGuards(t *testing.T) {
	// :96 — Encode rejects a state whose reservation count exceeds the cap.
	// Add() cannot produce such a state (it caps at :144), so the in-package
	// map is filled past the cap directly; :96 fires before any entry is read.
	t.Run("encode count exceeds max", func(t *testing.T) {
		state := newProvisioningWalletState()
		fillWalletReservations(state, maximumProvisioningWalletStateEntries+1)
		if _, err := state.Encode(); err == nil || !strings.Contains(err.Error(), "entry count is invalid") {
			t.Fatalf("Encode() err = %v, want non-nil containing \"entry count is invalid\" (:96)", err)
		}
	})

	// :101 — Encode rejects a reservation whose key is the wrong length (the
	// in-package map holds a short key; :96 passes since count is 1 <= max, then
	// the per-entry loop trips the length check).
	t.Run("encode entry invalid", func(t *testing.T) {
		state := newProvisioningWalletState()
		state.reservations["short"] = 1 // key len 5 != 48
		if _, err := state.Encode(); err == nil || !strings.Contains(err.Error(), "entry is invalid") {
			t.Fatalf("Encode() err = %v, want non-nil containing \"entry is invalid\" (:101)", err)
		}
	})

	// :134 — Add rejects a wrong-length key before touching the map.
	t.Run("add reservation invalid", func(t *testing.T) {
		state := newProvisioningWalletState()
		if err := state.Add(bytes.Repeat([]byte{0x01}, 4), 1); err == nil || !strings.Contains(err.Error(), "reservation is invalid") {
			t.Fatalf("Add() err = %v, want non-nil containing \"reservation is invalid\" (:134)", err)
		}
	})

	// :144 — Add refuses to grow the map once it is at the cap. The map is
	// pre-filled to exactly maximumProvisioningWalletStateEntries (via the
	// in-package bypass, since Add itself caps growth); the added key is a valid,
	// novel 48-byte key so :134 and the :141 exists-check both pass first.
	t.Run("add at count cap", func(t *testing.T) {
		state := newProvisioningWalletState()
		fillWalletReservations(state, maximumProvisioningWalletStateEntries)
		novelKey := bytes.Repeat([]byte{0xAB}, provisioningWalletSpentHintKeyBytes)
		if err := state.Add(novelKey, 1); err == nil || !strings.Contains(err.Error(), "entry count is invalid") {
			t.Fatalf("Add() err = %v, want non-nil containing \"entry count is invalid\" (:144)", err)
		}
	})
}
