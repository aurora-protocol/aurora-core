//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

// Adversarial white-box coverage for the count-0 nil-receiver clause of the
// compound guard in transactProvisioningWalletState (unix variant).
//
//   - wallet_state_unix.go:32 transactProvisioningWalletState
//     if store == nil || store.path == "" || store.lockPath == "" -> "client:
//     wallet state store is unavailable" (:33). The FIRST clause (store == nil)
//     is the nil-safety clause: it short-circuits the compound guard before
//     store.path is dereferenced (nil-receiver panic). The path == "" / lockPath
//     == "" clauses are empty-path VALIDATION, not panic-prevention, so they are
//     off-pillar; this test targets the store == nil nil-safety clause.
//
// The existing cmd/aurorac tests only ever drive transactProvisioningWalletState
// with a non-nil store (the production wallet-state path, plus the sibling
// wallet_state_transact_nil_update_unix_branch_coverage_test.go which passes a
// non-nil store with non-empty path/lockPath to reach the :38 update == nil
// guard). So the :32 guard body (the :33 return) stayed count-0 even though the
// nil-receiver clause is plainly reachable by passing a nil store — measured:
// wallet_state_unix.go:31.141,32.62 1 35 (condition evaluated 35x) but
// :32.62,34.3 1 0 (the body, COUNT 0).
//
// The windows variant (wallet_state_windows.go) is a stub with NO :32 guard, so
// this test carries the matching unix build constraint to assert against the
// unix variant's guard rather than the windows stub's different return (same
// discipline as the sibling nil-update test). On the coverage floor (unix) this
// covers the real guard; on windows CI the file is excluded from the build.
//
// Proof: transactProvisioningWalletState(nil, time.Now(), noop) — store == nil
// short-circuits :32 before store.path is dereferenced; :33 returns the
// "unavailable" error before the :35 time guard, the :38 update guard, and the
// :41 filepath.Dir / :45 openProvisioningWalletStateFile / :50 flock. The now
// value and update closure are never evaluated (the guard returns at :33), so no
// file IO occurs and the test is pure. No context is involved, so there is no
// SA1012 surface. In-package (package main) because transactProvisioningWalletState
// is unexported.
//
// This test file adds only a TestXxx entry point and references existing
// unexported in-package (transactProvisioningWalletState, provisioningWalletState)
// symbols and the standard library strings / testing / time packages, so it adds
// no U1000 surface.

import (
	"strings"
	"testing"
	"time"
)

func TestTransactProvisioningWalletStateNilStoreGuard(t *testing.T) {
	// 32 (nil-receiver): store == nil short-circuits the compound :32 guard
	// before store.path is dereferenced (nil-receiver panic); :33 returns
	// "wallet state store is unavailable". The update closure is never reached
	// (:38 is past :32), so a noop is safe; the now value is never evaluated.
	err := transactProvisioningWalletState(nil, time.Now(), func(*provisioningWalletState) error { return nil })
	if err == nil {
		t.Fatal("transactProvisioningWalletState(nil store) err = nil, want non-nil (:33 should reject)")
	}
	if !strings.Contains(err.Error(), "wallet state store is unavailable") {
		t.Fatalf("nil-store err = %q, want substring \"wallet state store is unavailable\" (:33)", err.Error())
	}
}
