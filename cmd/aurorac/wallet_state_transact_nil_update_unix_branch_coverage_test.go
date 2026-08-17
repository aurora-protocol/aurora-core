//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

// Adversarial white-box coverage for the count-0 nil-argument guard in
// transactProvisioningWalletState (unix variant). transactProvisioningWalletState
// begins with a store guard, a time guard, and then a nil-update guard that
// returns a "required" error before any file is opened or locked.
//
//   - wallet_state_unix.go:38 transactProvisioningWalletState
//     update == nil -> "client: wallet state update is required" (fires after
//     the store guard at :32 and the time guard at :35, before the filepath.Dir
//     at :41, the openProvisioningWalletStateFile at :45, and the flock at :50).
//
// The existing cmd/aurorac tests only ever drive transactProvisioningWalletState
// through the production wallet-state path with a real update closure, so the
// nil-update branch stayed count-0 even though it is plainly reachable by
// passing a nil update.
//
// The windows variant of transactProvisioningWalletState (wallet_state_windows.go)
// is a stub that returns "persistent wallet state is unavailable on this
// platform" with NO update == nil guard, so this test carries the matching unix
// build constraint to assert against the unix variant's guard rather than the
// windows stub's different return (same discipline as the wallet/restricted
// nil-argument coverage). On the coverage floor (unix) this covers the real
// guard; on windows CI the file is excluded from the build.
//
// Proof: a store with non-empty path/lockPath passes the :32 store guard and a
// real time.Now() passes the :35 time guard, so a nil update reaches the :38
// guard, which returns before any file is opened or locked — the path/lockPath
// strings are never used, so no file IO occurs and the test is pure. No context
// is involved, so there is no SA1012 surface. In-package (package main) because
// transactProvisioningWalletState and the provisioningWalletStateStore fields
// are unexported.
//
// This test file adds only a TestXxx entry point and references existing
// unexported in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
	"time"
)

func TestTransactProvisioningWalletStateNilUpdateGuard(t *testing.T) {
	// 38: a transactProvisioningWalletState call with a nil update returns the
	// "update is required" error at the :38 guard, before any file IO. A store
	// with non-empty path/lockPath passes the :32 store guard and a valid now
	// passes the :35 time guard, so the :38 update == nil guard is reached. The
	// path/lockPath strings are arbitrary — the guard returns before they are
	// used — so no file is touched.
	store := &provisioningWalletStateStore{path: "/tmp/aurora-wallet-test", lockPath: "/tmp/aurora-wallet-test.lock"}
	err := transactProvisioningWalletState(store, time.Now(), nil)
	if err == nil {
		t.Fatal("transactProvisioningWalletState(nil update) err = nil, want non-nil (:38 should reject)")
	} else if !strings.Contains(err.Error(), "wallet state update is required") {
		t.Fatalf("transactProvisioningWalletState(nil update) err = %q, want substring \"wallet state update is required\" (:38)", err.Error())
	}
}
