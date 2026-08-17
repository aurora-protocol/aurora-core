//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

// Adversarial white-box coverage for the two count-0 first-statement
// nil-argument safety guards in the unix build-tagged cmd/aurorac helpers.
// Each guard exists so a caller that passes a nil wallet source / a nil
// os.FileInfo does not proceed into the live wallet-reservation / restricted
// file-owner path: the function returns at its very first statement, before
// any field is dereferenced (store.Transact -> store.path / store.lockPath) or
// any type assertion runs (info.Sys().(*syscall.Stat_t)). The existing
// cmd/aurorac tests only ever drive a populated wallet source along the
// reservation path and a populated os.FileInfo along the owner-validation
// path, so the nil guards stayed count-0 even though each is plainly
// reachable.
//
//   - wallet_state_unix.go:75 (*provisioningWalletStateStore).Reserve
//     (wallet provisioningWalletSource, ...)  wallet == nil ->
//     (zero NativeProvisioningReservation{}, client.ErrNoUsableNativeProvisioning)
//     (fires before store.Transact / store.path / store.lockPath; the sentinel
//     ErrNoUsableNativeProvisioning distinguishes the nil-argument path from a
//     non-nil wallet that proceeds into Transact and hits the invalid-time /
//     update errors). A zero-value provisioningWalletStateStore is safe because
//     the guard returns before store is read.
//   - restricted_file_owner_unix.go:12 validateRestrictedOwnerFileOwner
//     (info os.FileInfo)  info == nil -> "restricted file owner is unavailable"
//     (fires before info.Sys().(*syscall.Stat_t); the "unavailable" message
//     distinguishes the nil-argument path from a non-nil info whose Sys() is not
//     a *syscall.Stat_t).
//
// These are nil-ARGUMENT first-statement guards on unexported helpers, so the
// test is in-package (package main). No context is involved, so there is no
// SA1012 surface. No filesystem, no real wallet, no real file descriptor —
// each guard returns before the platform-specific path runs, so the test is
// pure.
//
// The guards exist only in the unix build-tagged source variants; the windows
// variants (wallet_state_windows.go Reserve stub, restricted_file_owner_windows.go
// validateRestrictedOwnerFileOwner stub) carry no nil guard and return an
// unconditional / nil result. This test file therefore carries the matching
// unix build tag so it is active on exactly the platforms whose source has
// the guard (linux/darwin/bsd, which the coverage floor measures) and is
// excluded on windows (whose stubs have nothing to cover). It is not run on
// the windows CI test job.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestProvisioningWalletStateStoreReserveNilArgumentGuard(t *testing.T) {
	// 75: Reserve(nil wallet) returns at the first statement before
	// store.Transact. A zero-value provisioningWalletStateStore is safe because
	// the guard returns before store.path / store.lockPath are read. The
	// sentinel client.ErrNoUsableNativeProvisioning distinguishes the
	// nil-argument path from a non-nil wallet that proceeds into Transact.
	store := &provisioningWalletStateStore{}
	reservation, err := store.Reserve(nil, [provisioningWalletSourceDigestBytes]byte{}, time.Time{})
	if err != client.ErrNoUsableNativeProvisioning {
		t.Fatalf("Reserve(nil) err = %v, want client.ErrNoUsableNativeProvisioning (:75)", err)
	}
	// The guard returns the zero reservation; assert it carries no reservation
	// via its AccessHintExpiryUnix scalar (0 means no reservation was built)
	// rather than == on the whole struct, which may contain non-comparable
	// slice fields.
	if reservation.AccessHintExpiryUnix != 0 {
		t.Fatalf("Reserve(nil) reservation.AccessHintExpiryUnix = %d, want 0 (:75)", reservation.AccessHintExpiryUnix)
	}
}

func TestValidateRestrictedOwnerFileOwnerNilArgumentGuard(t *testing.T) {
	// 12: validateRestrictedOwnerFileOwner(nil) returns at the first statement
	// before info.Sys().(*syscall.Stat_t). The "unavailable" message
	// distinguishes the nil-argument path from a non-nil info whose Sys() is
	// not a *syscall.Stat_t.
	if err := validateRestrictedOwnerFileOwner(nil); err == nil {
		t.Fatal("validateRestrictedOwnerFileOwner(nil) err = nil, want non-nil (:12 should reject)")
	} else if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("validateRestrictedOwnerFileOwner(nil) err = %q, want substring \"unavailable\" (:12)", err.Error())
	}
}
