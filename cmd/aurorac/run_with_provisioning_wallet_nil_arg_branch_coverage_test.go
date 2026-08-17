package main

// Adversarial white-box coverage for the two count-0 first-statement
// nil-argument safety guards at the top of runWithProvisioningWallet. The
// function begins with two consecutive nil-argument guards so a caller that
// passes a nil wallet reservation / a nil wallet attempt does not proceed
// into the carrier-recovery loop (which dereferences reserve/attempt). The
// existing cmd/aurorac tests only ever drive runWithProvisioningWallet via the
// production CLI entry points with a populated reservation and attempt, so
// the nil-argument guards stayed count-0 even though each is plainly
// reachable.
//
//   - main.go:515 runWithProvisioningWallet(ctx, policy, reserve, attempt)
//     reserve == nil -> "client: wallet reservation is required" (fires before
//     the attempt == nil guard at :518, so a nil reserve short-circuits both
//     guards).
//   - main.go:518 runWithProvisioningWallet(ctx, policy, reserve, attempt)
//     attempt == nil -> "client: wallet attempt is required" (fires before
//     runWithCarrierRecovery, which is the first site that would dereference
//     reserve). Covering :518 requires a non-nil reserve so the :515 guard
//     does not short-circuit; the dummy reserve is never invoked because the
//     :518 guard returns before runWithCarrierRecovery.
//
// These are nil-ARGUMENT first-statement guards. The function takes a context,
// but neither exercised guard is the ctx==nil guard (runWithProvisioningWallet
// has no ctx==nil guard of its own), so the test passes context.Background() and
// there is no SA1012 surface. No network, no goroutine, no wallet I/O — each
// guard returns before runWithCarrierRecovery (the only site that calls
// reserve / attempt), so the dummy reserve is never invoked and the test is
// pure. The test is in-package (package main) because runWithProvisioningWallet
// and the provisioningWalletReservation / provisioningWalletAttempt /
// carrierRecoveryPolicy types are unexported.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestRunWithProvisioningWalletNilReserveGuard(t *testing.T) {
	// 515: a nil reserve fires the first-statement guard before the :518
	// attempt == nil guard, so passing nil for both arguments still reaches
	// :515 and short-circuits. The "wallet reservation is required" message
	// distinguishes the nil-reserve path from a non-nil reserve that proceeds
	// to :518.
	err := runWithProvisioningWallet(context.Background(), carrierRecoveryPolicy{}, nil, nil)
	if err == nil {
		t.Fatal("runWithProvisioningWallet(nil reserve) err = nil, want non-nil (:515 should reject)")
	} else if !strings.Contains(err.Error(), "wallet reservation is required") {
		t.Fatalf("runWithProvisioningWallet(nil reserve) err = %q, want substring \"wallet reservation is required\" (:515)", err.Error())
	}
}

func TestRunWithProvisioningWalletNilAttemptGuard(t *testing.T) {
	// 518: a non-nil reserve passes the :515 guard, then a nil attempt fires
	// the :518 guard before runWithCarrierRecovery. The dummy reserve is never
	// invoked because the :518 guard returns first, so it only needs to be
	// non-nil and type-correct. The "wallet attempt is required" message
	// distinguishes the nil-attempt path from a non-nil attempt that proceeds
	// into the carrier-recovery loop.
	nonNilReserve := provisioningWalletReservation(func(time.Time) (client.NativeProvisioningReservation, error) {
		return client.NativeProvisioningReservation{}, nil
	})
	err := runWithProvisioningWallet(context.Background(), carrierRecoveryPolicy{}, nonNilReserve, nil)
	if err == nil {
		t.Fatal("runWithProvisioningWallet(nil attempt) err = nil, want non-nil (:518 should reject)")
	} else if !strings.Contains(err.Error(), "wallet attempt is required") {
		t.Fatalf("runWithProvisioningWallet(nil attempt) err = %q, want substring \"wallet attempt is required\" (:518)", err.Error())
	}
}
