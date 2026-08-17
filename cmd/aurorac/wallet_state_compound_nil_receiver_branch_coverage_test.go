package main

// Adversarial white-box coverage for the two count-0 COMPOUND nil-receiver
// guards in cmd/aurorac/wallet_state.go that the existing
// wallet_state_nil_safety_branch_coverage_test.go intentionally deferred. That
// test's pillar was simple first-statement nil-receiver guards; :152 Contains
// and :167 prune are compound `state == nil || <other-clause>` guards, so it
// left them count-0 (see its header comment). This file covers them.
//
//   - wallet_state.go:152 (*provisioningWalletState).Contains
//     state == nil || len(spentHintKey) != 48 -> false (the first clause
//     short-circuits before state.reservations is read at :155).
//   - wallet_state.go:167 (*provisioningWalletState).prune
//     state == nil || now.IsZero() || now.Unix() < 0 -> no-op return (the first
//     clause short-circuits before the state.reservations range at :170).
//
// Proof: a nil *provisioningWalletState with a valid second arg isolates the
// state == nil clause (the other clauses are false), so the guard trips on the
// nil receiver alone and returns before any field deref.
//
//   - :152: (*provisioningWalletState)(nil).Contains(make([]byte, 48)) — the
//     48-byte key makes len(spentHintKey) != 48 false, so only state == nil is
//     true; :153 returns false before :155 reads state.reservations.
//   - :167: (*provisioningWalletState)(nil).prune(time.Now()) — a valid now makes
//     now.IsZero() and now.Unix() < 0 false, so only state == nil is true; :168
//     returns before :170 ranges state.reservations. prune is void, so the
//     nil-receiver safety is proven by the absence of panic (recover wrapper).
//
// No context is involved, so there is no SA1012 surface. No network, no goroutine,
// no crypto, no file IO — each guard returns at its first statement. In-package
// (package main) because provisioningWalletState, Contains, and prune are
// unexported.
//
// This test file adds only TestXxx entry points and references existing
// in-package (provisioningWalletState, provisioningWalletSpentHintKeyBytes)
// symbols and the standard library testing / time packages, so it adds no U1000
// surface.

import (
	"testing"
	"time"
)

func TestProvisioningWalletStateContainsNilReceiverGuard(t *testing.T) {
	// 152: a 48-byte key makes len(spentHintKey) != 48 false, so only state == nil
	// is true; :153 returns false before :155 reads state.reservations.
	var state *provisioningWalletState
	if state.Contains(make([]byte, provisioningWalletSpentHintKeyBytes)) {
		t.Fatal("nil.Contains returned true, want false (:153 should guard the nil receiver)")
	}
}

func TestProvisioningWalletStatePruneNilReceiverGuard(t *testing.T) {
	// 167: a valid now makes now.IsZero() and now.Unix() < 0 false, so only
	// state == nil is true; :168 returns before :170 ranges state.reservations.
	// prune is void, so the nil-receiver safety is proven by the absence of panic.
	var state *provisioningWalletState
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.prune panicked = %v, want no-op return (:167 should guard the nil receiver)", r)
			}
		}()
		state.prune(time.Now())
	}()
}
