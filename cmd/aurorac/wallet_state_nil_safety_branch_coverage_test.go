package main

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across cmd/aurorac/wallet_state.go. Each guard exists so a caller that
// holds a nil *provisioningWalletState does not panic or proceed into the
// encode / add / count / digest-bind path: the method returns at its very first
// statement, before any field is dereferenced (state.reservations,
// state.hasSourceDigest, state.sourceDigest). The existing aurorac tests only
// ever drive a fully-built wallet state along the live parse → reserve → encode
// path, so the nil-receiver guards stayed count-0 even though each is plainly
// reachable.
//
// These are nil-RECEIVER guards on the unexported *provisioningWalletState
// type, so the test is in-package (package main). None of the guarded methods
// take a context, so there is no SA1012 surface. No network, no goroutine, no
// crypto — each call returns at the first statement. The compound guards
// (:152 Contains, :166 prune) are intentionally left uncovered — they are not
// simple first-statement nil-receiver guards.
//
//   - :93  Encode()                  state == nil
//     -> nil, "client: wallet state is unavailable"
//   - :131 Add(spentHintKey, expiry)  state == nil
//     -> "client: wallet state is unavailable" (the state==nil guard fires
//     before the spentHintKey/expiry validation at 134)
//   - :160 Len()                      state == nil -> 0
//   - :178 bindSourceDigest(digest)   state == nil -> no-op return
//     (void; proven by absence of panic via a recover wrapper; the state==nil
//     guard fires before the digest-comparison / hasSourceDigest read at 181)
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestProvisioningWalletStateNilReceiverGuards(t *testing.T) {
	// 93/131/160/178: a nil *provisioningWalletState returns at the first
	// statement of Encode / Add / Len / bindSourceDigest rather than
	// dereferencing state.reservations / state.hasSourceDigest /
	// state.sourceDigest.
	var state *provisioningWalletState

	// 93: Encode returns "wallet state is unavailable" and a nil byte slice.
	encoded, err := state.Encode()
	if err == nil {
		t.Fatal("nil.Encode err = nil, want non-nil (:93 should reject)")
	} else if !strings.Contains(err.Error(), "wallet state is unavailable") {
		t.Fatalf("nil.Encode err = %q, want substring \"wallet state is unavailable\" (:93)", err.Error())
	}
	if encoded != nil {
		t.Fatalf("nil.Encode encoded = %v, want nil (:93)", encoded)
	}

	// 131: Add returns "wallet state is unavailable" (the state==nil guard fires
	// before the spentHintKey/expiry validation at 134).
	if err := state.Add(nil, 0); err == nil {
		t.Fatal("nil.Add err = nil, want non-nil (:131 should reject)")
	} else if !strings.Contains(err.Error(), "wallet state is unavailable") {
		t.Fatalf("nil.Add err = %q, want substring \"wallet state is unavailable\" (:131)", err.Error())
	}

	// 160: Len returns 0.
	if n := state.Len(); n != 0 {
		t.Fatalf("nil.Len = %d, want 0 (:160)", n)
	}

	// 178: bindSourceDigest is void; proven by absence of panic. The state==nil
	// guard fires before the digest-comparison / hasSourceDigest read at 181, so
	// a zero digest array is safe.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.bindSourceDigest panicked = %v, want no-op return (:178 should guard the nil receiver)", r)
			}
		}()
		state.bindSourceDigest([provisioningWalletSourceDigestBytes]byte{})
	}()
}