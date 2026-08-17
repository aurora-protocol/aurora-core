package handshake

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across handshake/relay.go. Each guard exists so a caller that holds a
// nil *RelayHandshake — or passes a nil value to the unexported zeroers — does
// not panic or proceed into the live capsule-exchange / secret-erase path: the
// method returns at its very first statement, before any field is dereferenced
// (h.mu, h.terminal, h.driver, value.Extensions) or any context method is called.
// The existing handshake tests only ever drive a fully-built RelayHandshake
// along the live Begin → Finish / Close path and populated policy/prelude
// values along the relay capsule path, so the nil guards stayed count-0 even
// though each is plainly reachable.
//
// These are nil-RECEIVER / nil-ARGUMENT guards. Finish takes a context and is
// driven with context.Background (never a nil context literal), so there is no
// SA1012 surface: the h==nil guard fires before h.mu.Lock / the ctx==nil guard
// at :205 / contextError at :208 are ever reached. No network, no goroutine, no
// crypto — each call returns at the first statement. The test is in-package
// because zeroPolicyOffer and zeroCoverPrelude1 are unexported.
//
//   - :181 (*RelayHandshake).Close()                 h == nil -> nil
//   - :195 (*RelayHandshake).Finish(ctx, capsule, now)  h == nil
//     -> nil, nil, zero PolicyAccept, "handshake: nil relay handshake"
//     (ctx=Background; h==nil fires before h.mu.Lock at 198)
//   - :498 zeroPolicyOffer(value)                    value == nil -> no-op return
//     (UNEXPORTED; void; no-panic proof)
//   - :636 zeroCoverPrelude1(value)                 value == nil -> no-op return
//     (UNEXPORTED; void; no-panic proof)
//
// This test file adds only TestXxx entry points and uses existing exported
// (plus unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
)

func TestRelayHandshakeNilReceiverGuards(t *testing.T) {
	// 181/195: a nil *RelayHandshake returns at the first statement of Close /
	// Finish rather than dereferencing h.mu / h.terminal / h.driver. Finish is
	// driven with context.Background so the nil-receiver guard fires before
	// h.mu.Lock and the context is read (no SA1012).
	var h *RelayHandshake
	ctx := context.Background()

	// 181: Close returns nil.
	if err := h.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:181 should return nil)", err)
	}

	// 195: Finish returns "nil relay handshake" with nil session + zero accept.
	capsule2, application, accept, err := h.Finish(ctx, nil, 0)
	if err == nil {
		t.Fatal("nil.Finish err = nil, want non-nil (:195 should reject)")
	} else if !strings.Contains(err.Error(), "nil relay handshake") {
		t.Fatalf("nil.Finish err = %q, want substring \"nil relay handshake\" (:195)", err.Error())
	}
	if capsule2 != nil || application != nil {
		t.Fatalf("nil.Finish returns = (%v, %v), want (nil, nil) (:195)", capsule2, application)
	}
	_ = accept // zero-value PolicyAccept is the expected return; nothing to assert.
}

func TestRelayZeroerNilArgumentGuards(t *testing.T) {
	// 498/636: the two unexported zeroers return at their first statement when
	// given a nil value pointer, before iterating the value's fields. Each is
	// void; the proof is that the call completes without panicking (a panic
	// surfaces as a test failure).
	zeroPolicyOffer(nil)
	zeroCoverPrelude1(nil)
}