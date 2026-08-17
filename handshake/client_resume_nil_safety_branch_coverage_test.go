package handshake

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across handshake/client_resume.go. Each guard exists so a caller that
// holds a nil *ClientHandshake / *deferredClientProofProvider — or passes a nil
// proof-result value to the zeroer — does not panic or proceed into the live
// proof-pumping / session-completion path: the method returns at its very first
// statement, before any field is dereferenced (h.mu, h.provider, p.requests,
// p.results, p.closed) or any context method is called (ctx.Err) or any channel
// is touched. The existing handshake tests only ever drive a fully-built
// ClientHandshake along the live Begin → Complete / Close path, so the nil guards
// stayed count-0 even though each is plainly reachable.
//
// These are nil-RECEIVER / nil-ARGUMENT guards. Complete and BuildProofs take a
// context and are driven with context.Background (never a nil context literal),
// so there is no SA1012 surface: the receiver==nil guard fires before the
// context is ever read (Complete's ctx==nil guard at :106 and the ctx.Err path
// at :109 are second statements and intentionally left uncovered). No network,
// no goroutine, no crypto — each call returns at the first statement. The test
// is in-package because deferredClientProofProvider, complete, close, and
// zeroClientProofResult are unexported.
//
//   - :103 (*ClientHandshake).Complete(ctx, admission, replay)  h == nil
//     -> nil, "handshake: nil client handshake" (ctx=Background; h==nil fires
//     before the ctx==nil guard at 106)
//   - :149 (*ClientHandshake).Close()                  h == nil -> nil
//   - :199 (*deferredClientProofProvider).BuildProofs(ctx, request)  p == nil
//     -> zero proofs, "handshake: deferred client proof provider is missing"
//     (UNEXPORTED receiver; ctx=Background; p==nil fires before the channel
//     selects at 204/212)
//   - :223 (*deferredClientProofProvider).complete(admission, replay)  p == nil
//     -> "handshake: deferred client proof provider is missing" (UNEXPORTED)
//   - :254 (*deferredClientProofProvider).close()      p == nil -> no-op return
//     (UNEXPORTED; void; proven by absence of panic via a recover wrapper)
//   - :276 zeroClientProofResult(value)               value == nil -> no-op
//     return (UNEXPORTED; void; no-panic proof)
//
// This test file adds only TestXxx entry points and uses existing exported
// (plus unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestClientHandshakeNilReceiverGuards(t *testing.T) {
	// 103/149: a nil *ClientHandshake returns at the first statement of Complete /
	// Close rather than dereferencing h.mu / h.provider. Complete is driven with
	// context.Background so the nil-receiver guard fires before the context is
	// read (no SA1012).
	var h *ClientHandshake
	ctx := context.Background()

	// 103: Complete returns "nil client handshake" and a nil session.
	session, err := h.Complete(ctx, protocol.AdmissionProof{}, protocol.ReplayProof{})
	if err == nil {
		t.Fatal("nil.Complete err = nil, want non-nil (:103 should reject)")
	} else if !strings.Contains(err.Error(), "nil client handshake") {
		t.Fatalf("nil.Complete err = %q, want substring \"nil client handshake\" (:103)", err.Error())
	}
	if session != nil {
		t.Fatalf("nil.Complete session = %v, want nil (:103)", session)
	}

	// 149: Close returns nil.
	if err := h.Close(); err != nil {
		t.Fatalf("nil.Close err = %v, want nil (:149 should return nil)", err)
	}
}

func TestDeferredClientProofProviderNilReceiverGuards(t *testing.T) {
	// 199/223/254: a nil *deferredClientProofProvider returns at the first
	// statement of BuildProofs / complete / close rather than dereferencing
	// p.requests / p.results / p.closed. BuildProofs is driven with
	// context.Background so the nil-receiver guard fires before the channel
	// selects (no SA1012). close is void; proven by absence of panic.
	var p *deferredClientProofProvider
	ctx := context.Background()

	// 199: BuildProofs returns "deferred client proof provider is missing".
	admission, replay, err := p.BuildProofs(ctx, ClientProofRequest{})
	if err == nil {
		t.Fatal("nil.BuildProofs err = nil, want non-nil (:199 should reject)")
	} else if !strings.Contains(err.Error(), "deferred client proof provider is missing") {
		t.Fatalf("nil.BuildProofs err = %q, want substring \"deferred client proof provider is missing\" (:199)", err.Error())
	}
	_ = admission // zero-value proofs are the expected return; nothing to assert.
	_ = replay

	// 223: complete returns "deferred client proof provider is missing".
	if err := p.complete(protocol.AdmissionProof{}, protocol.ReplayProof{}); err == nil {
		t.Fatal("nil.complete err = nil, want non-nil (:223 should reject)")
	} else if !strings.Contains(err.Error(), "deferred client proof provider is missing") {
		t.Fatalf("nil.complete err = %q, want substring \"deferred client proof provider is missing\" (:223)", err.Error())
	}

	// 254: close is void; proven by absence of panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.close panicked = %v, want no-op return (:254 should guard the nil receiver)", r)
			}
		}()
		p.close()
	}()
}

func TestZeroClientProofResultNilArgumentGuard(t *testing.T) {
	// 276: the unexported zeroer returns at its first statement when given a nil
	// value pointer, before iterating the value's fields. Void; the proof is that
	// the call completes without panicking (a panic surfaces as a test failure).
	zeroClientProofResult(nil)
}
