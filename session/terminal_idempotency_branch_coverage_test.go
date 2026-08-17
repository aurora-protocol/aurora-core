package session

// Adversarial white-box coverage for two count-0 `a.terminal != nil`
// idempotency guards that short-circuit an operation invoked on an
// already-terminated Application. Each guard returns the recorded terminal
// error at the first terminal check inside the method, before any real
// packet / key-update work runs. The existing session tests only ever drive
// these methods on a live (non-terminal) Application and terminate it once,
// so the `!= nil` branch on a pre-terminated Application stayed count-0 even
// though each is plainly reachable by terminating the Application first.
//
//   - application.go:264 (*Application).TryNextPacket()
//     a.terminal != nil -> (nil, a.terminal) (fires after the a == nil guard at
//     :259 and a.mu.Lock at :262, before the `len(a.queue) == 0` -> ErrNoPacket
//     path at :267).
//   - key_update.go:54 (*Application).InitiateKeyUpdate(ctx, reason)
//     a.terminal != nil -> a.terminal (fires after the ctx == nil guard at
//     :41, the reason range check at :44, ctx.Err() at :47, writeUpdateMu.Lock
//     at :50, and a.mu.Lock at :53, before the pendingWriteUpdate /
//     backpressure path at :59).
//
// Proof technique (matches the terminateLocked idempotency proof): set
// a.terminal to a distinct sentinel error and assert the method returns that
// exact error unchanged. The fall-through paths return different sentinels
// (ErrNoPacket for TryNextPacket, ErrBackpressure / a ctx error for
// InitiateKeyUpdate), so a return of the distinct sentinel uniquely
// identifies the `a.terminal != nil` guard.
//
// Neither exercised guard is a `ctx == nil` guard (each method's own ctx==nil
// guard is earlier and already covered), so the test passes
// context.Background() and there is no SA1012 surface. No network, no
// goroutine, no real packet, no real key update — each guard returns before
// the block / reason is dereferenced, so the test is pure. The a.mu /
// writeUpdateMu zero-value sync.Mutexes are valid unlocked mutexes, so
// locking them on a minimal &Application{terminal: sentinel} is safe in a
// single-goroutine test. In-package (package session) because queueBlock-style
// internals and the terminal field are unexported.
//
// This test file adds only TestXxx entry points and uses existing exported /
// unexported in-package symbols (ErrClosed is referenced only for context), so
// it adds no U1000 surface.

import (
	"context"
	"errors"
	"testing"
)

func TestApplicationTryNextPacketTerminalGuard(t *testing.T) {
	// 264: a TryNextPacket call on a pre-terminated Application returns the
	// recorded terminal error at the first terminal check, before the
	// empty-queue (ErrNoPacket) path. A distinct sentinel distinguishes the
	// :264 guard from the :267 fall-through (which returns ErrNoPacket).
	sentinel := errors.New("session-test: try-next-packet terminal")
	a := &Application{terminal: sentinel}
	pkt, err := a.TryNextPacket()
	if err != sentinel {
		t.Fatalf("TryNextPacket() err = %v, want sentinel (:264 should return a.terminal)", err)
	}
	if pkt != nil {
		t.Fatalf("TryNextPacket() pkt = %v, want nil (:264 returns a nil packet)", pkt)
	}
}

func TestApplicationInitiateKeyUpdateTerminalGuard(t *testing.T) {
	// 54: an InitiateKeyUpdate call on a pre-terminated Application returns
	// the recorded terminal error at the first terminal check, before the
	// pendingWriteUpdate / backpressure path. A distinct sentinel distinguishes
	// the :54 guard from the fall-through (ErrBackpressure / a ctx error).
	sentinel := errors.New("session-test: initiate-key-update terminal")
	a := &Application{terminal: sentinel}
	err := a.InitiateKeyUpdate(context.Background(), 0)
	if err != sentinel {
		t.Fatalf("InitiateKeyUpdate() err = %v, want sentinel (:54 should return a.terminal)", err)
	}
}
