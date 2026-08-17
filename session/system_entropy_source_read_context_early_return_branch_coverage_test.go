package session

// Adversarial white-box branch coverage for the two count-0 early-return guards
// in systemEntropySource.ReadContext (session/entropy.go:36) that fire BEFORE the
// requests channel / broker goroutine is touched:
//
//	func (s systemEntropySource) ReadContext(ctx context.Context, p []byte) error {
//	    if ctx == nil { return ... "nil entropy context" }   // :37 (covered by nil_context_branch_coverage_test.go)
//	    if err := ctx.Err(); err != nil { return err }        // :40  <-- COUNT 0
//	    if len(p) == 0 { return nil }                         // :43  <-- COUNT 0
//	    requests := s.requests                               // :46 (broker path starts here)
//	    ...
//	}
//
// The existing nil_context_branch_coverage_test.go covers :37 (ctx == nil) but
// stops there. :40 (a pre-canceled context returns ctx.Err() before the broker
// is engaged) and :43 (an empty buffer is a no-op) are the next two early
// returns and stayed count 0. Both fire before :46, so a zero-valued
// systemEntropySource (requests == nil) is safe — no broker goroutine is started
// and no channel send/receive occurs. This makes both guards DETERMINISTIC
// (no timing, no concurrency, no flake surface), the same shape as the :37
// test but for ctx.Err()/empty-input instead of ctx == nil.
//
// The broker-path guards (:52 select send, :54 ctx.Done-during-send, :58-:70
// result receive/validate/copy, :71 ctx.Done-during-receive) are deliberately
// NOT covered here: they require a running runSystemEntropyBroker goroutine and
// are timing-dependent (the send/receive races with context cancellation),
// which would introduce flake risk for no determinism gain.
//
// systemEntropySource is unexported, so this is in-package. The per-line
// coverage flip (:40 0 -> 1, :43 0 -> 1) is the rigorous proof.

import (
	"context"
	"errors"
	"testing"
)

func TestSystemEntropySourceReadContextEarlyReturns(t *testing.T) {
	var s systemEntropySource

	// entropy.go:40 — a pre-canceled context returns ctx.Err() before the
	// requests channel is touched, so no broker goroutine is started.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.ReadContext(ctx, []byte{0x01})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadContext(canceled ctx) err = %v, want context.Canceled (:40)", err)
	}

	// entropy.go:43 — an empty buffer is a no-op: ReadContext returns nil
	// before the requests channel is touched. A live (non-canceled) context
	// passes :40 so :43 is the branch that fires.
	if err := s.ReadContext(context.Background(), nil); err != nil {
		t.Fatalf("ReadContext(empty p) err = %v, want nil (:43)", err)
	}
}
