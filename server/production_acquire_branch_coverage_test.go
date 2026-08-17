package server

// Adversarial white-box coverage for the two count-0 branches on
// productionFirstHopLimiter.acquire in server/production.go: the nil-context
// rejection (217-219) and the cancelled-context short-circuit (220-222).
//
// acquire is the per-session admission gate wired into a production first-hop
// handler (handler.sessionAdmission = limiter.acquire). It runs on every
// incoming first-hop session, so its two early-exit arms must reject a
// misconfigured/empty context before the slot-channel send at 223 is ever
// reached:
//
//	func (l *productionFirstHopLimiter) acquire(ctx context.Context) (func(), error) {
//	    if ctx == nil {                                            // 217
//	        return nil, fmt.Errorf("server: production first-hop session context is required")
//	    }
//	    if err := ctx.Err(); err != nil {                          // 220
//	        return nil, err                                         // 221
//	    }
//	    select {
//	    case l.slots <- struct{}{}: ...                             // 224 — only reached with a live ctx
//	    }
//	}
//
//   - 217-219 — nil-context guard, FIRST statement. With a nil ctx the guard
//     returns before l.slots is touched, so a zero-valued receiver is safe
//     (the nil channel at 224 is never sent on). Reachable by a direct
//     in-package call; the existing production tests always drive acquire
//     transitively through a live handler with a real context, so this arm
//     stayed count-0 even though the gate is plainly reachable: a caller that
//     forgets to thread a context through hits it. Calling with a literal nil
//     context.Context triggers staticcheck SA1012; the codebase convention —
//     established across evidence/, transport/, server/production_test.go,
//     server/first_hop_nil_context_branch_coverage_test.go, handshake/, perf/,
//     and cmd/aurorac/ — is a //lint:ignore SA1012 directive immediately
//     before the call. It carries that directive below.
//   - 220-222 — ctx.Err() short-circuit. A non-nil but already-cancelled
//     context passes the :217 nil check but fails ctx.Err() != nil at 220,
//     returning the context's own error (context.Canceled) at 221 before the
//     slot send at 224. Reachable with a zero-valued receiver + a cancelled
//     context (the slots channel is never touched). The :220 condition line
//     itself is already executed by existing tests (they call acquire with a
//     live ctx, so ctx.Err() returns nil and the body is skipped); only the
//     220-222 body was count-0.
//
// productionFirstHopLimiter is an UNEXPORTED type, so this test lives
// in-package to construct it directly (the constructor
// newProductionFirstHopLimiter is also unexported). Both guards fire before
// l.slots is touched, so a zero-valued &productionFirstHopLimiter{} is safe —
// no channel send, no goroutine, no network, no filesystem. The released
// release-callback returned on the success path is never reached here.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProductionFirstHopLimiterAcquireRejectsNilContext(t *testing.T) {
	// 217-219: a nil context is rejected before the slot-channel send, so a
	// zero-valued limiter is safe (l.slots is a nil channel that is never sent
	// on).
	l := &productionFirstHopLimiter{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := l.acquire(nil)
	if err == nil {
		t.Fatal("acquire(nil ctx) err = nil, want non-nil (:217 should fire)")
	}
	if !strings.Contains(err.Error(), "production first-hop session context is required") {
		t.Fatalf("acquire(nil ctx) err = %v, want substring \"production first-hop session context is required\"", err)
	}
}

func TestProductionFirstHopLimiterAcquireRejectsCancelledContext(t *testing.T) {
	// 220-222: a non-nil but already-cancelled context passes the :217 nil
	// check but fails ctx.Err() != nil at 220, returning context.Canceled at
	// 221 before the slot send at 224. A zero-valued limiter is safe (l.slots
	// is never sent on).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l := &productionFirstHopLimiter{}
	release, err := l.acquire(ctx)
	if err == nil {
		t.Fatal("acquire(cancelled ctx) err = nil, want non-nil (:220 should fire)")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire(cancelled ctx) err = %v, want errors.Is err context.Canceled (:221 returns ctx.Err())", err)
	}
	if release != nil {
		t.Fatal("acquire(cancelled ctx) release != nil, want nil (no slot acquired)")
	}
}
