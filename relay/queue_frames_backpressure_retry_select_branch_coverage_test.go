package relay

// Adversarial white-box branch coverage for the two count-0 branches in
// (*ExitSession).queueFrames (relay/egress.go:121), the unexported frame-queue
// retry loop:
//
//	for {
//	    err := s.sink.QueueFrames(ctx, block)            // :129
//	    if !errors.Is(err, session.ErrBackpressure) {    // :130
//	        return err                                   // :131 (covered)
//	    }
//	    if timer == nil {                                // :133
//	        timer = time.NewTimer(s.retry)               // :134
//	    } else {
//	        timer.Reset(s.retry)                         // :135-:137  <-- count 0 (2nd iteration)
//	    }
//	    select {
//	    case <-s.closing:                                // :139
//	        timer.Stop(); return ErrExitSessionClosed     // :140-:141 (covered)
//	    case <-ctx.Done():                               // :142
//	        timer.Stop(); return ctx.Err()               // :143-:144  <-- count 0
//	    case <-timer.C:                                  // :145 (covered)
//	    }
//	}
//
// Baseline (clean tree, relay_371_base.out): the backpressure-retry path is
// only entered when the sink returns session.ErrBackpressure. The existing
// relay tests drive the happy path (sink accepts -> :131 returns nil) and
// one shutdown path (closing wins -> :140-:141), but never (a) loop a SECOND
// time under backpressure (so the `else timer.Reset` arm at :135-:137 stayed
// count 0) and never (b) win the select via ctx.Done under backpressure (so
// the :143-:144 ctx.Done body stayed count 0). Both are reachable
// DETERMINISTICALLY with a mock FrameSink that always returns
// session.ErrBackpressure:
//
//   - :135-:137 (timer.Reset else-branch) — needs a SECOND iteration, i.e.
//     the select must pick <-timer.C on iteration 1 (so the loop continues)
//     and then close s.closing during iteration 2's QueueFrames call (so the
//     iter-2 select picks <-s.closing and returns ErrExitSessionClosed). The
//     sink closes s.closing on its 2nd call; retry is short so the iter-1
//     timer fires promptly. ctx is Background (not done) so iter 1 waits for
//     the timer; iter 2 sees s.closing closed.
//   - :143-:144 (ctx.Done case body) — cancel ctx BEFORE the call; QueueFrames
//     returns ErrBackpressure (retry loop), timer armed (1h, won't fire), and
//     the select picks <-ctx.Done() (ready; closing open, timer not fired) ->
//     returns ctx.Err() (context.Canceled).
//
// queueFrames reads only s.sink, s.closing, and s.retry (not s.mu / s.validator
// / s.egress / s.closeOnce), so a minimal white-box &ExitSession{closing, sink,
// retry} is sufficient. queueFrames is unexported, so in-package (package
// relay) is required. The per-line coverage flip (0 -> N) is the rigorous proof.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/session"
)

// backpressureSink is a minimal FrameSink mock whose QueueFrames always
// reports session.ErrBackpressure, exercising the queueFrames retry loop.
// If closing is non-nil and closeOn > 0, the closeOn-th call closes closing so
// the loop can exit after the targeted branch executes. Local (lowercase) so
// it cannot create a package-level U1000 surface.
type backpressureSink struct {
	closing   chan struct{}
	closeOnce sync.Once
	closeOn   int
	calls     int
}

func (s *backpressureSink) QueueFrames(context.Context, protocol.FrameBlock) error {
	s.calls++
	if s.closing != nil && s.closeOn > 0 && s.calls >= s.closeOn {
		s.closeOnce.Do(func() { close(s.closing) })
	}
	return session.ErrBackpressure
}

func TestQueueFramesBackpressureRetryBranches(t *testing.T) {
	// egress.go:143-:144 — ctx.Done case body. ctx is canceled BEFORE the call;
	// QueueFrames returns ErrBackpressure (retry loop), the retry timer is
	// armed (1h, won't fire within the test), and the select picks <-ctx.Done()
	// (ready; closing open, timer not fired) -> returns ctx.Err().
	t.Run("ctx done wins backpressure retry select", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s := &ExitSession{
			closing: make(chan struct{}),
			sink:    &backpressureSink{},
			retry:   time.Hour,
		}
		err := s.queueFrames(ctx, protocol.FrameBlock{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	// egress.go:135-:137 — the `else timer.Reset(s.retry)` arm, reachable only
	// on a SECOND iteration under backpressure. The sink returns
	// ErrBackpressure on every call and closes s.closing on its 2nd call.
	//   iteration 1: QueueFrames(1) -> ErrBackpressure; timer == nil ->
	//     NewTimer(retry); select waits for <-timer.C (closing open, ctx =
	//     Background not done) -> timer fires, loop continues.
	//   iteration 2: QueueFrames(2) -> ErrBackpressure + closes s.closing;
	//     timer != nil -> timer.Reset(retry) [HITS :135-:137]; select picks
	//     <-s.closing (now ready) -> ErrExitSessionClosed.
	// A short retry makes iteration 1's timer fire promptly; the outcome is
	// deterministic (only <-timer.C is ready in iter 1; only <-s.closing is
	// ready in iter 2) regardless of exact timing.
	t.Run("timer reset on second backpressure iteration", func(t *testing.T) {
		closing := make(chan struct{})
		sink := &backpressureSink{closing: closing, closeOn: 2}
		s := &ExitSession{
			closing: closing,
			sink:    sink,
			retry:   10 * time.Millisecond,
		}
		err := s.queueFrames(context.Background(), protocol.FrameBlock{})
		if !errors.Is(err, ErrExitSessionClosed) {
			t.Fatalf("err = %v, want ErrExitSessionClosed", err)
		}
		if sink.calls < 2 {
			t.Fatalf("calls = %d, want >= 2 (timer.Reset else-arm needs a 2nd iteration)", sink.calls)
		}
	})
}
