package relay

// Adversarial white-box coverage for the two reachable count-0 branches in
// relay/egress.go's NewExitSession: the RateLimit override (59-61) and the
// UDPConfirmTTL override (62-64).
//
// NewExitSession is the PUBLIC constructor for an ExitSession. It builds the
// flow validator via NewExitFlowHandler(options.Policy), which pre-populates
// two operational knobs with safe defaults:
//
//	validator := NewExitFlowHandler(options.Policy)
//	// -> ExitFlowHandler{ ..., UDPConfirmTTLSeconds: 300,
//	//                    RateLimit: DefaultExitRateLimit() }
//
// then NewExitSession conditionally overrides those defaults from the
// caller's options:
//
//	if options.RateLimit != (ExitRateLimit{}) {        // 59
//	    validator.RateLimit = options.RateLimit        // 60
//	}                                                  // 61
//	if options.UDPConfirmTTL != 0 {                    // 62
//	    validator.UDPConfirmTTLSeconds = options.UDPConfirmTTL // 63
//	}                                                  // 64
//
// Every existing test in egress_test.go constructs NewExitSession with either
// ExitSessionOptions{} or options that set QueueRetryInterval but NOT
// RateLimit/UDPConfirmTTL, so the two override bodies stayed count-0 even
// though the constructor is public and the branches are plainly reachable:
// a caller who wants tighter rate limiting or a different confirmation TTL
// passes a non-zero option, and the branch fires.
//
//   - 59-61 — RateLimit override. Reachable with a custom, non-default
//     ExitRateLimit (distinct from DefaultExitRateLimit's {60, 1024, 64MB}).
//     The white-box assertion session.validator.RateLimit == custom (and !=
//     DefaultExitRateLimit()) proves :60 executed: the custom value replaced
//     the default rather than the default surviving untouched.
//   - 62-64 — UDPConfirmTTL override. Reachable with a non-zero TTL other
//     than the 300 default (7 here). The assertion
//     session.validator.UDPConfirmTTLSeconds == 7 proves :63 executed.
//
// A happy-path lock first confirms that ExitSessionOptions{} leaves both
// defaults intact (RateLimit == DefaultExitRateLimit(), UDPConfirmTTLSeconds
// == 300), so the two overrides are meaningful contrasts — they actually
// CHANGE a value that the default constructor path leaves alone.
//
// NewExitSession touches no network, no goroutine, and no context: it only
// validates its egress/sink dependencies (isNilExitDependency) and the queue
// retry interval, then assembles the struct. The recordingEgress and
// recordingFrameSink in-memory stubs (already heavily referenced across
// egress_test.go) satisfy the non-nil dependency checks without standing up
// any real transport. So this is pure struct-assembly coverage.
//
// The remaining count-0 branches in egress.go (NOT claimed here):
//   - 82-84 (HandleFrameBlock nil-context guard) needs a //lint:ignore SA1012
//     nil-Context call; left for a dedicated nil-context pillar.
//   - 95-97 / 103-105 (HandleFrameBlock ctx.Err mid-loop) need a live event
//     loop with a cancellable context — stateful.
//   - 135-137 / 142-144 (queueFrames timer-reset and ctx.Done backpressure
//     paths) need a sink that returns ErrBackpressure with a closing/cancelled
//     context — stateful.
//   - 151-153 (Close nil-receiver guard) is a trivial nil-method-call guard.
//
// This file adds no package-level helpers: it reuses recordingEgress and
// recordingFrameSink (each referenced by many tests in egress_test.go) and
// DefaultExitRateLimit (exported). No context.Context (no SA1012 surface),
// no goroutines.

import (
	"testing"
)

func TestNewExitSessionAppliesRateLimitOption(t *testing.T) {
	// 59-61: a caller-supplied non-default RateLimit replaces the
	// NewExitFlowHandler default. The custom value is chosen to differ from
	// DefaultExitRateLimit() on every field so the equality check is
	// unambiguous (the override provably ran, not the default surviving).
	custom := ExitRateLimit{WindowSeconds: 30, MaxFlowOpens: 5, MaxBytes: 1024}
	if custom == DefaultExitRateLimit() {
		t.Fatalf("test fixture: custom RateLimit must differ from DefaultExitRateLimit(); got %#v", custom)
	}
	s, err := NewExitSession(&recordingEgress{}, &recordingFrameSink{}, ExitSessionOptions{RateLimit: custom})
	if err != nil {
		t.Fatalf("NewExitSession(custom RateLimit) err = %v, want nil", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.validator.RateLimit != custom {
		t.Fatalf("NewExitSession(custom RateLimit) validator.RateLimit = %#v, want %#v (:60 should apply the override)", s.validator.RateLimit, custom)
	}
}

func TestNewExitSessionAppliesUDPConfirmTTLOption(t *testing.T) {
	// 62-64: a caller-supplied non-zero UDPConfirmTTL replaces the 300 default.
	const customTTL uint32 = 7
	s, err := NewExitSession(&recordingEgress{}, &recordingFrameSink{}, ExitSessionOptions{UDPConfirmTTL: customTTL})
	if err != nil {
		t.Fatalf("NewExitSession(UDPConfirmTTL=7) err = %v, want nil", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.validator.UDPConfirmTTLSeconds != customTTL {
		t.Fatalf("NewExitSession(UDPConfirmTTL=7) validator.UDPConfirmTTLSeconds = %d, want %d (:63 should apply the override)", s.validator.UDPConfirmTTLSeconds, customTTL)
	}
}

func TestNewExitSessionRetainsDefaultsForZeroOptions(t *testing.T) {
	// Happy-path lock so the :59/:62 overrides are meaningful contrasts: with
	// a zero-valued ExitSessionOptions the NewExitFlowHandler defaults survive
	// untouched — RateLimit == DefaultExitRateLimit() and UDPConfirmTTLSeconds
	// == 300 — proving the two override branches are NOT taken on the default
	// path and therefore that a non-zero option is what changes each value.
	s, err := NewExitSession(&recordingEgress{}, &recordingFrameSink{}, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession({}) err = %v, want nil", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.validator.RateLimit != DefaultExitRateLimit() {
		t.Fatalf("NewExitSession({}) validator.RateLimit = %#v, want DefaultExitRateLimit() (override NOT taken)", s.validator.RateLimit)
	}
	if s.validator.UDPConfirmTTLSeconds != 300 {
		t.Fatalf("NewExitSession({}) validator.UDPConfirmTTLSeconds = %d, want 300 (override NOT taken)", s.validator.UDPConfirmTTLSeconds)
	}
}
