package relay

// Adversarial white-box coverage for the two remaining count-0 nil-context
// rejection guards in the relay exit path:
//
//   - egress.go:82-84 — ExitSession.HandleFrameBlock(ctx, block). The FIRST
//     statement of the method returns "relay: nil exit session context"
//     before s.mu.Lock at 88, so a zero-valued receiver is safe (no field is
//     touched). The block argument is never inspected.
//   - socket_egress.go:166-168 — SocketEgress.HandleEvent(ctx, event). The
//     FIRST statement returns "relay: nil socket egress event context"
//     before ctx.Err() at 169 and e.beginOperation() at 172, so a
//     zero-valued receiver is safe (no field or channel is touched). The
//     event argument is never inspected.
//
// Both are first-statement guards on exported methods of exported receiver
// types. The existing relay tests always drive HandleFrameBlock and
// HandleEvent with a real context (a live ExitSession/SocketEgress handling
// real frame events), so the two nil-ctx arms stayed count-0 even though the
// methods are public and the guards are plainly reachable: a caller that
// forgets to thread a context through hits them.
//
// Calling with a literal nil context.Context triggers staticcheck SA1012 (nil
// context literal). The codebase convention — established in
// evidence/egress_test.go, evidence/first_hop_test.go, evidence/session_test.go,
// transport/http2_client_test.go, transport/duplex_test.go,
// server/production_test.go, server/first_hop_nil_context_branch_coverage_test.go,
// handshake/production_dependencies_nil_context_branch_coverage_test.go,
// handshake/driver_nil_context_branch_coverage_test.go,
// perf/load_branch_coverage_test.go, and cmd/aurorac/linux_tun_coverage_test.go
// — is a //lint:ignore SA1012 directive immediately before the call
// documenting that it verifies the public API's nil-context rejection. Each
// of the two calls below carries that directive.
//
// This file adds no package-level helpers: each test constructs its own
// zero-valued receiver inline. No goroutines, no network, no filesystem, no
// cryptography — every guard returns before any of that is reached.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestExitSessionHandleFrameBlockRejectsNilContext(t *testing.T) {
	// egress.go:82-84: a nil context is rejected before s.mu.Lock runs, so a
	// zero-valued receiver is safe (the lock and closing channel are never
	// touched). The block argument is never inspected.
	s := &ExitSession{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err := s.HandleFrameBlock(nil, protocol.FrameBlock{})
	if err == nil {
		t.Fatal("HandleFrameBlock(nil ctx) err = nil, want non-nil (:82 should fire)")
	}
	if !strings.Contains(err.Error(), "nil exit session context") {
		t.Fatalf("HandleFrameBlock(nil ctx) err = %v, want substring \"nil exit session context\"", err)
	}
}

func TestSocketEgressHandleEventRejectsNilContext(t *testing.T) {
	// socket_egress.go:166-168: a nil context is rejected before ctx.Err() and
	// e.beginOperation() run, so a zero-valued receiver is safe (the wait
	// group and flows map are never touched). The event argument is never
	// inspected.
	e := &SocketEgress{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := e.HandleEvent(nil, ExitFrameEvent{})
	if err == nil {
		t.Fatal("HandleEvent(nil ctx) err = nil, want non-nil (:166 should fire)")
	}
	if !strings.Contains(err.Error(), "nil socket egress event context") {
		t.Fatalf("HandleEvent(nil ctx) err = %v, want substring \"nil socket egress event context\"", err)
	}
}
