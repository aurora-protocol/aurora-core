package handshake

// Adversarial white-box coverage for five count-0 nil-context rejection
// guards across the handshake driver/handshake entry points. Each is the
// ctx == nil guard that immediately follows a nil-receiver guard, so it is
// reachable with a non-nil zero-valued receiver (which clears the
// nil-receiver check) and a nil context; the guard returns before any
// receiver field or argument is dereferenced.
//
//   - client.go:25-27 — ClientDriver.Connect(ctx, opener). After the
//     `if d == nil` check at 22, a nil ctx returns
//     "handshake: nil client context". opener (a ClientCarrierOpener) is
//     never inspected.
//   - client.go:472-474 — contextError(ctx), a free function. A nil ctx
//     returns "handshake: nil client context" before the ctx.Err() at 475.
//     (This helper is called internally by the relay handshake path, which
//     always passes a real ctx, so its nil arm is only reachable by a direct
//     in-package call.)
//   - relay.go:39-41 — RelayDriver.Begin(ctx, binding, input, nowUnix). After
//     the `if d == nil` check at 36, a nil ctx returns
//     "handshake: nil relay context" before the binding/input/nowUnix args
//     are touched.
//   - client_resume.go:51-53 — ClientDriver.Begin(ctx, opener). After the
//     `if d == nil` check at 48, a nil ctx returns
//     "handshake: nil client context" before opener is inspected.
//   - client_resume.go:106-108 — ClientHandshake.Complete(ctx, admissionProof,
//     replayProof). After the `if h == nil` check at 103, a nil ctx returns
//     "handshake: nil client completion context" before h.Close() at 110.
//
// NOT covered here: relay.go:205-207 is a nil-ctx guard too, but it sits
// deep inside the relay handshake continuation (after `h.terminal = true`
// and `defer h.destroyLocked()`), so reaching it requires a partially
// advanced RelayHandshake state — it is stateful, not a clean first-statement
// guard, and is left for a dedicated stateful pillar.
//
// The existing handshake tests always drive Connect/Begin/Complete (and
// contextError transitively) with a real context, so all five nil arms
// stayed count-0 even though the entry points are public and the guards are
// plainly reachable: a caller that forgets to thread a context through hits
// them.
//
// Calling with a literal nil context.Context triggers staticcheck SA1012
// (nil context literal). The codebase convention — established in
// handshake/production_dependencies_nil_context_branch_coverage_test.go (PR
// #245), evidence/, transport/, server/, perf/, cmd/aurorac/ — is a
// //lint:ignore SA1012 directive immediately before the call. Each of the
// five calls below carries that directive.
//
// This file adds no package-level helpers: each test constructs its own
// zero-valued receiver inline. No goroutines, no network, no filesystem, no
// cryptography — every guard returns before any of that is reached.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestClientDriverConnectRejectsNilContext(t *testing.T) {
	// client.go:25-27: a non-nil zero-valued driver clears the :22 nil-receiver
	// check, then a nil ctx is rejected before the opener is inspected.
	d := &ClientDriver{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := d.Connect(nil, nil)
	if err == nil {
		t.Fatal("Connect(nil ctx) err = nil, want non-nil (:25 should fire)")
	}
	if !strings.Contains(err.Error(), "nil client context") {
		t.Fatalf("Connect(nil ctx) err = %v, want substring \"nil client context\"", err)
	}
}

func TestContextErrorRejectsNilContext(t *testing.T) {
	// client.go:472-474: the free contextError helper rejects a nil ctx before
	// calling ctx.Err(). Reachable only by a direct in-package call (callers
	// in the relay path always pass a real ctx).
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err := contextError(nil)
	if err == nil {
		t.Fatal("contextError(nil) err = nil, want non-nil (:472 should fire)")
	}
	if !strings.Contains(err.Error(), "nil client context") {
		t.Fatalf("contextError(nil) err = %v, want substring \"nil client context\"", err)
	}
}

func TestRelayDriverBeginRejectsNilContext(t *testing.T) {
	// relay.go:39-41: a non-nil zero-valued driver clears the :36 nil-receiver
	// check, then a nil ctx is rejected before the binding/input/nowUnix args
	// are touched. FirstHopBinding is a struct, so pass the zero value.
	d := &RelayDriver{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, _, err := d.Begin(nil, FirstHopBinding{}, protocol.CoverPrelude0{}, 0)
	if err == nil {
		t.Fatal("RelayDriver.Begin(nil ctx) err = nil, want non-nil (:39 should fire)")
	}
	if !strings.Contains(err.Error(), "nil relay context") {
		t.Fatalf("RelayDriver.Begin(nil ctx) err = %v, want substring \"nil relay context\"", err)
	}
}

func TestClientDriverBeginRejectsNilContext(t *testing.T) {
	// client_resume.go:51-53: a non-nil zero-valued driver clears the :48
	// nil-receiver check, then a nil ctx is rejected before the opener is
	// inspected.
	d := &ClientDriver{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, _, err := d.Begin(nil, nil)
	if err == nil {
		t.Fatal("ClientDriver.Begin(nil ctx) err = nil, want non-nil (:51 should fire)")
	}
	if !strings.Contains(err.Error(), "nil client context") {
		t.Fatalf("ClientDriver.Begin(nil ctx) err = %v, want substring \"nil client context\"", err)
	}
}

func TestClientHandshakeCompleteRejectsNilContext(t *testing.T) {
	// client_resume.go:106-108: a non-nil zero-valued handshake clears the :103
	// nil-receiver check, then a nil ctx is rejected before h.Close() at 110.
	h := &ClientHandshake{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := h.Complete(nil, protocol.AdmissionProof{}, protocol.ReplayProof{})
	if err == nil {
		t.Fatal("Complete(nil ctx) err = nil, want non-nil (:106 should fire)")
	}
	if !strings.Contains(err.Error(), "nil client completion context") {
		t.Fatalf("Complete(nil ctx) err = %v, want substring \"nil client completion context\"", err)
	}
}
