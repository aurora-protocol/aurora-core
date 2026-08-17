package server

// Adversarial white-box coverage for three count-0 nil-context guards in
// server/first_hop.go: the ConnContext substitution (237-239) and the two
// shutdown-path rejections (496-498, 504-506).
//
//   - 237-239 — FirstHopHandler.ConnContext(ctx, connection). Unlike the
//     other two guards, this one does NOT return an error: it substitutes
//     context.Background() for a nil ctx so a misconfigured server.ConnContext
//     hook still yields a usable request context. The guard is reachable with
//     a zero-valued receiver and a nil connection: 237 sets ctx to
//     context.Background(), then 240 (`if h == nil || connection == nil {
//     return ctx }`) returns it without ever dereferencing h or connection.
//     Asserting the returned context IS context.Background() proves 237 ran
//     (the substitution), since that is the only path by which a nil ctx
//     becomes the Background singleton here.
//   - 496-498 — FirstHopHandler.shutdownAndWait(ctx). The guard returns
//     "server: first-hop shutdown context is required" BEFORE 499 calls
//     h.shutdown() or 500 h.waitForSessions(ctx), so a zero-valued receiver is
//     safe (nothing is touched). shutdownAndWait is unexported; this test is
//     in-package to call it directly.
//   - 504-506 — FirstHopHandler.waitForSessions(ctx). Same guard, same
//     message, returns before any session-wait state is touched. Also
//     unexported; in-package.
//
// All three are first-statement guards on methods of *FirstHopHandler. The
// existing first_hop_test.go / first_hop_integration_test.go always call
// ConnContext, shutdownAndWait, and waitForSessions with a real context (and
// a real connection / live handler), so the three nil-ctx arms stayed
// count-0. They are plainly reachable: a caller wiring ConnContext into an
// http.Server, or an operator invoking a shutdown without a context, hits
// them.
//
// Calling with a literal nil context.Context triggers staticcheck SA1012 (nil
// context literal). The codebase convention — established in
// server/production_test.go:105, evidence/, transport/, handshake/, perf/,
// and cmd/aurorac/ — is a //lint:ignore SA1012 directive immediately before
// the call documenting that it verifies the public API's nil-context
// behavior. Each of the three calls below carries that directive.
//
// This file adds no package-level helpers: each test constructs its own
// zero-valued &FirstHopHandler{} inline. No goroutines, no network, no
// filesystem, no cryptography — every guard returns (or substitutes) before
// any of that is reached.

import (
	"context"
	"strings"
	"testing"
)

func TestFirstHopHandlerConnContextSubstitutesBackgroundForNilContext(t *testing.T) {
	// 237-239: a nil ctx is substituted with context.Background(), and with a
	// nil connection the function returns that substituted context at 240
	// without dereferencing h or connection. The returned context IS
	// context.Background() — the singleton identity proves the substitution
	// ran, not some other path.
	h := &FirstHopHandler{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	got := h.ConnContext(nil, nil)
	if got == nil {
		t.Fatal("ConnContext(nil ctx, nil conn) = nil, want context.Background() (:237 should substitute)")
	}
	if got != context.Background() {
		t.Fatalf("ConnContext(nil ctx, nil conn) = %v, want context.Background() (:237 should substitute)", got)
	}
}

func TestFirstHopHandlerShutdownAndWaitRejectsNilContext(t *testing.T) {
	// 496-498: a nil ctx is rejected before h.shutdown() runs, so a
	// zero-valued receiver is safe (the shutdown machinery is never touched).
	h := &FirstHopHandler{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err := h.shutdownAndWait(nil)
	if err == nil {
		t.Fatal("shutdownAndWait(nil ctx) err = nil, want non-nil (:496 should fire)")
	}
	if !strings.Contains(err.Error(), "first-hop shutdown context is required") {
		t.Fatalf("shutdownAndWait(nil ctx) err = %v, want substring \"first-hop shutdown context is required\"", err)
	}
}

func TestFirstHopHandlerWaitForSessionsRejectsNilContext(t *testing.T) {
	// 504-506: a nil ctx is rejected before any session-wait state is touched.
	h := &FirstHopHandler{}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	err := h.waitForSessions(nil)
	if err == nil {
		t.Fatal("waitForSessions(nil ctx) err = nil, want non-nil (:504 should fire)")
	}
	if !strings.Contains(err.Error(), "first-hop shutdown context is required") {
		t.Fatalf("waitForSessions(nil ctx) err = %v, want substring \"first-hop shutdown context is required\"", err)
	}
}
