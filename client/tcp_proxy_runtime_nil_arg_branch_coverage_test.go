package client

// Adversarial white-box coverage for the two count-0 nil-arg guards of the
// TCPProxyRuntime serve entrypoints that sit IMMEDIATELY AFTER the ctx==nil
// guards covered by #353 (proxy_tun_nil_context_branch_coverage_test.go). Each
// is reached with a NON-nil context (context.Background) + a nil arg, so no
// SA1012 nil-context lint is involved.
//
// Coverage targets (baseline measured on main; both body blocks COUNT 0 — #353
// passes nil ctx and returns at :184/:335 before reaching these):
//   - tcp_proxy_runtime.go:187.16,189.3 0 — Serve: listener==nil
//     -> "client: nil TCP proxy listener"
//   - tcp_proxy_runtime.go:339.16,341.3 0 — serveConnection: connection==nil
//     -> "client: nil TCP proxy connection"
//
// Reachability:
//   - Serve(bg, nil): the :181 receiver-nil and :184 ctx==nil guards pass
//     (non-nil receiver &TCPProxyRuntime{}, non-nil ctx), then :187
//     listener==nil returns before the :189 ctx.Err() / :191 addListener reads.
//   - serveConnection(bg, nil): the :334 receiver-nil and :335 ctx==nil guards
//     pass; the :335 body (which would close the connection) is SKIPPED with a
//     non-nil ctx, so a nil connection is safe (never Closed); then :339
//     connection==nil returns before :341 addPending reads it.
//
// Error strings are asserted per subtest (self-validating); the per-line
// coverage flip is the rigorous proof. serveConnection is unexported -> in-
// package (package client) test; Serve is exported. No goroutine, no network
// (no net.Pipe needed — :339 never Closes the nil connection). One TestXxx with
// two t.Run subtests; imports context/strings/testing -> no U1000 surface.

import (
	"context"
	"strings"
	"testing"
)

func TestTCPProxyRuntimeNilListenerAndConnectionGuards(t *testing.T) {
	// :187 — Serve with a non-nil context but a nil listener. The receiver is a
	// non-nil zero-value &TCPProxyRuntime{} (passes the :181 r==nil guard).
	t.Run("Serve nil listener", func(t *testing.T) {
		if err := (&TCPProxyRuntime{}).Serve(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "nil TCP proxy listener") {
			t.Fatalf("Serve(bg, nil listener) err = %v, want non-nil containing \"nil TCP proxy listener\" (:187)", err)
		}
	})

	// :339 — serveConnection with a non-nil context but a nil connection. The
	// :335 ctx==nil body (which closes the connection) is skipped, so the nil
	// connection is never dereferenced.
	t.Run("serveConnection nil connection", func(t *testing.T) {
		if err := (&TCPProxyRuntime{}).serveConnection(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "nil TCP proxy connection") {
			t.Fatalf("serveConnection(bg, nil connection) err = %v, want non-nil containing \"nil TCP proxy connection\" (:339)", err)
		}
	})
}
