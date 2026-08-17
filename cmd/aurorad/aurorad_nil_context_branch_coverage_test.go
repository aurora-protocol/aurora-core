package main

// Adversarial white-box coverage for the two count-0 nil-context guards of the
// cmd/aurorad production serve entrypoints. Both functions open with
// `if ctx == nil { return ... }` as their very first statement; the existing
// production nil-arg test (aurorad_production_nil_arg_branch_coverage_test.go)
// deliberately passes context.Background() so it skips these ctx==nil guards
// (and avoids SA1012), which is exactly why :338 and :704 stayed COUNT 0.
//
// Coverage targets (baseline measured on main; both body blocks COUNT 0):
//   - issuer_production.go:338.16,340.3 0 — serveProductionIssuer ctx==nil
//     -> "issuer: production service context is required"
//   - production.go:704.16,706.3 0       — serveProduction ctx==nil
//     -> "server: production service context is required"
//
// Each guard is the first statement of its function, so nil ctx returns before
// the runtime/service/listener args are ever read — nil runtime/service/listener
// is safe (never dereferenced). Error strings are asserted per subtest
// (self-validating); the per-line coverage flip is the rigorous proof.
//
// SA1012 (nil Context literal) is suppressed per the established codebase
// convention (//lint:ignore SA1012 Verifies the public API's explicit
// nil-context rejection.) on each intentional nil-context call (CI-proven on
// #264/#346/#349/#350/#353). serveProductionIssuer/serveProduction are
// unexported -> in-package (package main) test. No goroutine, no network, no
// filesystem. One TestXxx with two t.Run subtests; imports strings/testing ->
// no U1000 surface.

import (
	"strings"
	"testing"
)

func TestServeProductionIssuerAndServeProductionRejectNilContext(t *testing.T) {
	// :338 — serveProductionIssuer. The runtime and listener are nil but never
	// read (ctx==nil returns first).
	t.Run("serveProductionIssuer", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := serveProductionIssuer(nil, nil, nil); err == nil || !strings.Contains(err.Error(), "production service context is required") {
			t.Fatalf("serveProductionIssuer(nil ctx) err = %v, want non-nil containing \"production service context is required\" (:338)", err)
		}
	})

	// :704 — serveProduction. The service and listener are nil but never read
	// (ctx==nil returns first). This is the guard the existing nil-arg test
	// intentionally skips by passing context.Background().
	t.Run("serveProduction", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := serveProduction(nil, nil, nil); err == nil || !strings.Contains(err.Error(), "production service context is required") {
			t.Fatalf("serveProduction(nil ctx) err = %v, want non-nil containing \"production service context is required\" (:704)", err)
		}
	})
}
