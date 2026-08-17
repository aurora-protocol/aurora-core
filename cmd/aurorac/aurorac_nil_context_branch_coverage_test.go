package main

// Adversarial white-box coverage for the count-0 nil-context guards of the
// aurorac proxy/tunnel/issuer entrypoints (cmd/aurorac/main.go). Eight package-
// main functions open with `if ctx == nil { return ... }` (six as the sole
// condition; two compound it with established/runtime/listener nil checks via a
// short-circuiting ||). Every existing aurorac test passes a real
// context.Background(), so all eight nil-context bodies are COUNT 0.
//
// Coverage targets (baseline measured on main; all bodies COUNT 0 while each
// condition was already evaluated once):
//   - main.go:266.16,268.3 0  — runProxy nil-context ("proxy context is required")
//   - main.go:283.16,285.3 0  — runProxyAttempt nil-context
//   - main.go:360.16,362.3 0  — runTUN nil-context ("tunnel context is required")
//   - main.go:377.16,379.3 0  — runTUNAttempt nil-context
//   - main.go:469.16,471.3 0  — runWithCarrierRecovery nil-context
//   - main.go:593.16,595.3 0  — exchangeIssuerWork nil-context ("issuer context is required")
//   - main.go:683.206,685.3 0 — runProxyComponents incomplete ("proxy components are incomplete")
//   - main.go:724.159,726.3 0 — runTUNComponents incomplete ("tunnel components are incomplete")
//
// Each guard is the function's first statement (or a short-circuiting || whose
// ctx==nil term is first), so it returns before any field/config/carrier is read.
// A bare zero-value config + nil listener/runtime/established is enough — no
// provisioning, no network, no TUN device. The two compound guards
// (runProxyComponents/runTUNComponents) short-circuit on ctx==nil, so passing nil
// for the other args never dereferences them.
//
// SA1012 (nil Context literal) is suppressed per the established codebase
// convention (//lint:ignore SA1012 Verifies the public API's explicit nil-context
// rejection. — CI-proven on #264 and many successors) on each intentional
// nil-context call. In-package (package main) because all eight functions are
// unexported. No goroutines, no real network, no TUN. One TestXxx with eight
// t.Run subtests; references in-package config types + client struct types +
// stdlib strings/testing -> no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestAuroracEntrypointsRejectNilContext(t *testing.T) {
	// :266 — runProxy returns before reading config or provisioning.
	t.Run("runProxy", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runProxy(nil, proxyConfig{}, nil); err == nil || !strings.Contains(err.Error(), "proxy context is required") {
			t.Fatalf("runProxy(nil ctx) err = %v, want non-nil containing \"proxy context is required\" (:266)", err)
		}
	})

	// :283 — runProxyAttempt returns before the reservation/provisioning path.
	t.Run("runProxyAttempt", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runProxyAttempt(nil, proxyConfig{}, client.NativeProvisioningTrust{}, nil); err == nil || !strings.Contains(err.Error(), "proxy context is required") {
			t.Fatalf("runProxyAttempt(nil ctx) err = %v, want non-nil containing \"proxy context is required\" (:283)", err)
		}
	})

	// :360 — runTUN returns before reading config or provisioning.
	t.Run("runTUN", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runTUN(nil, tunConfig{}, nil); err == nil || !strings.Contains(err.Error(), "tunnel context is required") {
			t.Fatalf("runTUN(nil ctx) err = %v, want non-nil containing \"tunnel context is required\" (:360)", err)
		}
	})

	// :377 — runTUNAttempt returns before the reservation/provisioning path.
	t.Run("runTUNAttempt", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runTUNAttempt(nil, tunConfig{}, client.NativeProvisioningTrust{}, nil); err == nil || !strings.Contains(err.Error(), "tunnel context is required") {
			t.Fatalf("runTUNAttempt(nil ctx) err = %v, want non-nil containing \"tunnel context is required\" (:377)", err)
		}
	})

	// :469 — runWithCarrierRecovery returns before reading policy or calling attempt.
	t.Run("runWithCarrierRecovery", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runWithCarrierRecovery(nil, carrierRecoveryPolicy{}, nil); err == nil || !strings.Contains(err.Error(), "carrier recovery context is required") {
			t.Fatalf("runWithCarrierRecovery(nil ctx) err = %v, want non-nil containing \"carrier recovery context is required\" (:469)", err)
		}
	})

	// :593 — exchangeIssuerWork returns (nil, err) before reading timeout/work.
	// The 0 timeout is an untyped constant assignable to time.Duration.
	t.Run("exchangeIssuerWork", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		out, err := exchangeIssuerWork(nil, 0, client.IssuerWork{})
		if err == nil || !strings.Contains(err.Error(), "issuer context is required") || out != nil {
			t.Fatalf("exchangeIssuerWork(nil ctx) out=%v err=%v, want nil out + non-nil err containing \"issuer context is required\" (:593)", out, err)
		}
	})

	// :683 — runProxyComponents' compound guard short-circuits on ctx==nil, so the
	// nil established/runtime/listeners are never dereferenced.
	t.Run("runProxyComponents", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runProxyComponents(nil, nil, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "proxy components are incomplete") {
			t.Fatalf("runProxyComponents(nil ctx) err = %v, want non-nil containing \"proxy components are incomplete\" (:683)", err)
		}
	})

	// :724 — runTUNComponents' compound guard short-circuits on ctx==nil, so the
	// nil established/runtime/close-callback are never dereferenced.
	t.Run("runTUNComponents", func(t *testing.T) {
		//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
		if err := runTUNComponents(nil, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "tunnel components are incomplete") {
			t.Fatalf("runTUNComponents(nil ctx) err = %v, want non-nil containing \"tunnel components are incomplete\" (:724)", err)
		}
	})
}
