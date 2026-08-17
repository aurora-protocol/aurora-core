package main

// Adversarial white-box coverage for two count-0 nil-argument guards in
// cmd/aurorac: a nil recovery-attempt guard in the carrier-recovery loop and a
// nil issuer-HTTP-client guard in the issuer work exchange.
//
//   - main.go:472 runWithCarrierRecovery
//     attempt == nil -> return "client: carrier recovery attempt is required"
//     (fires after the :469 nil-context guard, before the :475 policy
//     normalization). carrierRecoveryAttempt is a func type, so nil is a valid
//     zero value.
//   - main.go:617 exchangeIssuerWork
//     httpClient == nil -> return "client: issuer HTTP client is unavailable"
//     (fires after the :616 newIssuerHTTPClient() call, before the :620
//     CloseIdleConnections / :621 Do). newIssuerHTTPClient is a package-level
//     function var, swapped via setNewIssuerHTTPClientForTest.
//
// The existing cmd/aurorac tests drive runWithCarrierRecovery only with a real
// attempt callback and drive exchangeIssuerWork only with the real issuer HTTP
// client, so :472 and :617 stayed count-0 even though each is plainly
// reachable on a nil argument / nil factory result.
//
// Proof technique:
//
//   - :472 (nil-argument clean return): call runWithCarrierRecovery with a real
//     context.Background (so the :469 nil-context guard is skipped — this test
//     does NOT cover the ctx == nil guard, so there is no SA1012 surface), a
//     zero-value carrierRecoveryPolicy (never used — :475 is unreachable once
//     :472 returns), and a nil attempt. The :472 guard sees attempt == nil and
//     returns "carrier recovery attempt is required" before policy
//     normalization. The non-nil error containing "carrier recovery attempt is
//     required" uniquely proves :473 ran: :473 is the only site that returns
//     that message, and the non-nil context rules out the :469 path. Pure (no
//     IO; it returns before any network / retry loop).
//
//   - :617 (nil-factory-result clean return): override newIssuerHTTPClient via
//     setNewIssuerHTTPClientForTest to return nil, then call exchangeIssuerWork
//     with a valid client.IssuerWork (https issuer URL, relative carrier path,
//     non-empty body) and a positive timeout. The :596 ctx.Err check passes
//     (real context), :599 timeout > 0 passes, :602 issuerWorkURL succeeds (the
//     work is complete and well-formed), :608 http.NewRequestWithContext
//     succeeds, :612-615 set headers, :616 newIssuerHTTPClient() returns nil,
//     and :617 returns "issuer HTTP client is unavailable" before :620
//     CloseIdleConnections / :621 Do. The non-nil error containing "issuer HTTP
//     client is unavailable" uniquely proves :618 ran: :618 is the only site
//     that returns that message. The factory is restored via the returned
//     closure (deferred). cmd/aurorac tests run sequentially (no t.Parallel), so
//     the package-var swap is race-free. No real network IO is performed (:617
//     returns before httpClient.Do).
//
// Neither guard is a ctx == nil guard (a real context.Background is passed), so
// there is no SA1012 surface. In-package (package main) because
// runWithCarrierRecovery, exchangeIssuerWork, carrierRecoveryPolicy,
// setNewIssuerHTTPClientForTest, and newIssuerHTTPClient are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (runWithCarrierRecovery, exchangeIssuerWork,
// carrierRecoveryPolicy, setNewIssuerHTTPClientForTest) symbols and the
// exported client.IssuerWork type, so it adds no U1000 surface.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestRunWithCarrierRecoveryNilAttemptGuard(t *testing.T) {
	// 472: a nil attempt (carrierRecoveryAttempt is a func type) with a real
	// context skips the :469 nil-context guard and fires :472, returning the
	// "attempt is required" error before policy normalization at :475.
	err := runWithCarrierRecovery(context.Background(), carrierRecoveryPolicy{}, nil)
	if err == nil {
		t.Fatal("runWithCarrierRecovery(nil attempt) returned nil, want non-nil (:473)")
	}
	if !strings.Contains(err.Error(), "carrier recovery attempt is required") {
		t.Fatalf("runWithCarrierRecovery nil-attempt err = %q, want \"carrier recovery attempt is required\" (:473)", err.Error())
	}
}

func TestExchangeIssuerWorkNilHTTPClientGuard(t *testing.T) {
	// 617: override newIssuerHTTPClient to return nil so :616 yields nil and :617
	// fires. A valid issuer work (https URL + relative carrier path + non-empty
	// body) and a positive timeout pass :596/:599/:602-605/:608-615 so :616 is
	// reached; :617 returns "issuer HTTP client is unavailable" before any Do.
	restore := setNewIssuerHTTPClientForTest(func() *http.Client { return nil })
	defer restore()
	work := client.IssuerWork{
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/assets/app.bin",
		RequestBody:       []byte{0x01},
	}
	_, err := exchangeIssuerWork(context.Background(), time.Second, work)
	if err == nil {
		t.Fatal("exchangeIssuerWork(nil HTTP client) returned nil, want non-nil (:618)")
	}
	if !strings.Contains(err.Error(), "issuer HTTP client is unavailable") {
		t.Fatalf("exchangeIssuerWork nil-client err = %q, want \"issuer HTTP client is unavailable\" (:618)", err.Error())
	}
}
