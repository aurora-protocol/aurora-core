package client

// Adversarial white-box branch coverage for four count-0 early-return guards in the
// provisioned-session setup path (client/provisioned_session.go):
//
//	// BeginProvisionedSession (:81) is the exported wrapper that delegates to
//	// newProvisionedSession (:85); tests call newProvisionedSession in-package, so the
//	// wrapper body (:81.160,83.2) stays count 0.
//	func BeginProvisionedSession(ctx, provisioning, options) (...) {
//	    return newProvisionedSession(ctx, provisioning, options)   // :81  <-- COUNT 0 (wrapper)
//	}
//	func newProvisionedSession(ctx, provisioning, options) (...) {
//	    if ctx == nil { return ..., "nil provisioned session context" }   // :86-88 (covered by nil_safety test)
//	    if err := ctx.Err(); err != nil { return ..., err }                // :89  <-- COUNT 0
//	    options = normalizeProvisionedSessionOptions(options)
//	    now := options.now().UTC()
//	    if now.IsZero() || now.Unix() < 0 { return ..., "requires a valid time" }  // :94  <-- COUNT 0
//	    issuerMetadata, err := provisioning.verifiedIssuerMetadataAt(now)
//	    if err != nil { return ..., err }                                  // :98  <-- COUNT 0
//	    ...
//	}
//
// All four fire BEFORE any handshake or crypto (verifiedIssuerMetadataAt rejects the
// empty IssuerURL at its first check, before verifiedSignedSeedAt/signature work), so
// the tests are fully deterministic: no goroutine, no network, no rand, no SA1012 (only
// non-nil live / pre-canceled contexts are passed; the ctx==nil guard at :86, which
// would need SA1012, is already covered by provisioned_session_nil_safety_branch_coverage_test.go).
//
//	- :81 + :89 -> BeginProvisionedSession (exported wrapper) with a pre-canceled context:
//	  the wrapper delegates to newProvisionedSession, :86 passes (ctx non-nil), :89
//	  ctx.Err() = context.Canceled -> returns it. Covers the wrapper body AND :89.
//	- :94 -> a live context passes :89, but an injected `now` func returning a zero time
//	  makes the :94 time guard fire. normalizeProvisionedSessionOptions only defaults
//	  `now` to time.Now when options.now == nil (:307), so an explicit zero-returning
//	  now func is preserved and :94 fires deterministically (the default time.Now path
//	  always yields a valid now, so :94 is reachable ONLY via this in-package injection).
//	- :98 -> valid ctx + valid (default) now reach verifiedIssuerMetadataAt, which
//	  rejects the empty IssuerURL at its first check (validateNativeHTTPSURL len check
//	  -> "URL length is invalid"), surfaced at :98 — before any crypto.
//
// The remaining count-0 in newProvisionedSession's later body (handshake start, proof
// building) is MEDIUM (needs a fully-valid NativeProvisioning + handshake wiring) and is
// NOT claimed here. newProvisionedSession and the options.now field are unexported, so
// this is in-package. The per-line coverage flips (:81 0->1, :89 0->1, :94 0->1, :98 0->1)
// are the rigorous proof.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProvisionedSessionSetupEarlyReturns(t *testing.T) {
	// :81 + :89 — the exported BeginProvisionedSession wrapper delegates to
	// newProvisionedSession, which rejects a pre-canceled context at :89 before any
	// handshake/crypto. NativeProvisioning{} is never validated (the guard fires first).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := BeginProvisionedSession(ctx, NativeProvisioning{}, ProvisionedSessionOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginProvisionedSession(canceled ctx) err = %v, want context.Canceled (:81 wrapper + :89 ctx.Err guard)", err)
	}

	// :94 — a live context passes :89, but an injected now func returning a zero time
	// makes the :94 time guard fire. normalize only defaults now when options.now == nil,
	// so an explicit zero-returning now func is preserved and :94 fires deterministically.
	zeroNow := ProvisionedSessionOptions{now: func() time.Time { return time.Time{} }}
	if _, _, err := newProvisionedSession(context.Background(), NativeProvisioning{}, zeroNow); err == nil || !strings.Contains(err.Error(), "valid time") {
		t.Fatalf("newProvisionedSession(zero now) err = %v, want substring %q (:94 time guard)", err, "valid time")
	}

	// :98 — valid ctx + valid (default) now reach verifiedIssuerMetadataAt, which rejects
	// the empty IssuerURL at its first check (validateNativeHTTPSURL len check) before any
	// crypto, surfaced at :98.
	if _, _, err := newProvisionedSession(context.Background(), NativeProvisioning{}, ProvisionedSessionOptions{}); err == nil || !strings.Contains(err.Error(), "issuer URL") {
		t.Fatalf("newProvisionedSession(empty provisioning) err = %v, want substring %q (:98 verifiedIssuerMetadataAt err guard)", err, "issuer URL")
	}
}
