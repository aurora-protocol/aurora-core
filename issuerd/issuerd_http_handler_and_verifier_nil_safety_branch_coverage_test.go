package issuerd

// Adversarial white-box coverage for five count-0 service-readiness guards in
// the issuer HTTP handler surface and the verifier service: two true nil-safety
// guards (a nil service and a nil receiver) and three harness-handler
// not-ready guards whose service == nil clause is dead (the harness endpoints
// are only registered when service != nil && allowHarnessHTTPEndpoints, so the
// :144 early-return skips their registration when service == nil).
//
//   - http.go:124 NewHTTPHandler /issuer-metadata handler
//     service == nil -> 503 "issuer unavailable" (REACHABLE with a nil service:
//     /issuer-metadata is registered before the :144 early-return, so a nil
//     service still serves it and :124 trips on the service == nil clause).
//   - http.go:148 NewHTTPHandler /blind-rsa/issue handler
//     !service.ready() -> 503 "issuer unavailable" (the service == nil clause
//     is dead: the harness endpoint is registered only when service != nil, so
//     :148 trips on !service.ready() of a non-nil not-ready service).
//   - http.go:187 NewHTTPHandler /voprf/verify handler
//     !service.ready() -> 503 "verifier unavailable" (same dead-nil-clause shape
//     as :148).
//   - http.go:216 NewHTTPHandler /token/spend handler
//     !service.ready() -> 503 "issuer unavailable" (same dead-nil-clause shape
//     as :148).
//   - service.go:576 (*Service).verifierServiceForRequest
//     s == nil -> "issuerd: verifier unavailable" (the first clause of the
//     compound :576 guard; short-circuits before !s.ready() — which would deref
//     s via currentUnix — so a nil receiver is safe).
//
// The existing issuerd tests drive the handlers only with a ready service (the
// success paths) and call verifierServiceForRequest only with a constructed
// service, so :124 / :148 / :187 / :216 / :576 stayed count-0 even though each
// is plainly reachable with a nil service, a nil receiver, or a non-nil
// not-ready service.
//
// Proof technique:
//   - :124 (nil-service): NewHTTPHandler(nil) registers /issuer-metadata before
//     the :144 early-return; GET /issuer-metadata sees service == nil and :125
//     writes 503 before PublishIssuerMetadata. Pure (httptest in-memory; no
//     real network).
//   - :148 / :187 / :216 (not-ready harness handlers): NewHTTPHandler(
//     &Service{allowHarnessHTTPEndpoints: true}) registers the harness endpoints
//     (service != nil, harness allowed); a zero-value Service is not ready
//     (currentUnix returns 0, so ready() short-circuits to false at the nowUnix
//     == 0 clause without derefing blindRSAKey / spentTokens / metadata). Each
//     harness handler's service == nil || !service.ready() guard trips on
//     !service.ready() and writes 503 before reading the request body. The
//     service == nil clause is dead for these (the :144 early-return skips
//     harness registration when service == nil), so !ready() is the only live
//     path — covered honestly as a not-ready guard, not a nil-safety guard.
//   - :576 (nil-receiver): (*Service)(nil).verifierServiceForRequest(
//     protocol.IssuerVerifierRequest{}) — s == nil short-circuits :576 before
//     !s.ready(); :577 returns. Calling the method on a nil receiver is safe
//     because :576 is the first statement and guards the receiver. The error
//     message is unique to :577.
//
// No nil Context is passed, so there is no SA1012 surface. No real network, no
// goroutine, no file IO — httptest.NewRecorder / NewRequest are in-memory; the
// handlers return 503 before any body read / PublishIssuerMetadata; :576
// returns before any field deref. In-package (package issuerd) because
// verifierServiceForRequest and the allowHarnessHTTPEndpoints field are
// unexported.
//
// This test file adds only TestXxx entry points and references existing
// in-package (NewHTTPHandler, verifierServiceForRequest, Service) symbols, the
// exported protocol.IssuerVerifierRequest type, and the standard library
// net/http / net/http/httptest / strings / testing packages, so it adds no U1000
// surface.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestNewHTTPHandlerNilServiceMetadataGuard(t *testing.T) {
	// 124: NewHTTPHandler(nil) registers /issuer-metadata before the :144
	// early-return; GET /issuer-metadata sees service == nil and :125 writes 503
	// before PublishIssuerMetadata.
	h := NewHTTPHandler(nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/issuer-metadata", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil-service /issuer-metadata code = %d, want 503 (:125)", rr.Code)
	}
}

func TestNewHTTPHandlerNotReadyHarnessEndpointGuards(t *testing.T) {
	// 148/187/216: a non-nil not-ready Service with allowHarnessHTTPEndpoints set
	// registers the harness endpoints; each handler's service == nil ||
	// !service.ready() guard trips on !service.ready() (the service == nil clause
	// is dead — the :144 early-return skips harness registration when service ==
	// nil) and writes 503 before reading the request body. currentUnix returns 0
	// for the zero-value Service, so ready() short-circuits to false without
	// derefing blindRSAKey / spentTokens / metadata.
	h := NewHTTPHandler(&Service{allowHarnessHTTPEndpoints: true})
	for _, ep := range []string{"/blind-rsa/issue", "/voprf/verify", "/token/spend"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, ep, nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("not-ready %s code = %d, want 503 (:149/:188/:217)", ep, rr.Code)
		}
	}
}

func TestVerifierServiceForRequestNilReceiverGuard(t *testing.T) {
	// 576: s == nil short-circuits the compound :576 guard before !s.ready()
	// (which would deref s via currentUnix); :577 returns. The message is unique
	// to :577.
	_, _, err := (*Service)(nil).verifierServiceForRequest(protocol.IssuerVerifierRequest{})
	if err == nil {
		t.Fatal("verifierServiceForRequest(nil receiver) returned nil, want non-nil (:577)")
	}
	if !strings.Contains(err.Error(), "verifier unavailable") {
		t.Fatalf("nil-receiver err = %q, want \"...verifier unavailable\" (:577)", err.Error())
	}
}
