package ops

// Adversarial white-box coverage for the count-0 first-statement nil-field
// safety guard on the mTLS verifier transport. ExchangeIssuerVerifier begins
// with `if t.Client == nil { return ... }` so a caller that drives a zero-value
// MTLSIssuerVerifierTransport (no *http.Client configured) does not proceed
// into the verifier HTTP request path or dereference the nil client. The
// existing ops tests only ever drive a transport with a populated Client
// (constructed via the production transport builder), so the nil-field guard
// stayed count-0 even though it is plainly reachable with a zero-value
// transport.
//
//   - verifier_transport.go:69 (MTLSIssuerVerifierTransport).ExchangeIssuerVerifier
//     (service protocol.IssuerVerifierServiceRecord, req protocol.IssuerVerifierRequest)
//     t.Client == nil -> (zero protocol.IssuerVerifierResponse{},
//     "ops: missing mTLS verifier HTTP client") (fires before
//     issuerVerifierEndpoint / issuerVerifierHTTPClient / the request encode).
//     The "missing mTLS verifier HTTP client" message distinguishes the
//     nil-client path from a populated client that hits the endpoint / HTTP
//     client errors.
//
// MTLSIssuerVerifierTransport has a VALUE receiver, so a zero-value composite
// literal MTLSIssuerVerifierTransport{} (Client == nil) is the adversarial
// input. The service / req arguments are never read because the guard returns
// first, so zero-value records are safe. This is a nil-FIELD first-statement
// guard (on a field of the receiver). No context is involved, so there is no
// SA1012 surface. No network, no goroutine, no TLS handshake — the guard
// returns before any HTTP client is touched, so the test is pure and cannot
// perturb the ops integration tests. The test is in-package (package ops).
//
// This test file adds only a TestXxx entry point and uses existing exported
// types, so it adds no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestMTLSIssuerVerifierTransportNilClientGuard(t *testing.T) {
	// 69: a zero-value MTLSIssuerVerifierTransport has Client == nil, so the
	// first-statement guard returns before issuerVerifierEndpoint / the HTTP
	// client path. The "missing mTLS verifier HTTP client" message
	// distinguishes the nil-client path from a populated client. The service /
	// req args are never read, so zero-value records are safe.
	t0 := MTLSIssuerVerifierTransport{}
	resp, err := t0.ExchangeIssuerVerifier(protocol.IssuerVerifierServiceRecord{}, protocol.IssuerVerifierRequest{})
	if err == nil {
		t.Fatal("ExchangeIssuerVerifier(zero) err = nil, want non-nil (:69 should reject)")
	} else if !strings.Contains(err.Error(), "missing mTLS verifier HTTP client") {
		t.Fatalf("ExchangeIssuerVerifier(zero) err = %q, want substring \"missing mTLS verifier HTTP client\" (:69)", err.Error())
	}
	// IssuerVerifierResponse carries several []byte fields (ServiceID,
	// RequestHash, TokenSpentKey, ResponseNonce, ServiceSignature) so it is not
	// comparable with !=; assert on the ResponseVersion uint64 scalar, which is 0
	// for the zero value the guard returns (a populated response would carry a
	// non-zero version).
	if resp.ResponseVersion != 0 {
		t.Fatalf("ExchangeIssuerVerifier(zero) resp.ResponseVersion = %d, want 0 (:69)", resp.ResponseVersion)
	}
}
