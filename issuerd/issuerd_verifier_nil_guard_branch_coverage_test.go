package issuerd

// Adversarial white-box coverage for the two count-0 nil guards deep inside the
// issuerd verifier path (issuerd/service.go), both behind a successful
// verifierServiceForRequest. A prior nil-receiver pillar (nil_receiver_branch_
// coverage_test.go) explicitly deferred these as "reachable only via a real
// [fully-constructed verifier] service" — this file supplies that service via the
// existing NewHarnessService + verifierHTTPTestRequest harness and flips both.
//
// Coverage targets (baseline measured on main; both bodies COUNT 0 while their
// conditions were already evaluated):
//   - service.go:564  AuthorizeVerifierRequestClient: cert == nil
//     -> "issuerd: verifier request lacks relay client certificate"
//   - service.go:612  verifierServiceForRequest: signer == nil
//     -> "issuerd: verifier service signer unavailable"
//
// Reuses NewHarnessService(200) (service.go:84) + verifierHTTPTestRequest
// (http_test.go:750), the same harness the happy-path VerifyIssuerVerifierRequest
// tests (TestVerifierServiceRejectsEmptyAuthenticatorBeforeSpending etc.) use to
// drive a request through verifierServiceForRequest successfully. The ONLY changes
// are the assertion target:
//   - :564 — call AuthorizeVerifierRequestClient(req, nil) with a nil cert.
//     verifierServiceForRequest(req) still succeeds (:560), then the :564 nil-cert
//     guard fires before the :567 authorizedRelayKeys loop.
//   - :612 — delete the matched service's signer from verifierServiceSigners
//     AFTER building the request (verifierHTTPTestRequest does not read
//     verifierServiceSigners, so the request stays valid), then call
//     VerifyIssuerVerifierRequest(req). verifierServiceForRequest still matches
//     exactly one service (:608 len(matched)==1) but its signer is nil at :611 ->
//     :612 rejects.
//
// In-package (package issuerd) because verifierServiceForRequest and the
// verifierServiceSigners field are unexported. No context is involved, so there is
// no SA1012 surface. This test file adds only TestXxx entry points and references
// existing in-package (NewHarnessService, PublishIssuerMetadata,
// verifierHTTPTestRequest, AuthorizeVerifierRequestClient,
// VerifyIssuerVerifierRequest, verifierServiceSigners) symbols and stdlib
// strings / testing, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestAuthorizeVerifierRequestClientRejectsNilCertificate(t *testing.T) {
	// :564 cert == nil: a valid verifier request that passes verifierServiceForRequest
	// (:560), then a nil client certificate is rejected before the authorizedRelayKeys
	// authorization loop.
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	req := verifierHTTPTestRequest(t, service, verifierService)
	if err := service.AuthorizeVerifierRequestClient(req, nil); err == nil {
		t.Fatal("AuthorizeVerifierRequestClient(nil cert) err = nil, want non-nil (:564 should reject)")
	} else if !strings.Contains(err.Error(), "lacks relay client certificate") {
		t.Fatalf("nil cert err = %q, want substring \"lacks relay client certificate\" (:565)", err.Error())
	}
}

func TestVerifierServiceForRequestRejectsSignerlessMatchedService(t *testing.T) {
	// :612 signer == nil: a request that still matches exactly one verifier service
	// (:608 len(matched)==1) but whose signer was never registered (or was removed)
	// in verifierServiceSigners, so :611 yields a nil signer and :612 rejects.
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	verifierService := service.PublishIssuerMetadata().VerifierServices[0]
	req := verifierHTTPTestRequest(t, service, verifierService)
	// Remove the registered signer for the matched service. verifierHTTPTestRequest
	// does not read verifierServiceSigners, so the request built above stays valid;
	// the matched service still passes Allows (:603) so len(matched)==1, but :611 is
	// now nil -> :612.
	delete(service.verifierServiceSigners, string(verifierService.ServiceID))
	if _, err := service.VerifyIssuerVerifierRequest(req); err == nil {
		t.Fatal("VerifyIssuerVerifierRequest(signerless matched service) err = nil, want non-nil (:612 should reject)")
	} else if !strings.Contains(err.Error(), "verifier service signer unavailable") {
		t.Fatalf("signerless err = %q, want substring \"verifier service signer unavailable\" (:613)", err.Error())
	}
}
