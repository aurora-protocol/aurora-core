package issuerd

// Adversarial white-box branch coverage for the four count-0 request
// input-validation guards in the harness HTTP handlers (issuerd/http.go):
//
//	mux.HandleFunc("/blind-rsa/issue", ...) {
//	    var req IssueRequest
//	    if err := decodeJSONBody(r, &req); err != nil { ... }   // :153 (covered)
//	    ...
//	    nonce, err := decodeHexFixed(req.TokenNonce, 32)
//	    if err != nil {                                           // :161 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "invalid issue request")
//	    }
//	    redemptionContext, err := decodeHexFixed(req.RedemptionContextHash, 48)
//	    if err != nil {                                           // :166 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "invalid issue request")
//	    }
//	    ...
//	mux.HandleFunc("/voprf/verify", ...) {
//	    var req VOPRFVerifyRequest
//	    if err := decodeJSONBody(r, &req); err != nil {           // :192 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "invalid verifier request")
//	    }
//	    ...
//	    relayBucketID, err := decodeHexFixed(req.RelayBucketID, 16)
//	    if err != nil {                                           // :200 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "invalid verifier request")
//	    }
//
// The harness handlers are registered only when service != nil && allowHarnessHTTPEndpoints
// (http.go:144). http_test.go:TestHTTPDaemonPublishesMetadataIssuesVerifiesAndSpends builds
// a ready service via NewHarnessService(200) and exercises /blind-rsa/issue and /voprf/verify
// with VALID bodies — so the success paths (:153/:160/:165/:192-success/:199) are covered but
// the four err BODIES (:161/:166/:192/:200) stay count 0: no fixture sends a structurally-valid
// JSON request whose hex field fails decodeHexFixed, or a malformed JSON body to /voprf/verify.
//
// This file drives each guard through the real handler (NewHTTPHandler(NewHarnessService(200)))
// via httptest, asserting a 400 response containing the expected error string. The guards fire
// BEFORE any crypto/issuance work (decodeHexFixed is a pure hex+length check), so the test is
// fully deterministic: no goroutine, no network, no cgo, no signatures.
//
//	- :161 -> POST /blind-rsa/issue with valid JSON, malformed TokenNonce hex ("ZZ").
//	- :166 -> POST /blind-rsa/issue with a VALID 32-byte TokenNonce but malformed
//	  RedemptionContextHash hex ("ZZ") so :160 passes and :165 reaches the decode.
//	- :192 -> POST /voprf/verify with a malformed JSON body so decodeJSONBody fails.
//	- :200 -> POST /voprf/verify with valid JSON but malformed RelayBucketID hex ("ZZ")
//	  so :192 passes and :199 reaches the decode.
//
// The per-line coverage flips (:161/:166/:192/:200 0->1) are the rigorous proof.

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestHarnessHTTPRejectsMalformedRequestFields(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)

	// :161 — malformed TokenNonce hex. decodeHexFixed("ZZ", 32) fails (non-hex + wrong
	// length) at :160, so :161 writes 400 "invalid issue request". RedemptionContextHash
	// is valid so the request is otherwise well-formed JSON.
	issueBadNonce := mustJSON(t, IssueRequest{
		TokenNonce:            "ZZ",
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	if resp := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", issueBadNonce); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid issue request") {
		t.Fatalf(":161 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "invalid issue request")
	}

	// :166 — valid 32-byte TokenNonce (so :160 passes) but malformed RedemptionContextHash
	// hex ("ZZ"), so :165 decodeHexFixed("ZZ", 48) fails and :166 writes 400.
	issueBadCtx := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: "ZZ",
		ExpiryUnix:            300,
	})
	if resp := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", issueBadCtx); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid issue request") {
		t.Fatalf(":166 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "invalid issue request")
	}

	// :192 — malformed JSON body to /voprf/verify. decodeJSONBody fails at :191, so :192
	// writes 400 "invalid verifier request" before any field decode.
	if resp := serveHTTP(t, handler, http.MethodPost, "/voprf/verify", []byte("{not valid json")); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid verifier request") {
		t.Fatalf(":192 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "invalid verifier request")
	}

	// :200 — valid JSON to /voprf/verify (so :191 decodeJSONBody passes / :192 not taken)
	// but malformed RelayBucketID hex ("ZZ"), so :199 decodeHexFixed("ZZ", 16) fails and
	// :200 writes 400.
	voprfBadBucket := mustJSON(t, VOPRFVerifyRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       "ZZ",
		RequestAuthPolicyID: 9,
	})
	if resp := serveHTTP(t, handler, http.MethodPost, "/voprf/verify", voprfBadBucket); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid verifier request") {
		t.Fatalf(":200 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "invalid verifier request")
	}
}
