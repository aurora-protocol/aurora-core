package issuerd

// Adversarial white-box branch coverage for three count-0 service/decode
// error-propagation guards in the harness HTTP handlers (issuerd/http.go):
//
//	mux.HandleFunc("/blind-rsa/issue", ...) {
//	    ...nonce, redemptionContext decode ok...
//	    proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{...})
//	    if err != nil {                                          // :175 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "issue request rejected")
//	    }
//	    ...
//	mux.HandleFunc("/token/spend", ...) {
//	    ...decodeJSONBody ok...
//	    raw, err := hex.DecodeString(req.AdmissionProof)
//	    if err != nil {                                          // :229 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "invalid spend request")
//	    }
//	    proof, err := DecodeAdmissionProofBytes(raw)
//	    if err != nil {                                          // :234 <-- COUNT 0
//	        writeError(w, http.StatusBadRequest, "invalid spend request")
//	    }
//	    ...
//
// http_test.go:TestHTTPDaemonPublishesMetadataIssuesVerifiesAndSpends exercises the happy
// path: a VALID issue request (ExpiryUnix = nowUnix+100, inside the metadata validity
// window) and a VALID spend (a freshly-issued, hex-encoded AdmissionProof). So the three
// err BODIES (:175/:229/:234) stay count 0: no fixture sends a structurally-valid issue
// request whose ExpiryUnix the service rejects, or a /token/spend body with a malformed
// / structurally-invalid AdmissionProof.
//
// This file drives each guard through the real handler (NewHTTPHandler(NewHarnessService(200)))
// via httptest. The guards fire AFTER input validation but BEFORE any successful
// issuance/spend, so the test is deterministic (no double-spend, no crypto on the failing
// path — IssueBlindRSA2048 rejects ExpiryUnix at :367 before signing; DecodeAdmissionProofBytes
// is a pure wire decode):
//
//	- :175 -> POST /blind-rsa/issue with valid 32-byte TokenNonce + 48-byte
//	  RedemptionContextHash but ExpiryUnix = 0 (<= harness nowUnix=200), so
//	  IssueBlindRSA2048 rejects at service.go:367 ("token expiry outside issuer metadata
//	  validity") and :175 writes 400 "issue request rejected".
//	- :229 -> POST /token/spend with AdmissionProof = "ZZ" (non-hex), so
//	  hex.DecodeString fails at :228 and :229 writes 400 "invalid spend request".
//	- :234 -> POST /token/spend with AdmissionProof = valid hex that decodes to a
//	  too-short raw, so :228 passes but DecodeAdmissionProofBytes fails at :233 and :234
//	  writes 400 "invalid spend request".
//
// The per-line coverage flips (:175/:229/:234 0->1) are the rigorous proof.

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestHarnessHTTPRejectsInvalidIssueExpiryAndSpendProof(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)

	// :175 — valid TokenNonce + RedemptionContextHash (so :160/:165 decode ok) but
	// ExpiryUnix = 0, which is <= the harness nowUnix (200). IssueBlindRSA2048 rejects at
	// service.go:367 ("token expiry outside issuer metadata validity") before signing, so
	// :175 writes 400 "issue request rejected".
	issueBadExpiry := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            0,
	})
	if resp := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", issueBadExpiry); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "issue request rejected") {
		t.Fatalf(":175 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "issue request rejected")
	}

	// :229 — malformed-hex AdmissionProof. hex.DecodeString("ZZ") fails at :228, so :229
	// writes 400 "invalid spend request" before the proof is decoded.
	spendBadHex := mustJSON(t, SpendRequest{AdmissionProof: "ZZ"})
	if resp := serveHTTP(t, handler, http.MethodPost, "/token/spend", spendBadHex); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid spend request") {
		t.Fatalf(":229 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "invalid spend request")
	}

	// :234 — valid hex (decodes to a too-short 1-byte raw) so :228 passes, but
	// DecodeAdmissionProofBytes rejects the raw at :233 (reader.Err, same failure mode as
	// TestDecodeAdmissionProofBytesRejectsMalformedRaw), so :234 writes 400.
	spendBadProof := mustJSON(t, SpendRequest{AdmissionProof: "00"})
	if resp := serveHTTP(t, handler, http.MethodPost, "/token/spend", spendBadProof); resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "invalid spend request") {
		t.Fatalf(":234 response = %d %q, want 400 + %q", resp.Code, resp.Body.String(), "invalid spend request")
	}
}
