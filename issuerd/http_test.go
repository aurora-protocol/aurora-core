package issuerd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestHTTPDaemonReadinessHarnessCoversLiveIssuerSurface(t *testing.T) {
	report, err := RunHTTPReadinessHarness(200)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("issuer HTTP readiness failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"health":              report.HealthEndpoint,
		"metadata":            report.MetadataEndpoint,
		"blind_rsa":           report.BlindRSAIssueEndpoint,
		"voprf":               report.VOPRFVerifyEndpoint,
		"voprf_fail_closed":   report.VOPRFFailClosedEndpoint,
		"spend":               report.SpendEndpoint,
		"duplicate_rejected":  report.DuplicateSpendRejected,
		"redacted_failures":   report.RedactedFailureBodies,
		"method_restrictions": report.MethodRestrictions,
	} {
		if !passed {
			t.Fatalf("%s endpoint behavior was not covered: %+v", name, report)
		}
	}
	if len(report.Findings) != 0 {
		t.Fatalf("issuer HTTP readiness reported findings: %+v", report.Findings)
	}
}

func TestHTTPDaemonPublishesMetadataIssuesVerifiesAndSpends(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)

	health := serveHTTP(t, handler, http.MethodGet, "/healthz", nil)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"ready":true`) {
		t.Fatalf("health response = %d %s", health.Code, health.Body.String())
	}

	metadataResponse := serveHTTP(t, handler, http.MethodGet, "/issuer-metadata", nil)
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata response = %d %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	var metadataBody MetadataResponse
	decodeJSON(t, metadataResponse.Body.Bytes(), &metadataBody)
	metadata := service.PublishIssuerMetadata()
	if metadataBody.IssuerMetadataHash != hex.EncodeToString(mustIssuerMetadataHash(t, metadata)) {
		t.Fatalf("metadata hash response mismatch: %+v", metadataBody)
	}

	issueBody := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	issueResponse := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", issueBody)
	if issueResponse.Code != http.StatusOK {
		t.Fatalf("issue response = %d %s", issueResponse.Code, issueResponse.Body.String())
	}
	var issued IssueResponse
	decodeJSON(t, issueResponse.Body.Bytes(), &issued)
	proofBytes, err := hex.DecodeString(issued.AdmissionProof)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := DecodeAdmissionProofBytes(proofBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, 200); err != nil {
		t.Fatalf("issued proof did not verify: %v", err)
	}

	voprfBody := mustJSON(t, VOPRFVerifyRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       hex.EncodeToString(fill(0x81, 16)),
		RequestAuthPolicyID: 9,
	})
	voprfResponse := serveHTTP(t, handler, http.MethodPost, "/voprf/verify", voprfBody)
	if voprfResponse.Code != http.StatusOK || !strings.Contains(voprfResponse.Body.String(), `"verified":true`) {
		t.Fatalf("voprf response = %d %s", voprfResponse.Code, voprfResponse.Body.String())
	}

	spendResponse := serveHTTP(t, handler, http.MethodPost, "/token/spend", mustJSON(t, SpendRequest{AdmissionProof: issued.AdmissionProof}))
	if spendResponse.Code != http.StatusOK || !strings.Contains(spendResponse.Body.String(), `"spent":true`) {
		t.Fatalf("spend response = %d %s", spendResponse.Code, spendResponse.Body.String())
	}
	duplicate := serveHTTP(t, handler, http.MethodPost, "/token/spend", mustJSON(t, SpendRequest{AdmissionProof: issued.AdmissionProof}))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate spend response = %d %s", duplicate.Code, duplicate.Body.String())
	}
	if strings.Contains(duplicate.Body.String(), issued.AdmissionProof) || strings.Contains(duplicate.Body.String(), hex.EncodeToString(proof.TokenAuthenticator)) {
		t.Fatalf("duplicate failure leaked proof material: %s", duplicate.Body.String())
	}
}

func TestHTTPDaemonFailsClosedAndRestrictsMethods(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	if got := serveHTTP(t, handler, http.MethodPost, "/issuer-metadata", nil); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST metadata response = %d %s", got.Code, got.Body.String())
	}
	service.SetVOPRFVerifierAvailable(false)
	resp := serveHTTP(t, handler, http.MethodPost, "/voprf/verify", mustJSON(t, VOPRFVerifyRequest{
		ProofType:           registry.ProofVOPRFP384SHA384,
		RelayBucketID:       hex.EncodeToString(fill(0x81, 16)),
		RequestAuthPolicyID: 9,
	}))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("VOPRF outage response = %d %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "verifier unavailable") || strings.Contains(resp.Body.String(), "RelayBucketID") {
		t.Fatalf("VOPRF outage response not sanitized: %s", resp.Body.String())
	}
}

func TestHTTPDaemonRejectsTrailingJSON(t *testing.T) {
	service, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	body := mustJSON(t, IssueRequest{
		TokenNonce:            hex.EncodeToString(fill(0x44, 32)),
		RedemptionContextHash: hex.EncodeToString(fill(0x45, 48)),
		ExpiryUnix:            300,
	})
	body = append(body, []byte(`{"second":true}`)...)
	resp := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON response = %d %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "token_nonce") || strings.Contains(resp.Body.String(), "second") {
		t.Fatalf("trailing JSON failure leaked request details: %s", resp.Body.String())
	}
}

func serveHTTP(t *testing.T, handler http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeJSON(t *testing.T, raw []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode JSON %q: %v", string(raw), err)
	}
}

func mustIssuerMetadataHash(t *testing.T, metadata protocol.IssuerMetadata) []byte {
	t.Helper()
	hash, err := auroratrust.IssuerMetadataHash(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
