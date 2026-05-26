package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHarnessHandlerServesCoverAndIssuerEndpoints(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte("<html>cover</html>"),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}

	health := serveRequest(handler, http.MethodGet, "/healthz", nil)
	if health.status != http.StatusOK || !bytes.Contains(health.body, []byte(`"ready":true`)) {
		t.Fatalf("health endpoint = %d %s", health.status, health.body)
	}

	cover := serveRequest(handler, http.MethodGet, "/ordinary-origin-path", nil)
	if cover.status != http.StatusOK || string(cover.body) != "<html>cover</html>" {
		t.Fatalf("cover origin response = %d %q", cover.status, cover.body)
	}

	metadata := serveRequest(handler, http.MethodGet, "/issuer/issuer-metadata", nil)
	if metadata.status != http.StatusOK || !bytes.Contains(metadata.body, []byte("issuer_metadata_hash")) {
		t.Fatalf("issuer metadata endpoint = %d %s", metadata.status, metadata.body)
	}

	issueBody := mustJSON(t, map[string]any{
		"token_nonce":             strings.Repeat("44", 32),
		"redemption_context_hash": strings.Repeat("45", 48),
		"expiry_unix":             uint64(250),
	})
	issue := serveRequest(handler, http.MethodPost, "/issuer/blind-rsa/issue", issueBody)
	if issue.status != http.StatusOK || !bytes.Contains(issue.body, []byte("admission_proof")) {
		t.Fatalf("issuer issue endpoint = %d %s", issue.status, issue.body)
	}

	var issued struct {
		AdmissionProof string `json:"admission_proof"`
	}
	if err := json.Unmarshal(issue.body, &issued); err != nil {
		t.Fatalf("issue response JSON failed: %v", err)
	}
	if raw, err := hex.DecodeString(issued.AdmissionProof); err != nil || len(raw) == 0 {
		t.Fatalf("issue response admission proof is not non-empty hex: len=%d err=%v", len(raw), err)
	}
}

func TestRunReadinessHarnessCoversLinuxServerSurface(t *testing.T) {
	report, err := RunReadinessHarness(200)
	if err != nil {
		t.Fatalf("RunReadinessHarness failed: %v", err)
	}
	if !report.Passed {
		t.Fatalf("server readiness report failed: %+v", report)
	}
	if !report.HealthEndpoint || !report.CoverEndpoint || !report.IssuerMetadataEndpoint || !report.BlindRSAIssueEndpoint {
		t.Fatalf("server readiness report missing coverage: %+v", report)
	}
}

func TestRunReadinessHarnessUsesValidDefaultClock(t *testing.T) {
	report, err := RunReadinessHarness(0)
	if err != nil {
		t.Fatalf("RunReadinessHarness failed: %v", err)
	}
	if !report.Passed || !report.BlindRSAIssueEndpoint {
		t.Fatalf("zero-value readiness report failed: %+v", report)
	}
}

type servedResponse struct {
	status int
	body   []byte
}

func serveRequest(handler http.Handler, method, path string, body []byte) servedResponse {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return servedResponse{status: rec.Code, body: rec.Body.Bytes()}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	return out
}
