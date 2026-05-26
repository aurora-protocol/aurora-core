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

func TestPacketBatchCodecMatchesInteroperabilityVector(t *testing.T) {
	batch := PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	}

	encoded, err := EncodePacketBatch(batch)
	if err != nil {
		t.Fatalf("EncodePacketBatch failed: %v", err)
	}
	if got, want := hex.EncodeToString(encoded), "000100020000000445000014"; got != want {
		t.Fatalf("packet batch vector = %s, want %s", got, want)
	}
	decoded, err := DecodePacketBatch(encoded)
	if err != nil {
		t.Fatalf("DecodePacketBatch failed: %v", err)
	}
	if len(decoded.Packets) != 1 || !bytes.Equal(decoded.Packets[0], batch.Packets[0]) || decoded.ProtocolNumbers[0] != 2 {
		t.Fatalf("decoded packet batch mismatch: %+v", decoded)
	}
}

func TestPacketBatchCodecRejectsEmptyPacketEntry(t *testing.T) {
	encodedEmptyPacket := []byte{
		0x00, 0x01,
		0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
	}

	if _, err := DecodePacketBatch(encodedEmptyPacket); err == nil {
		t.Fatal("DecodePacketBatch accepted an empty packet entry")
	}
}

func TestHarnessHandlerExchangesPacketBatchesThroughPrivateCarrierSlot(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte("<html>cover</html>"),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}
	inbound, err := EncodePacketBatch(PacketBatch{
		Packets:         [][]byte{{0x45, 0x00, 0x00, 0x14}},
		ProtocolNumbers: []uint16{2},
	})
	if err != nil {
		t.Fatalf("EncodePacketBatch failed: %v", err)
	}

	exchanged := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, inbound, "application/octet-stream")

	if exchanged.status != http.StatusOK {
		t.Fatalf("packet exchange status = %d body=%q", exchanged.status, exchanged.body)
	}
	if got := exchanged.header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("packet exchange content type = %q", got)
	}
	outbound, err := DecodePacketBatch(exchanged.body)
	if err != nil {
		t.Fatalf("DecodePacketBatch response failed: %v", err)
	}
	if len(outbound.Packets) != 1 || !bytes.Equal(outbound.Packets[0], []byte{0x45, 0x00, 0x00, 0x14}) || outbound.ProtocolNumbers[0] != 2 {
		t.Fatalf("packet exchange response mismatch: %+v", outbound)
	}
}

func TestPacketExchangeInvalidProbeFallsBackToCover(t *testing.T) {
	handler, err := NewHarnessHandler(HarnessOptions{
		NowUnix:   200,
		CoverBody: []byte("<html>cover</html>"),
	})
	if err != nil {
		t.Fatalf("NewHarnessHandler failed: %v", err)
	}

	probe := serveRequestWithContentType(handler, http.MethodPost, DefaultPacketExchangePath, []byte("not a packet batch"), "application/octet-stream")

	if probe.status != http.StatusOK || string(probe.body) != "<html>cover</html>" {
		t.Fatalf("invalid packet exchange did not fall back to cover: status=%d body=%q", probe.status, probe.body)
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
	if !report.PacketExchangeEndpoint {
		t.Fatalf("server readiness report did not cover packet exchange: %+v", report)
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
	header http.Header
	body   []byte
}

func serveRequest(handler http.Handler, method, path string, body []byte) servedResponse {
	return serveRequestWithContentType(handler, method, path, body, "application/json")
}

func serveRequestWithContentType(handler http.Handler, method, path string, body []byte, contentType string) servedResponse {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return servedResponse{status: rec.Code, header: rec.Result().Header, body: rec.Body.Bytes()}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	return out
}
