package relay

// Coverage for the coverDeploymentProbeOrigin forwarding stubs at
// cover_deployment.go:265/:271/:289. The deployment harness drives the probe
// origin almost exclusively through failure paths (asserting that nothing was
// forwarded) and the pass-through path goes through ForwardHTTPRequest, so
// ForwardRequest, ForwardSidecarRequest, and ForwardSidecarHTTPRequest were
// never called. These are hermetic test-double methods; the direct contract
// worth pinning is: counter incremented, body stored as an independent copy,
// and the canned status returned (204 ordinary / 206 sidecar).

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCoverDeploymentProbeOriginForwardRequestRecordsIndependentCopy(t *testing.T) {
	origin := &coverDeploymentProbeOrigin{}
	body := []byte("ordinary body")
	resp := origin.ForwardRequest(body)
	if resp.Status != http.StatusNoContent {
		t.Fatalf("ForwardRequest status = %d, want %d", resp.Status, http.StatusNoContent)
	}
	if origin.forwarded != 1 || !bytes.Equal(origin.lastBody, []byte("ordinary body")) {
		t.Fatalf("ForwardRequest recorded forwarded=%d lastBody=%q", origin.forwarded, origin.lastBody)
	}
	body[0] = 'X'
	if bytes.Equal(origin.lastBody, body) {
		t.Fatal("ForwardRequest lastBody aliases the caller's buffer")
	}
}

func TestCoverDeploymentProbeOriginForwardSidecarRequestRecordsIndependentCopy(t *testing.T) {
	origin := &coverDeploymentProbeOrigin{}
	body := []byte("sidecar body")
	resp := origin.ForwardSidecarRequest(body)
	if resp.Status != http.StatusPartialContent {
		t.Fatalf("ForwardSidecarRequest status = %d, want %d", resp.Status, http.StatusPartialContent)
	}
	if origin.sidecarForwarded != 1 || !bytes.Equal(origin.lastSidecarBody, []byte("sidecar body")) {
		t.Fatalf("ForwardSidecarRequest recorded sidecarForwarded=%d lastSidecarBody=%q", origin.sidecarForwarded, origin.lastSidecarBody)
	}
	body[0] = 'X'
	if bytes.Equal(origin.lastSidecarBody, body) {
		t.Fatal("ForwardSidecarRequest lastSidecarBody aliases the caller's buffer")
	}
}

func TestCoverDeploymentProbeOriginForwardSidecarHTTPRequestRecordsPathAndCopy(t *testing.T) {
	origin := &coverDeploymentProbeOrigin{}
	body := []byte("http sidecar body")
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/assets/sidecar", nil)
	resp := origin.ForwardSidecarHTTPRequest(req, body)
	if resp.Status != http.StatusPartialContent {
		t.Fatalf("ForwardSidecarHTTPRequest status = %d, want %d", resp.Status, http.StatusPartialContent)
	}
	if origin.httpSidecarForwarded != 1 || origin.lastPath != "/assets/sidecar" || !bytes.Equal(origin.lastHTTPBody, []byte("http sidecar body")) {
		t.Fatalf(
			"ForwardSidecarHTTPRequest recorded httpSidecarForwarded=%d lastPath=%q lastHTTPBody=%q",
			origin.httpSidecarForwarded, origin.lastPath, origin.lastHTTPBody,
		)
	}
	body[0] = 'X'
	if bytes.Equal(origin.lastHTTPBody, body) {
		t.Fatal("ForwardSidecarHTTPRequest lastHTTPBody aliases the caller's buffer")
	}
}
