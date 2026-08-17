package relay

// Adversarial white-box coverage for the two count-0 branches in the
// RequestSidecarOriginSlot + CoverRequestOrdinary dispatch arm of
// relay/http_gateway.go's handleMatchedRoute (101-104):
//
//	case registry.RequestSidecarOriginSlot:
//	    if route.Kind == CoverRequestOrdinary {                              // 101
//	        if origin, ok := h.Gateway.Origin.(HTTPSidecarOrigin); ok {       // 102
//	            return origin.ForwardSidecarHTTPRequest(r.Clone(...), body...) // 103
//	        }                                                                 // 104
//	    }
//
//   - 101 — the sidecar-slot ordinary-kind condition. The existing sidecar
//     HTTP-gateway tests (TestHTTPGatewaySidecarFailureRedactsBodyAtHTTPBoundary,
//     TestHTTPGatewayOwnedFailureConsumesBodyAtHTTPBoundary) request a
//     sidecar-slot route (ClassID 3) but with Kind CoverRequestCapsule, so the
//     ordinary-kind condition at 101 is false and dispatch falls through to
//     HandleCoverRequest at 107. Driving the route with Kind CoverRequestOrdinary
//     makes 101 true.
//   - 102-104 — the HTTPSidecarOrigin type assertion. With an Origin that
//     implements HTTPSidecarOrigin (recordingHTTPOrigin exposes
//     ForwardSidecarHTTPRequest, see relay_test.go:832), the assertion succeeds
//     and ForwardSidecarHTTPRequest runs, returning Response{Status: 206}. That
//     206 + a recorded sidecar forward (and a recorded path/body) proves the
//     102-104 arm ran — not the fall-through HandleCoverRequest, which would
//     return the origin's NormalResponse (200 "cover") without advancing the
//     sidecar forward counter.
//
// The pass-through analogue (94-98, RequestOriginPassThrough + Ordinary +
// HTTPForwardingOrigin) is already covered by TestHTTPGatewayForwardsOriginPassThroughRoute;
// only the sidecar-ordinary arm was count-0.
//
// HTTP-level test reusing coverTemplateForRelayTest (class 3 = sidecar slot),
// recordingHTTPOrigin, and httptest — no new package-level helpers, no
// context.Context (no SA1012 surface), no goroutine, no real network.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPGatewayForwardsSidecarOriginOrdinaryRoute(t *testing.T) {
	// 101-104: a sidecar-slot route with an ordinary kind and an Origin that
	// implements HTTPSidecarOrigin dispatches to ForwardSidecarHTTPRequest,
	// returning 206 and recording exactly one sidecar forward with the
	// request's path and body. (A fall-through to HandleCoverRequest would
	// return 200 "cover" and leave the sidecar forward counter at 0.)
	origin := &recordingHTTPOrigin{recordingOrigin: recordingOrigin{normal: Response{Status: 200, Body: []byte("cover")}}}
	handler := HTTPGatewayHandler{
		Gateway:  Gateway{Origin: origin},
		Template: coverTemplateForRelayTest(),
		Routes: []HTTPGatewayRoute{{
			Path:    "/sidecar/ordinary",
			ClassID: 3,
			Kind:    CoverRequestOrdinary,
		}},
	}
	body := []byte("sidecar-ordinary-body")
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/sidecar/ordinary", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("ServeHTTP(sidecar ordinary) code = %d, want %d (:102-104 should forward via ForwardSidecarHTTPRequest)", rec.Code, http.StatusPartialContent)
	}
	if origin.httpSidecarForwarded != 1 {
		t.Fatalf("ServeHTTP(sidecar ordinary) httpSidecarForwarded = %d, want 1 (:103 ForwardSidecarHTTPRequest should run once)", origin.httpSidecarForwarded)
	}
	if origin.lastPath != "/sidecar/ordinary" {
		t.Fatalf("ServeHTTP(sidecar ordinary) lastPath = %q, want %q", origin.lastPath, "/sidecar/ordinary")
	}
	if !bytes.Equal(origin.lastHTTPBody, body) {
		t.Fatalf("ServeHTTP(sidecar ordinary) lastHTTPBody = %q, want %q", origin.lastHTTPBody, body)
	}
	// The pass-through counter must NOT advance: this is the sidecar arm, not
	// the pass-through arm, proving the right dispatch branch ran.
	if origin.httpForwarded != 0 {
		t.Fatalf("ServeHTTP(sidecar ordinary) httpForwarded = %d, want 0 (sidecar arm, not pass-through)", origin.httpForwarded)
	}
}
