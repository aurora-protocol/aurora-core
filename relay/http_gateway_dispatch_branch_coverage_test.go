package relay

// Adversarial white-box coverage for two more count-0 branches in
// relay/http_gateway.go: the handleMatchedRoute unknown-class rejection
// (90-92) and the writeHTTPGatewayResponse default-status path (124-126).
//
//   - 90-92 — handleMatchedRoute's findRequestClass miss. After ServeHTTP
//     matches a route by path (so 40/58 are NOT hit) and reads the body,
//     serveMatchedRoute -> handleMatchedRoute looks up route.ClassID in
//     h.Template. When the route's ClassID is absent from the template,
//     findRequestClass returns ok=false and handleMatchedRoute returns
//     h.Gateway.HandleFailure(FailureInvalidCoverSlot). With a nil Origin
//     (Gateway{}) that resolves to the 404 "not found" cover — proving the
//     unknown-class arm ran, not a forward. The existing relay_test.go
//     HTTP-gateway tests always pair a route's ClassID with a template that
//     contains it, so the miss arm stayed count-0.
//
//   - 124-126 — writeHTTPGatewayResponse's status-default branch. The helper
//     substitutes http.StatusOK for a Response with Status == 0 before
//     WriteHeader. Every caller in the existing tests returns a Response with
//     a non-zero Status (404 from HandleFailure-nil-Origin, 200/204 from
//     origins), so the 0->200 default stayed count-0. Reachable directly
//     (in-package) by calling writeHTTPGatewayResponse with Response{Status:
//     0}; the recorder then reports Code 200, proving 124-126 ran.
//
// Both branches are reachable with no real origin and no goroutine. The :90
// test is HTTP-level (httptest.NewRecorder / NewRequest + Gateway{}); the
// :124 test is a direct in-package call to the unexported helper. No
// context.Context (no SA1012 surface), no network.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestHTTPGatewayServeHTTPRejectsMatchedPathWithUnknownClassID(t *testing.T) {
	// 90-92: the path matches Routes (so dispatch reaches handleMatchedRoute),
	// but route.ClassID is absent from h.Template, so findRequestClass misses
	// and HandleFailure(FailureInvalidCoverSlot) is returned. With a nil Origin
	// that failure is the 404 "not found" cover, proving the unknown-class arm
	// ran rather than a forward.
	h := HTTPGatewayHandler{
		Gateway: Gateway{},
		Template: protocol.CoverTemplate{
			RequestClasses: []protocol.RequestClass{
				{ClassID: 1, ClassType: 1},
			},
		},
		Routes: []HTTPGatewayRoute{
			{Path: "/assets/app.bin", ClassID: 99, Kind: CoverRequestOrdinary},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/assets/app.bin", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("ServeHTTP(matched path, unknown ClassID) code = %d, want %d (:90-92 should return the not-found cover)", rec.Code, http.StatusNotFound)
	}
	if rec.Body.String() != "not found" {
		t.Fatalf("ServeHTTP(matched path, unknown ClassID) body = %q, want \"not found\" (nil-Origin HandleFailure cover)", rec.Body.String())
	}
}

func TestWriteHTTPGatewayResponseDefaultsZeroStatusToOK(t *testing.T) {
	// 124-126: a Response with Status == 0 is written as http.StatusOK. The
	// recorder reports Code 200 and the body verbatim, proving the default ran
	// (a non-zero status would have been written as-is).
	rec := httptest.NewRecorder()
	writeHTTPGatewayResponse(rec, Response{Status: 0, Body: []byte("default-body")})
	if rec.Code != http.StatusOK {
		t.Fatalf("writeHTTPGatewayResponse(Status 0) code = %d, want %d (:124-126 should default to OK)", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "default-body" {
		t.Fatalf("writeHTTPGatewayResponse(Status 0) body = %q, want %q", rec.Body.String(), "default-body")
	}
}
