package relay

// Adversarial white-box coverage for the two count-0 "not-found" branches in
// relay/http_gateway.go: the ServeHTTP no-route-match arm (40-43) and the
// matchRoute miss return (58).
//
// HTTPGatewayHandler.ServeHTTP dispatches a request by matching r.URL.Path
// against h.Routes:
//
//	func (h HTTPGatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
//	    route, ok := h.matchRoute(r.URL.Path)   // 39
//	    if !ok {                                 // 40
//	        writeHTTPGatewayResponse(w, h.Gateway.HandleFailure(FailureInvalidCoverSlot)) // 41
//	        return                               // 42-43
//	    }
//	    ...
//	}
//
//	func (h HTTPGatewayHandler) matchRoute(path string) (HTTPGatewayRoute, bool) {
//	    for _, route := range h.Routes {
//	        if route.Path == path { return route, true }  // 54-56 (hit — already covered)
//	    }
//	    return HTTPGatewayRoute{}, false                  // 58 (miss — count-0)
//	}
//
//   - 40-43 — ServeHTTP no-match arm. A request whose path is not in h.Routes
//     makes matchRoute return ok=false, so ServeHTTP writes the failure
//     response and returns before reading the body. Reachable with a single
//     ServeHTTP call to a path absent from Routes.
//   - 58 — matchRoute miss return. The loop exhausts h.Routes without a
//     path equality and returns the zero route + false. Reachable directly
//     (in-package) by calling matchRoute with a non-matching path; also
//     reached transitively by the ServeHTTP no-match test above.
//
// The existing relay_test.go HTTP-gateway tests (TestHTTPGatewayForwards...,
// TestHTTPGatewayOwnedFailure..., TestHTTPGatewaySidecarFailure...) all
// request a path that IS in h.Routes, so they exercise the match-hit branch
// (54-56) and never the miss branches. Both 40-43 and 58 stayed count-0 even
// though a request to an unknown path plainly reaches them.
//
// The failure response uses Gateway{} (nil Origin) so HandleFailure returns
// the documented 404 "not found" cover response (see
// relay_gateway_coverage_test.go:68-76 for the nil-Origin HandleFailure
// contract). writeHTTPGatewayResponse writes resp.Status (404) then
// resp.Body ("not found"), so rec.Code == 404 and rec.Body == "not found"
// prove the 40-43 arm ran and produced the not-found cover — not a forward.
//
// This is an HTTP-level test reusing httptest.NewRecorder / httptest.NewRequest
// and Gateway{} — no new package-level helpers, no context.Context (no SA1012
// surface), no goroutine, no network. matchRoute is unexported, so the direct
// miss test lives in-package alongside ServeHTTP.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPGatewayMatchRouteMissesUnknownPath(t *testing.T) {
	// 58: a path absent from Routes exhausts the loop and returns the zero
	// route + false. The handler's other fields are irrelevant — matchRoute
	// reads only h.Routes.
	h := HTTPGatewayHandler{
		Routes: []HTTPGatewayRoute{
			{Path: "/assets/app.bin", ClassID: 2, Kind: CoverRequestOrdinary},
		},
	}
	route, ok := h.matchRoute("/does/not/exist")
	if ok {
		t.Fatal("matchRoute(unknown path) ok = true, want false (:58 should miss)")
	}
	if route != (HTTPGatewayRoute{}) {
		t.Fatalf("matchRoute(unknown path) route = %+v, want zero HTTPGatewayRoute{}", route)
	}
}

func TestHTTPGatewayServeHTTPRejectsUnknownPath(t *testing.T) {
	// 40-43: a request whose path is not in Routes makes matchRoute return
	// ok=false, so ServeHTTP writes HandleFailure(FailureInvalidCoverSlot) and
	// returns before reading the body. With a nil Origin (Gateway{}) that
	// failure resolves to the 404 "not found" cover response, proving the
	// not-found arm ran — not a forward to an origin.
	h := HTTPGatewayHandler{
		Gateway: Gateway{},
		Routes: []HTTPGatewayRoute{
			{Path: "/assets/app.bin", ClassID: 2, Kind: CoverRequestOrdinary},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "https://cover.example/unknown/path", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("ServeHTTP(unknown path) code = %d, want %d (:40-43 should return the not-found cover)", rec.Code, http.StatusNotFound)
	}
	if rec.Body.String() != "not found" {
		t.Fatalf("ServeHTTP(unknown path) body = %q, want \"not found\" (nil-Origin HandleFailure cover)", rec.Body.String())
	}
}
