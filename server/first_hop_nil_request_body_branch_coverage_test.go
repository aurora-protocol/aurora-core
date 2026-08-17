package server

// Prototype (temporary): adversarial white-box coverage for the count-0
// nil-request-Body guard in FirstHopHandler.ServeHTTP.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFirstHopHandlerNilRequestBodyGuardSetsNoBody(t *testing.T) {
	handler := &FirstHopHandler{}
	request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	request.Body = nil // force the count-0 nil-Body guard (:402)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	// :402 sets request.Body = http.NoBody so the cancelSession closure's
	// :407 request.Body.Close() (used on other paths) cannot nil-deref a nil
	// io.ReadCloser. This request carries no firstHopConnectionContextKey, so
	// :411 -> :412 stopSession() -> :413 serveUnclaimedCover ->
	// isGatewayTarget false (Host "example.com" != zero h.authority) ->
	// serveCoverRequest(w, r, nil, nil) -> :235 coverOrigin==nil ->
	// serveCoverOrigin(w, nil) -> :218 origin==nil -> http.NotFound -> 404.
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("nil-Body request status = %d, want 404 (nil origin -> http.NotFound)", recorder.Code)
	}
	if request.Body == nil {
		t.Fatal("request.Body still nil after ServeHTTP (:403 should set http.NoBody)")
	}
}
