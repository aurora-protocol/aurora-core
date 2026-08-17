package issuerd

// Adversarial white-box coverage for two count-0 nil-argument guards in the
// issuerd package: a nil-field guard in the production Blind RSA service
// constructor, and a nil-request guard in the methodHandler HTTP wrapper.
//
//   - production_service.go:35 NewProductionBlindRSAService
//     options.BlindRSAKey == nil -> "issuerd: Blind RSA private key is required"
//     (fires after the NowUnix == nil guard at :28 and the nowUnix == 0 guard at
//     :32, before the BlindRSAKey.Validate call at :38).
//   - http.go:460 methodHandler (returned closure)
//     r == nil -> writeError(w, 400, "invalid request") (first statement; fires
//     before the r.Method != method guard at :464 and before the wrapped
//     handler is dispatched at :472).
//
// The existing issuerd tests drive NewProductionBlindRSAService only with a
// real Blind RSA key (so :28 and :32 are covered but :35 stays count-0), and
// drive methodHandler's closure only through the HTTP mux with a real request,
// so the :460 nil-request branch stayed count-0 even though each is plainly
// reachable.
//
// Proof technique:
//
//   - NewProductionBlindRSAService (nil-field clean return): pass
//     ProductionBlindRSAServiceOptions with NowUnix set to a function returning
//     a non-zero time (so the :28 NowUnix == nil guard and the :32 nowUnix == 0
//     guard both pass) and BlindRSAKey left nil. The :35 guard returns the
//     "Blind RSA private key is required" error before Validate is called, so
//     no real key is constructed and the test is pure. The assertion on the
//     "Blind RSA private key is required" substring uniquely identifies :35
//     (the earlier :28 / :32 guards return different messages and are not
//     reached because NowUnix is non-nil and returns a non-zero time).
//
//   - methodHandler (nil-argument HTTP-handler): call the closure returned by
//     methodHandler with an httptest.NewRecorder() and a nil *http.Request. The
//     :460 guard fires as the first statement and calls writeError(w, 400, ...),
//     which (via writeJSON) does w.WriteHeader(400), so the recorder's status is
//     400. The wrapped handler is never called (the closure returns at :462
//     before :472), so a no-op handler suffices. The 400 status uniquely proves
//     the :460 guard's body ran. httptest is in-memory; no network, no IO.
//
// No context is involved in either guard, so there is no SA1012 surface.
// In-package (package issuerd) because methodHandler is unexported.
// NewProductionBlindRSAService and ProductionBlindRSAServiceOptions are
// exported but kept in-package for consistency with the methodHandler test.
//
// This test file adds only TestXxx entry points and references existing
// exported (NewProductionBlindRSAService, ProductionBlindRSAServiceOptions) and
// unexported in-package (methodHandler) symbols, so it adds no U1000 surface.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewProductionBlindRSAServiceNilBlindRSAKeyGuard(t *testing.T) {
	// 35: NowUnix is non-nil (passes :28) and returns 1, a non-zero time (passes
	// :32), so a nil BlindRSAKey reaches :35, which returns "Blind RSA private
	// key is required" before the :38 Validate call. No real key is
	// constructed; none of the other options fields are touched before :35.
	_, err := NewProductionBlindRSAService(ProductionBlindRSAServiceOptions{
		NowUnix: func() uint64 { return 1 },
	})
	if err == nil {
		t.Fatal("NewProductionBlindRSAService(nil BlindRSAKey) err = nil, want non-nil (:35 should reject)")
	} else if !strings.Contains(err.Error(), "Blind RSA private key is required") {
		t.Fatalf("NewProductionBlindRSAService(nil BlindRSAKey) err = %q, want substring \"Blind RSA private key is required\" (:35)", err.Error())
	}
}

func TestMethodHandlerNilRequestGuard(t *testing.T) {
	// 460: the closure returned by methodHandler rejects a nil *http.Request at
	// the first statement with a 400, before the r.Method check at :464 and
	// before the wrapped handler is dispatched at :472. The wrapped handler is
	// never called, so a no-op handler suffices. httptest captures the 400.
	rec := httptest.NewRecorder()
	methodHandler(http.MethodPost, func(http.ResponseWriter, *http.Request) {})(rec, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("methodHandler(nil request) status = %d, want %d (:460 -> writeError 400)", rec.Code, http.StatusBadRequest)
	}
}
