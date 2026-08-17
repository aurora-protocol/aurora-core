package server

// Adversarial white-box coverage for the two count-0 first-statement
// nil-safety guards in server/server.go and server/packet_device_exchange.go.
// Each guard exists so a caller that passes a nil cover origin / a nil read
// error does not proceed into the live cover / device-exchange path: the
// function returns at its very first statement, before any field is
// dereferenced (origin.NormalResponse) or any channel / mutex is touched
// (e.done, e.readErrMu, e.readErr). The existing server tests only ever drive
// a populated relay.Origin along the cover-origin path and a non-nil read
// error along the device-exchange read path, so the nil guards stayed
// count-0 even though each is plainly reachable.
//
//   - server.go:218 serveCoverOrigin(w http.ResponseWriter, origin relay.Origin)
//     origin == nil -> http.NotFound(w, nil); return (fires before
//     origin.NormalResponse / the Content-Type / WriteHeader / Write path).
//     http.NotFound writes only the 404 status and a plain-text body; it does
//     not consult the nil *http.Request, so an httptest.ResponseRecorder
//     captures the response and the 404 status distinguishes the nil-origin
//     path from a populated origin that serves cover content.
//   - packet_device_exchange.go:147 (*DevicePacketExchanger).setReadError(err error)
//     err == nil -> void no-op return (fires before the select on e.done /
//     e.readErrMu.Lock / the e.readErr assignment). A zero-value
//     DevicePacketExchanger is safe because the guard returns before any
//     field is read.
//
// These are nil-ARGUMENT first-statement guards. No context is involved, so
// there is no SA1012 surface. No network, no goroutine, no real device — the
// serveCoverOrigin guard only writes a 404 to an in-memory recorder, and the
// setReadError guard returns before any channel / mutex / field access, so
// neither can perturb the server's integration tests. The test is in-package
// (package server) because serveCoverOrigin and setReadError are unexported.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeCoverOriginNilArgumentGuard(t *testing.T) {
	// 218: serveCoverOrigin(nil origin) writes a 404 via http.NotFound and
	// returns before origin.NormalResponse. The recorder captures the status;
	// http.StatusNotFound distinguishes the nil-origin path from a populated
	// origin that serves cover content. http.NotFound does not consult the nil
	// request, so passing nil for the request is safe.
	rec := httptest.NewRecorder()
	serveCoverOrigin(rec, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("serveCoverOrigin(nil) code = %d, want %d (:218)", rec.Code, http.StatusNotFound)
	}
}

func TestDevicePacketExchangerSetReadErrorNilArgumentGuard(t *testing.T) {
	// 147: setReadError(nil) returns at the first statement before the select on
	// e.done / e.readErrMu.Lock / the e.readErr assignment. A zero-value
	// DevicePacketExchanger is safe because the guard returns before any field
	// is read. It is void; the proof is that the call completes without
	// panicking (a panic surfaces as a test failure).
	e := &DevicePacketExchanger{}
	e.setReadError(nil)
}
