package perf

// Adversarial white-box coverage for four branches of perf/load.go that the
// existing load_test.go suite never reaches. All four are exercised without
// any real network socket: two are construction-time / pre-dial guards driven
// directly, and two use the existing roundTripFunc fake transport (the same
// in-process transport the suite already relies on) so no connection is opened.
//
// Targets covered:
//
//   - RunCarrierLoad:62-64 — the `ctx == nil` guard. validateLoadInputs runs
//     first (line 59) and the existing TestRunCarrierLoadValidatesInputs only
//     drives validation failures with a non-nil context, so the nil-context
//     guard is never reached. A valid client/endpoint/options triple plus a
//     literal nil context passes validation and hits "perf: context is
//     required" before any request body or goroutine is created. Passing a
//     literal nil as a context.Context trips staticcheck SA1012, so the call
//     carries the codebase's standard lint directive (see
//     evidence/first_hop_test.go:62, relay/dns_upstream_branch_coverage_test.go).
//
//   - RunCarrierLoad:85-87 — the loadClient.CheckRedirect closure that returns
//     http.ErrUseLastResponse. The existing suite never serves a redirect, so
//     the closure body is never executed. A roundTripFunc returning a 302 with
//     a Location makes the http.Client invoke CheckRedirect; the closure
//     returns ErrUseLastResponse, so the 302 is returned as-is (NOT followed).
//     Attribution: with the closure, RoundTrip is called exactly once; if the
//     closure were absent the default CheckRedirect would follow the redirect
//     and call RoundTrip repeatedly. Asserting a single RoundTrip call AND a
//     failed request (302 != 200) proves the closure ran and prevented the
//     follow.
//
//   - executeCarrierLoadRequest:242-245 — the `closeErr != nil` branch after
//     response.Body.Close(). The existing suite serves httptest bodies whose
//     Close never errors. A roundTripFunc returning a 200 with a body whose
//     Close returns an error reaches this branch (the empty read succeeds, so
//     the readErr branch at 238 is skipped; the close-error branch fires and
//     returns "close response").
//
//   - countingBody.Read:293-295 — the `b.closed` guard returning
//     http.ErrBodyReadAfterClose. The countingBody is the request body; in
//     normal transport use Read is never invoked after Close, so the guard is
//     uncovered. Calling Read after Close on a newCountingBody hits it
//     directly — pure, no transport, no goroutine.
//
// Dead-by-design (documented, NOT contrived):
//   - RunCarrierLoad:67-69 and carrierLoadRequest:196-198 — the
//     carrierLoadRequest error propagations. carrierLoadRequest only fails if
//     server.EncodePacketBatch rejects the packet, but validateLoadInputs
//     constrains PacketBytes to [20, 65535] and server.maxPacketBytes == 65535,
//     so the validated packet is always within the encode limit and
//     EncodePacketBatch always succeeds. No input can reach these returns.
//   - executeCarrierLoadRequest:212-217 — the http.NewRequestWithContext error
//     branch. The endpoint has already passed validateLoadInputs (url.Parse
//     succeeds, host non-empty, scheme http/https, no user, no fragment), so
//     NewRequestWithContext — which re-parses the same URL with the valid POST
//     method — cannot fail. No validated input reaches this branch.
//
// roundTripFunc (load_test.go:507) is reused; the only new package-level symbol
// is closeErrBody (a tiny io.ReadCloser whose Close errors), used by the
// response-body-close test. cancelOnCloseBody in load_test.go is a single-use
// package-level test type that already passes CI staticcheck U1000, confirming
// single-use test types are not flagged; closeErrBody follows the same shape.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunCarrierLoadRejectsNilContext(t *testing.T) {
	// validateLoadInputs passes for a valid client/endpoint/options triple, so
	// execution reaches the nil-context guard at line 62 before any request body
	// or worker goroutine is created.
	valid := LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	}
	//lint:ignore SA1012 Verifies the public API's explicit nil-context rejection.
	_, err := RunCarrierLoad(nil, http.DefaultClient, "http://127.0.0.1/assets/app.bin", valid)
	if err == nil || !strings.Contains(err.Error(), "context is required") {
		t.Fatalf("RunCarrierLoad(nil ctx) err = %v, want substring \"context is required\"", err)
	}
}

func TestRunCarrierLoadDoesNotFollowRedirects(t *testing.T) {
	// The CheckRedirect closure (load.go:85) returns http.ErrUseLastResponse, so
	// a 302 is returned as-is rather than followed. Attribution is by RoundTrip
	// call count: with the closure, the client calls RoundTrip exactly once; if
	// the closure were absent the default CheckRedirect would follow the
	// redirect and call RoundTrip repeatedly. A single call plus a failed
	// request (302 != 200) proves the closure ran.
	var roundTrips atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		roundTrips.Add(1)
		// Close the request body so body.WaitClosed resolves without waiting
		// for the request-limit deadline.
		_ = request.Body.Close()
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://127.0.0.1/elsewhere"}},
			Body:       http.NoBody,
		}, nil
	})}
	report, err := RunCarrierLoad(context.Background(), client, "http://127.0.0.1/assets/app.bin", LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	})
	if roundTrips.Load() != 1 {
		t.Fatalf("RoundTrip called %d times, want 1 (redirect was followed, so the CheckRedirect closure did not return ErrUseLastResponse)", roundTrips.Load())
	}
	if err == nil || report.Passed || report.Errors != 1 || report.Completed != 1 {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

// closeErrBody is an io.ReadCloser that reads nothing (immediate EOF) but whose
// Close returns an error, so executeCarrierLoadRequest reaches the close-error
// branch (load.go:242) without first hitting the read-error branch (238).
type closeErrBody struct{}

func (closeErrBody) Read([]byte) (int, error) { return 0, io.EOF }

func (closeErrBody) Close() error { return errors.New("close failure") }

func TestRunCarrierLoadSurfacesResponseBodyCloseError(t *testing.T) {
	// A 200 response whose body Close returns an error reaches the closeErr
	// branch at load.go:242 (the empty read succeeds, so readErr is nil and the
	// 238 branch is skipped; Close then fails and the request is recorded as an
	// error).
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		_ = request.Body.Close()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/octet-stream"}},
			Body:       closeErrBody{},
		}, nil
	})}
	report, err := RunCarrierLoad(context.Background(), client, "http://127.0.0.1/assets/app.bin", LoadOptions{
		Requests:     1,
		Concurrency:  1,
		PacketBytes:  20,
		RequestLimit: time.Second,
	})
	if err == nil || report.Passed || report.Errors != 1 || report.Completed != 1 {
		t.Fatalf("report=%+v error=%v", report, err)
	}
}

func TestCountingBodyReadAfterCloseReturnsReadAfterCloseError(t *testing.T) {
	// Closing the counting body then reading reaches the b.closed guard at
	// load.go:293, returning http.ErrBodyReadAfterClose. Pure: no transport, no
	// goroutine.
	body := newCountingBody([]byte{1, 2, 3})
	if err := body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	n, err := body.Read(make([]byte, 4))
	if n != 0 || !errors.Is(err, http.ErrBodyReadAfterClose) {
		t.Fatalf("Read after Close: n=%d err=%v, want 0 and http.ErrBodyReadAfterClose", n, err)
	}
}
