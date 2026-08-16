package server

// Adversarial white-box coverage for the constructor validation branches of
// server/cover_origin.go that the existing production_test.go / server_test.go
// suites do not reach. cover_origin.go is pure stdlib (context, net/http,
// net/http/httputil, net/url, time); every branch below is exercised at
// *construction time* with crafted *url.URL values — no HTTP server, no
// socket, no goroutine.
//
// Targets covered:
//
//   - NewReverseProxyCoverOrigin:55-57 — the thin wrapper that delegates to
//     NewReverseProxyCoverOriginWithTransport(target, nil). The existing suite
//     only ever calls the ...WithTransport constructor directly (server_test.go
//     :508/:545) and the production constructors, so the wrapper body itself is
//     never executed. Calling NewReverseProxyCoverOrigin with a valid URL
//     exercises it (and confirms a non-nil CoverOrigin comes back).
//
//   - NewReverseProxyCoverOriginWithTransport:90-92 — the `target == nil`
//     guard ("cover origin URL is required"). The existing suite always passes
//     a parsed https://cover.example URL, so nil is never tested.
//
//   - NewReverseProxyCoverOriginWithTransport:93-95 — the scheme guard ("must
//     use http or https"). A non-http(s) scheme (ftp://) reaches it; the
//     existing suite only passes http/https targets.
//
//   - NewReverseProxyCoverOriginWithTransport:96-98 — the empty-host guard
//     ("host is required"). A URL with an http scheme but an empty host
//     ("http://") passes the scheme check and fails here; the existing suite
//     always passes a host.
//
//   - NewProductionReverseProxyCoverOriginWithTransport:70-72 — the
//     production-constructor error propagation. Passing a nil target makes the
//     inner NewReverseProxyCoverOriginWithTransport return the line-90 error,
//     which the production wrapper then propagates at 70. The existing suite
//     only constructs the production origin with valid targets, so the
//     propagation is never reached.
//
// Not coverable / deferred (documented, NOT claimed):
//   - productionCoverOrigin.productionFirstHopCoverOrigin (line 37) is an empty
//     marker method with zero statements — there is nothing to execute, so it
//     carries a 0/0 block that no test can move.
//   - reverseProxyCoverOrigin's httputil.ReverseProxy.ErrorHandler closure
//     (line 103-105) fires only when an upstream request fails. Reaching it
//     needs a live httptest upstream that refuses the connection and a served
//     request through the proxy — a network/httptest harness, not a
//     construction-time branch, so it is left to the integration-test domain.
//
// The existing mustParseURL helper (server_test.go:922) is reused; no new
// package-level helpers or types are introduced (only test functions), so
// there is nothing for staticcheck U1000. No context.Context is passed (so no
// SA1012 surface), no goroutines, no real network or filesystem.

import (
	"net/url"
	"strings"
	"testing"
)

func TestNewReverseProxyCoverOriginWrapsValidTarget(t *testing.T) {
	// The thin NewReverseProxyCoverOrigin wrapper delegates to
	// NewReverseProxyCoverOriginWithTransport(target, nil); a valid URL must
	// come back as a non-nil CoverOrigin. The existing suite never calls this
	// wrapper, so its body (line 55) is uncovered without this test.
	origin, err := NewReverseProxyCoverOrigin(mustParseURL(t, "http://cover.example"))
	if err != nil {
		t.Fatalf("NewReverseProxyCoverOrigin err = %v, want nil", err)
	}
	if origin == nil {
		t.Fatal("NewReverseProxyCoverOrigin returned nil origin on success")
	}
}

func TestNewReverseProxyCoverOriginWithTransportRejectsInvalidTargets(t *testing.T) {
	cases := []struct {
		name    string
		target  func() *url.URL
		wantSub string
	}{
		// 90-92: nil target.
		{"nil target", func() *url.URL { return nil }, "cover origin URL is required"},
		// 93-95: non-http(s) scheme. url.Parse accepts "ftp://", so the nil
		// and scheme guards are the ones that fire.
		{"non-http scheme", func() *url.URL { return mustParseURL(t, "ftp://cover.example") }, "must use http or https"},
		// 96-98: http scheme but empty host ("http://" parses to Host == "").
		{"empty host", func() *url.URL { return mustParseURL(t, "http://") }, "host is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewReverseProxyCoverOriginWithTransport(tc.target(), nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want substring %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestNewProductionReverseProxyCoverOriginWithTransportPropagatesError(t *testing.T) {
	// A nil target makes the inner NewReverseProxyCoverOriginWithTransport
	// return the line-90 error; the production constructor propagates it at
	// line 70. The existing suite only constructs the production origin with
	// valid targets, so this propagation is uncovered.
	_, err := NewProductionReverseProxyCoverOriginWithTransport(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cover origin URL is required") {
		t.Fatalf("NewProductionReverseProxyCoverOriginWithTransport(nil) err = %v, want substring \"cover origin URL is required\"", err)
	}
}
