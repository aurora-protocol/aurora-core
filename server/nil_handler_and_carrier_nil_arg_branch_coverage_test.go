package server

// Adversarial white-box coverage for six count-0 nil-argument guards in the
// server package: two exported listen-serve entry points that reject a nil
// handler, and four cover-carrier HTTP handlers that route a nil exchanger /
// nil issuer to the cover-failure path.
//
//   - server.go:172 ListenAndServe
//     handler == nil -> "server: handler is required" (fires after the
//     addr == "" guard at :169, before the http.Server construction at :175
//     and the server.ListenAndServe call at :180).
//   - server.go:191 ListenAndServeTLS
//     handler == nil -> "server: handler is required" (fires after the
//     addr == "" guard at :188, before the certFile / keyFile guard at :194
//     and the http.Server construction at :197).
//   - cover_carrier.go:196 serveCarrierPacketBatch
//     exchanger == nil -> serveCoverFailure (first statement; fires before
//     the DecodePacketBatch call at :200, so a nil payload is never decoded).
//   - cover_carrier.go:222 serveCarrierIssuerMetadata
//     issuer == nil -> serveCoverFailure (first statement; fires before the
//     issuer.IssuerMetadata call at :226).
//   - cover_carrier.go:240 serveCarrierBlindRSAIssue
//     issuer == nil -> serveCoverFailure (first statement; fires before the
//     DecodeCarrierIssueRequest call at :244, so a nil payload is never
//     decoded).
//   - cover_carrier.go:261 serveCarrierTokenSpend
//     issuer == nil || len(payload) == 0 -> serveCoverFailure (first
//     statement; fires before the DecodeCarrierSpendRequest call).
//
// The existing server tests drive ListenAndServe / ListenAndServeTLS only
// through the production first-hop path with a real handler, and drive the
// cover-carrier handlers only through the HTTP mux with a wired-up exchanger
// / issuer, so every one of these nil-argument branches stayed count-0 even
// though each is plainly reachable.
//
// Proof technique:
//
//   - ListenAndServe / ListenAndServeTLS (nil-argument clean return): pass a
//     non-empty addr (so the addr == "" guard at :169 / :188 passes) and a nil
//     handler. The :172 / :191 guard returns the "handler is required" error
//     before any http.Server is constructed or any socket is bound, so the
//     test is pure. The assertion on the "handler is required" substring
//     uniquely identifies the :172 / :191 guard (the later :194 certFile /
//     keyFile guard in ListenAndServeTLS returns a different message and is
//     never reached because :191 returns first).
//
//   - serveCarrier* (nil-argument HTTP-handler): call each handler with an
//     httptest.NewRecorder() and nil for r, origin, coverOrigin, and the
//     nil-tested argument (exchanger / issuer). The nil-tested guard fires as
//     the first statement and routes to serveCoverFailure, which (with a nil
//     coverOrigin) short-circuits at server.go:243-245 to serveCoverOrigin(w,
//     nil), which (with a nil origin) writes http.NotFound -> 404 at
//     server.go:218-220 and returns. r is never dereferenced on this path:
//     serveCoverFailure returns at :245 before the sanitizedCoverFailureRequest
//     call at :247, and serveCoverOrigin never touches r. So the 404 status
//     code uniquely proves the nil-tested guard's body (serveCoverFailure)
//     ran. The handlers return at their first statement, so the payload /
//     issuer methods are never called — no real exchanger or issuer is needed
//     and the tests are pure (httptest is in-memory; no network, no IO).
//
//     For serveCarrierTokenSpend (:261) the guard is compound
//     (issuer == nil || len(payload) == 0); a non-empty payload is passed so
//     the second operand is false and the guard is attributed to issuer == nil
//     (passing a non-nil issuer to exercise the len(payload) == 0 operand would
//     require a real IssuerCarrier implementation, and the operand shares the
//     single coverage block, so one call suffices to cover :261).
//
// No context is involved in any of these guards, so there is no SA1012 surface.
// In-package (package server) because the four serveCarrier* handlers and the
// PacketExchanger / IssuerCarrier interfaces are unexported.
//
// This test file adds only TestXxx entry points and references existing
// exported (ListenAndServe, ListenAndServeTLS) and unexported in-package
// (serveCarrier*) symbols, so it adds no U1000 surface.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListenAndServeNilHandlerGuard(t *testing.T) {
	// 172: a non-empty addr passes the :169 addr guard, so a nil handler
	// reaches the :172 guard, which returns "handler is required" before any
	// http.Server is constructed or any socket is bound. The addr is never
	// used, so the test is pure.
	err := ListenAndServe("127.0.0.1:0", nil)
	if err == nil {
		t.Fatal("ListenAndServe(nil handler) err = nil, want non-nil (:172 should reject)")
	} else if !strings.Contains(err.Error(), "handler is required") {
		t.Fatalf("ListenAndServe(nil handler) err = %q, want substring \"handler is required\" (:172)", err.Error())
	}
}

func TestListenAndServeTLSNilHandlerGuard(t *testing.T) {
	// 191: a non-empty addr passes the :188 addr guard, so a nil handler
	// reaches the :191 guard, which returns "handler is required" before the
	// :194 certFile / keyFile guard and before any http.Server is constructed.
	// The certFile / keyFile strings are arbitrary — the :191 guard returns
	// first — so no file is read and the test is pure. The "handler is
	// required" substring uniquely identifies :191 (the :194 guard returns a
	// different message and is never reached).
	err := ListenAndServeTLS("127.0.0.1:0", nil, "cert.pem", "key.pem")
	if err == nil {
		t.Fatal("ListenAndServeTLS(nil handler) err = nil, want non-nil (:191 should reject)")
	} else if !strings.Contains(err.Error(), "handler is required") {
		t.Fatalf("ListenAndServeTLS(nil handler) err = %q, want substring \"handler is required\" (:191)", err.Error())
	}
}

func TestServeCarrierPacketBatchNilExchangerGuard(t *testing.T) {
	// 196: a nil exchanger trips the first-statement guard and routes to
	// serveCoverFailure, which (nil coverOrigin) routes to serveCoverOrigin
	// (nil origin) -> 404. r is never dereferenced. payload is nil and is never
	// decoded (the guard returns before :200).
	rec := httptest.NewRecorder()
	serveCarrierPacketBatch(rec, nil, nil, nil, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("serveCarrierPacketBatch(nil exchanger) status = %d, want %d (:196 -> serveCoverFailure -> serveCoverOrigin nil -> 404)", rec.Code, http.StatusNotFound)
	}
}

func TestServeCarrierIssuerMetadataNilIssuerGuard(t *testing.T) {
	// 222: a nil issuer trips the first-statement guard -> serveCoverFailure
	// -> 404. r never dereferenced.
	rec := httptest.NewRecorder()
	serveCarrierIssuerMetadata(rec, nil, nil, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("serveCarrierIssuerMetadata(nil issuer) status = %d, want %d (:222 -> serveCoverFailure -> serveCoverOrigin nil -> 404)", rec.Code, http.StatusNotFound)
	}
}

func TestServeCarrierBlindRSAIssueNilIssuerGuard(t *testing.T) {
	// 240: a nil issuer trips the first-statement guard -> serveCoverFailure
	// -> 404. payload is nil and never decoded (the guard returns before :244).
	rec := httptest.NewRecorder()
	serveCarrierBlindRSAIssue(rec, nil, nil, nil, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("serveCarrierBlindRSAIssue(nil issuer) status = %d, want %d (:240 -> serveCoverFailure -> serveCoverOrigin nil -> 404)", rec.Code, http.StatusNotFound)
	}
}

func TestServeCarrierTokenSpendNilIssuerGuard(t *testing.T) {
	// 261: the compound guard (issuer == nil || len(payload) == 0) is tripped
	// by a nil issuer; a non-empty payload makes the second operand false so
	// the guard is attributed to issuer == nil. -> serveCoverFailure -> 404.
	rec := httptest.NewRecorder()
	serveCarrierTokenSpend(rec, nil, nil, nil, nil, []byte{1})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("serveCarrierTokenSpend(nil issuer) status = %d, want %d (:261 -> serveCoverFailure -> serveCoverOrigin nil -> 404)", rec.Code, http.StatusNotFound)
	}
}
