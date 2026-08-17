package server

// Adversarial white-box coverage for the two count-0 contract-violation guards
// of FirstHopHandler.serveCandidate around h.begin (server/first_hop.go:568-581).
// h.begin is the injected first-hop session factory entry point; the two guards
// defend against it violating its (state, err) contract:
//
//   - :570 if handshakeState != nil  (inside the :569 err != nil block)
//     -> the Begin callback returned BOTH a non-nil handshake state AND an error;
//        the partial state must be closed (:571) before failing the request.
//   - :577 if handshakeState == nil  (the :569 err == nil path)
//     -> Begin returned (nil, _, nil); a nil state with no error is a contract
//        violation ("Begin returned nil handshake state").
//
// Both bodies are COUNT 0 because the existing gate-server tests only ever
// return (nil, prelude1, err) — nil state + error, which takes the :569-575 path
// but skips :570 (state is nil) and never reaches :577 (err != nil) — or
// (&RelayHandshake{}, prelude1, nil), the happy path that skips both. Neither
// returns a NON-nil state WITH an error, nor a nil state WITH no error.
//
// Coverage targets (baseline measured on main; both bodies COUNT 0 while their
// conditions were already evaluated):
//   - first_hop.go:570.19,572.3 0  — handshakeState != nil inside err != nil
//   - first_hop.go:577.19,581.3 0  — handshakeState == nil inside err == nil
//
// Reuses the existing gate-server harness startFirstHopGateTestServer
// (first_hop_test.go:1429), which exposes the *FirstHopHandler and overrides
// handler.begin directly (line 1433) and runs a real TLS 1.3 httptest server so
// request.TLS is a genuine ConnectionState whose ExportKeyingMaterial succeeds
// at :562 (DeriveHTTP2FirstHopBinding). The request therefore reaches :568
// (h.begin) for real, and the overridden Begin returns the contract-violating
// combination. &handshake.RelayHandshake{} is the same zero-value state the
// happy-path tests (first_hop_test.go:245,285,...) return; its Close() is
// nil/zero-value safe (handshake/relay.go:180). In-package (package server)
// because startFirstHopGateTestServer, firstHopTestPreludeRecord,
// firstHopTestPrelude1, assertFirstHopCoverResult, readFirstHopHTTPResult and
// handler.path are unexported. No context-nil involved -> no SA1012 surface.
// This file adds only TestXxx entry points and references existing in-package
// helpers + stdlib bytes/context/errors/net/http/sync/atomic/testing and the
// handshake/protocol packages already imported by first_hop_test.go, so it
// adds no U1000 surface.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestFirstHopBeginReturningPartialStateAndErrorClosesState(t *testing.T) {
	// :570 handshakeState != nil (inside :569 err != nil): Begin returns a NON-nil
	// handshake state together with an error. The :570 guard fires and :571 closes
	// the partial state before servePreHeaderFailure returns the cover response.
	var beginCalls atomic.Int32
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginCalls.Add(1)
		return &handshake.RelayHandshake{}, firstHopTestPrelude1(), errors.New("begin transient failure")
	})
	request, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(response, nil))
	if got := beginCalls.Load(); got != 1 {
		t.Fatalf("Begin calls = %d, want 1 (request must reach :568 to exercise :570)", got)
	}
}

func TestFirstHopBeginReturningNilHandshakeStateRejected(t *testing.T) {
	// :577 handshakeState == nil (the :569 err == nil path): Begin returns
	// (nil, prelude1, nil) — a nil state with NO error is a contract violation.
	// The :577 guard fires ("Begin returned nil handshake state") and
	// servePreHeaderFailure returns the cover response.
	var beginCalls atomic.Int32
	server, client, _, handler := startFirstHopGateTestServer(t, func(context.Context, handshake.FirstHopBinding, protocol.CoverPrelude0, uint64) (*handshake.RelayHandshake, protocol.CoverPrelude1, error) {
		beginCalls.Add(1)
		return nil, protocol.CoverPrelude1{}, nil
	})
	request, err := http.NewRequest(http.MethodPost, server.URL+handler.path, bytes.NewReader(firstHopTestPreludeRecord(t)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	assertFirstHopCoverResult(t, readFirstHopHTTPResult(response, nil))
	if got := beginCalls.Load(); got != 1 {
		t.Fatalf("Begin calls = %d, want 1 (request must reach :568 to exercise :577)", got)
	}
}
