package server

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across the server package's cover-carrier, production, and first-hop
// paths. Each guard exists so a caller that holds a nil *ProductionFirstHopServer
// or *FirstHopHandler pointer — or a serviceIssuerCarrier with no backing issuer
// — does not panic or proceed past an uninitialised state: the method returns at
// its very first statement, before any field is dereferenced or any issuer/listener
// is touched. The existing server tests only ever drive fully-built production
// servers, first-hop handlers, and carrier instances wrapping a live issuerd
// service, so these nil guards stayed count-0 even though each is plainly
// reachable.
//
// These are nil-RECEIVER / nil-SERVICE / nil-ARGUMENT guards (none is a ctx==nil
// guard), so there is no SA1012 surface: Shutdown is driven with context.Background
// (never a nil context literal). No network, no goroutine, no crypto — each call
// returns at the first statement. The || short-circuits on the nil side of every
// compound guard, so the right-hand deref (s.server.TLSConfig, s.handler,
// c.service.AllowsUntrustedCarrierIssuance, request) is never evaluated and the
// call cannot panic.
//
//   - cover_carrier.go:76  serviceIssuerCarrier.IssuerMetadata    c.service == nil
//     -> nil,nil,"server: issuer unavailable" (value receiver; serviceIssuerCarrier{}
//     has a nil service, so the guard fires before c.service.PublishIssuerMetadata)
//   - cover_carrier.go:92  serviceIssuerCarrier.IssueBlindRSA      c.service == nil || ...
//     -> nil,"server: issuer unavailable" (the || short-circuits on c.service==nil,
//     so c.service.AllowsUntrustedCarrierIssuance is never called)
//   - cover_carrier.go:107 serviceIssuerCarrier.SpendToken         c.service == nil || ...
//     -> nil,"server: issuer unavailable" (same short-circuit)
//   - production.go:101    ProductionFirstHopServer.Serve         s == nil || s.server == nil || ...
//     -> "server: production first-hop server is not initialized" (s==nil
//     short-circuits before the listener nil-check; a nil listener is safe)
//   - production.go:120    ProductionFirstHopServer.Shutdown       s == nil || s.handler == nil || s.server == nil
//     -> "server: production first-hop server is not initialized" (driven with
//     context.Background, so the later ctx==nil guard at 123 is not reached)
//   - first_hop.go:399     FirstHopHandler.ServeHTTP              h == nil || request == nil
//     -> no-op return (h==nil short-circuits before w / request are touched; the
//     call must complete without panicking)
//
// The test is in-package because serviceIssuerCarrier is unexported. The void
// ServeHTTP guard is proven by absence of panic (wrapped in a recover so a panic
// surfaces as a test failure): h==nil returns at the first statement and never
// reaches the body that reads request.Body / request.Context().

import (
	"context"
	"strings"
	"testing"
)

func TestServiceIssuerCarrierNilServiceGuards(t *testing.T) {
	// 76/92/107: a zero-valued serviceIssuerCarrier has a nil service, so all
	// three methods return "server: issuer unavailable" at their first statement
	// rather than dereferencing c.service. The two || guards (:92/:107)
	// short-circuit on c.service==nil, so AllowsUntrustedCarrierIssuance is never
	// called (which would deref the nil service and panic).
	c := serviceIssuerCarrier{}

	if _, _, err := c.IssuerMetadata(); err == nil {
		t.Fatal("serviceIssuerCarrier{}.IssuerMetadata err = nil, want non-nil (:76 should return \"issuer unavailable\")")
	} else if !strings.Contains(err.Error(), "issuer unavailable") {
		t.Fatalf("serviceIssuerCarrier{}.IssuerMetadata err = %q, want it to contain \"issuer unavailable\" (:76)", err.Error())
	}

	if _, err := c.IssueBlindRSA(nil, nil, 0); err == nil {
		t.Fatal("serviceIssuerCarrier{}.IssueBlindRSA err = nil, want non-nil (:92 should return \"issuer unavailable\")")
	} else if !strings.Contains(err.Error(), "issuer unavailable") {
		t.Fatalf("serviceIssuerCarrier{}.IssueBlindRSA err = %q, want it to contain \"issuer unavailable\" (:92)", err.Error())
	}

	if _, err := c.SpendToken(nil); err == nil {
		t.Fatal("serviceIssuerCarrier{}.SpendToken err = nil, want non-nil (:107 should return \"issuer unavailable\")")
	} else if !strings.Contains(err.Error(), "issuer unavailable") {
		t.Fatalf("serviceIssuerCarrier{}.SpendToken err = %q, want it to contain \"issuer unavailable\" (:107)", err.Error())
	}
}

func TestProductionFirstHopServerServeIsNilSafe(t *testing.T) {
	// 101: a nil *ProductionFirstHopServer.Serve returns "not initialized" at its
	// first statement. s==nil short-circuits the || before s.server.TLSConfig is
	// read, and the guard fires before the listener nil-check at 105, so a nil
	// listener is safe.
	var s *ProductionFirstHopServer
	if err := s.Serve(nil); err == nil {
		t.Fatal("nil.Serve err = nil, want non-nil (:101 should return \"not initialized\")")
	} else if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("nil.Serve err = %q, want it to contain \"not initialized\" (:101)", err.Error())
	}
}

func TestProductionFirstHopServerShutdownIsNilSafe(t *testing.T) {
	// 120: a nil *ProductionFirstHopServer.Shutdown returns "not initialized" at
	// its first statement. s==nil short-circuits the || before s.handler/s.server
	// are read. Driven with context.Background (never a nil context literal, so no
	// SA1012 surface); the later ctx==nil guard at 123 is not reached.
	var s *ProductionFirstHopServer
	if err := s.Shutdown(context.Background()); err == nil {
		t.Fatal("nil.Shutdown err = nil, want non-nil (:120 should return \"not initialized\")")
	} else if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("nil.Shutdown err = %q, want it to contain \"not initialized\" (:120)", err.Error())
	}
}

func TestFirstHopHandlerServeHTTPIsNilSafe(t *testing.T) {
	// 399: a nil *FirstHopHandler.ServeHTTP returns at its first statement before
	// w / request are touched. h==nil short-circuits the || before request==nil is
	// evaluated and before request.Body / request.Context() are read. The call is
	// void, so it is proven by absence of panic (a recover surfaces a panic as a
	// test failure). Nil w/request are safe because the guard fires first.
	var h *FirstHopHandler
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.ServeHTTP panicked = %v, want no-op return (:399 should guard the nil handler)", r)
			}
		}()
		h.ServeHTTP(nil, nil)
	}()
}
