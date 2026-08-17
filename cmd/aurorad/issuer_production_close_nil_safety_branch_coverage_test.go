package main

// Adversarial white-box coverage for the count-0 nil-safety guard in
// (*productionIssuerService).Close. The compound :62 guard has two nil-safety
// clauses: a nil receiver (so s.cache is never read) and a nil cache field (so
// s.cache.Close() is never called on a nil io.Closer).
//
//   - cmd/aurorad/issuer_production.go:62 (*productionIssuerService).Close
//     s == nil || s.cache == nil -> return nil (the first clause short-circuits
//     before s.cache is read; the second clause short-circuits before
//     s.cache.Close() panics on a nil io.Closer).
//
// The existing cmd/aurorad tests drive Close only on a fully-built issuer service
// (s != nil, s.cache != nil — falls through to the :65 s.cache.Close() success
// path), so the nil-receiver / nil-cache clause stayed count-0 even though each
// is plainly reachable.
//
// Proof:
//   - nil-receiver: var s *productionIssuerService; s.Close() — s == nil
//     short-circuits :62 before s.cache is read; :63 returns nil.
//   - nil-cache: (&productionIssuerService{}).Close() — s != nil but the
//     zero-value s.cache (a nil io.Closer) trips the s.cache == nil clause;
//     :63 returns nil before :65 s.cache.Close() would panic.
//
// No context is involved, so there is no SA1012 surface. No network, no goroutine,
// no file IO — the guard returns before s.cache.Close() is called. In-package
// (package main) because productionIssuerService and Close (well, Close is a
// method on the unexported type) are unexported.
//
// This test file adds only a TestXxx entry point and references existing
// in-package (productionIssuerService) symbols and the standard library testing
// package, so it adds no U1000 surface.

import "testing"

func TestProductionIssuerServiceCloseNilGuards(t *testing.T) {
	// 62 (nil-receiver): s == nil short-circuits before s.cache is read; :63
	// returns nil.
	var nilReceiver *productionIssuerService
	if err := nilReceiver.Close(); err != nil {
		t.Fatalf("nil-receiver Close err = %v, want nil (:63)", err)
	}
	// 62 (nil-cache): s != nil, s.cache == nil (zero-value io.Closer); :63
	// returns nil before :65 s.cache.Close() would panic on a nil io.Closer.
	if err := (&productionIssuerService{}).Close(); err != nil {
		t.Fatalf("nil-cache Close err = %v, want nil (:63)", err)
	}
}
