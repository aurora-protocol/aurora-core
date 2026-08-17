package issuerd

// Adversarial white-box coverage for the two count-0 first-statement
// nil-field safety guards in issuerd. Each guard exists so a caller that
// constructs a zero-value options struct / a zero-value Service does not
// proceed into the production-service / relay-key authorization path with a
// nil clock / nil map: the guard fires at the very first statement. The
// existing issuerd tests construct the production service via
// NewProductionBlindRSAService with a populated NowUnix clock, and the
// registry service via NewService (which pre-initializes authorizedRelayKeys
// with make at service.go:240), so the nil-field branches stayed count-0
// even though each is plainly reachable with a zero-value struct.
//
//   - production_service.go:28 NewProductionBlindRSAService(options)
//     options.NowUnix == nil -> (nil, "issuerd: production clock is required")
//     (a clean return; fires before options.NowUnix() / the BlindRSAKey
//     validation). The "production clock is required" message distinguishes
//     the nil-clock path from a non-nil clock that returns 0 (the "invalid
//     time" error on :32) or a missing BlindRSAKey.
//   - service.go:552 (*Service).AuthorizeRelayClientKey(requestAuthPolicyID, key)
//     s.authorizedRelayKeys == nil -> lazy init
//     s.authorizedRelayKeys = make(map[uint64][]protocol.PublicKeyRecord)
//     (fires before the key.PublicKey copy / the map append). This is a
//     lazy-init guard rather than an early return: the nil branch initializes
//     the map and falls through to the append. The proof that the nil branch
//     ran is that s.authorizedRelayKeys is non-nil and the appended key is
//     present after the call. A zero-value *Service is safe because the only
//     field touched before the guard's make is s.authorizedRelayKeys itself.
//
// These are nil-FIELD first-statement guards (on a field of the argument /
// receiver). No context is involved, so there is no SA1012 surface. No
// network, no goroutine, no crypto — the :28 guard returns before any clock
// call, and the :552 guard does only a map make + slice append before
// returning, so neither can perturb the issuerd integration tests. The test
// is in-package (package issuerd) because it constructs a zero-value *Service
// and reads the unexported authorizedRelayKeys field.
//
// This test file adds only TestXxx entry points and uses existing exported
// types / unexported in-package fields, so it adds no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestNewProductionBlindRSAServiceNilNowUnixGuard(t *testing.T) {
	// 28: a zero-value ProductionBlindRSAServiceOptions has NowUnix == nil, so
	// the first-statement guard returns before options.NowUnix() / the
	// BlindRSAKey validation. The "production clock is required" message
	// distinguishes the nil-clock path from a non-nil clock that returns 0
	// (the "invalid time" error) or a missing key.
	svc, err := NewProductionBlindRSAService(ProductionBlindRSAServiceOptions{})
	if err == nil {
		t.Fatal("NewProductionBlindRSAService(zero) err = nil, want non-nil (:28 should reject)")
	} else if !strings.Contains(err.Error(), "production clock is required") {
		t.Fatalf("NewProductionBlindRSAService(zero) err = %q, want substring \"production clock is required\" (:28)", err.Error())
	}
	if svc != nil {
		t.Fatalf("NewProductionBlindRSAService(zero) svc = %v, want nil (:28)", svc)
	}
}

func TestServiceAuthorizeRelayClientKeyNilMapGuard(t *testing.T) {
	// 552: a zero-value *Service has authorizedRelayKeys == nil, so the
	// first-statement guard initializes the map and falls through to the
	// append. The proof that the nil branch ran is that authorizedRelayKeys is
	// non-nil and the appended key is present after the call. NewService
	// pre-initializes the map (service.go:240), so existing tests never hit
	// the nil branch.
	s := &Service{}
	s.AuthorizeRelayClientKey(0, protocol.PublicKeyRecord{})
	if s.authorizedRelayKeys == nil {
		t.Fatal("AuthorizeRelayClientKey left authorizedRelayKeys nil, want non-nil (:552 should lazy-init)")
	}
	if got := s.authorizedRelayKeys[0]; len(got) != 1 {
		t.Fatalf("AuthorizeRelayClientKey authorizedRelayKeys[0] len = %d, want 1 (:552 append ran)", len(got))
	}
}
