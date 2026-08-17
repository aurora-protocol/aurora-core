package issuerd

// Adversarial white-box coverage for the count-0 nil-receiver first-statement
// safety guards on three issuerd Service methods. Each guard exists so a caller
// that holds a nil *Service pointer does not panic: the method returns at its
// very first statement, before any field (s.metadata, s.authorityKeys, s.now,
// s.nowUnix) is dereferenced. The existing issuerd tests only ever drive
// services built by the issuer constructors (which never return a nil pointer)
// along the live issue/verify path, so the nil-receiver guards stayed count-0
// even though each is plainly reachable: call the method on a nil *Service.
//
// These are nil-RECEIVER guards (none is a ctx==nil guard), so there is no SA1012
// surface. No crypto, no network, no goroutine — each call returns at the first
// statement and never reaches the clone/now body.
//
//   - service.go:338 Service.PublishIssuerMetadata  s == nil -> protocol.IssuerMetadata{}
//     (exported; the zero-value IssuerMetadata is asserted with reflect.DeepEqual
//     because the struct may contain slices and so is not ==-comparable)
//   - service.go:349 Service.AuthorityKeys          s == nil -> nil
//     (exported; a nil []protocol.AuthorityKeyRecord, asserted with != nil)
//   - service.go:738 Service.currentUnix            s == nil -> 0
//     (UNEXPORTED, so the test is in-package; the zero uint64 is asserted with != 0)
//
// The two other count-0 nil checks in this file — :564 (cert == nil) and :612
// (signer == nil) — are NOT first-statement guards: they sit deep inside
// AuthorizeVerifierRequestClient / verifierServiceForRequest, behind a successful
// verifierServiceForRequest that requires a fully-constructed Service with verifier
// services wired. They are reachable only via a real service, so they are out of
// scope for this nil-receiver pillar and left uncovered here.
//
// This test file adds only TestXxx entry points and uses existing exported
// (plus one unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"reflect"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestServiceNilReceiverGuards(t *testing.T) {
	// 338/349/738: a nil *Service returns at the first statement of
	// PublishIssuerMetadata / AuthorityKeys / currentUnix rather than
	// dereferencing s.metadata / s.authorityKeys / s.now / s.nowUnix.
	var s *Service

	// 338: the zero-value IssuerMetadata. reflect.DeepEqual is used because
	// IssuerMetadata may contain slices and so is not ==-comparable.
	if got := s.PublishIssuerMetadata(); !reflect.DeepEqual(got, protocol.IssuerMetadata{}) {
		t.Fatalf("nil.PublishIssuerMetadata = %+v, want zero protocol.IssuerMetadata (:338 should return the zero value)", got)
	}

	// 349: a nil []protocol.AuthorityKeyRecord. != nil distinguishes the nil
	// return from any populated non-nil slice.
	if keys := s.AuthorityKeys(); keys != nil {
		t.Fatalf("nil.AuthorityKeys = %v (len %d), want nil (:349 should return nil)", keys, len(keys))
	}

	// 738: the zero uint64.
	if u := s.currentUnix(); u != 0 {
		t.Fatalf("nil.currentUnix = %d, want 0 (:738 should return 0)", u)
	}
}
