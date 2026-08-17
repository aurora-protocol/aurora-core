//go:build cgo

package main

// Adversarial white-box coverage for the count-0 first-statement nil-receiver
// safety guards in mobile/auroracore/session.go. Each guard exists so a caller
// that holds a nil *nativeSessionRegistry / *nativeSession does not panic or
// proceed into the registry / duplex / termination / close path: the method
// returns at its very first statement, before any field is dereferenced
// (r.now, s.mu, s.closed, s.pumpErr, s.cancel, s.established) or any helper /
// closer is called (zeroNativeProvisioning, established.Close). The existing
// mobile tests only ever drive a populated registry / live native session
// along the native path, so the nil-receiver guards stayed count-0 even though
// each is plainly reachable.
//
//   - :119 (*nativeSessionRegistry).begin(provisioning client.NativeProvisioning) (nativeIssuerWork, error)
//     r == nil -> (nativeIssuerWork{}, "auroracore: native session registry is
//     unavailable") (fires before the deferred zeroNativeProvisioning / r.now;
//     the "registry is unavailable" message distinguishes the nil-receiver path
//     from a non-nil registry that hits the invalid-time error)
//   - :604 (*nativeSession).finishDuplex(err error)
//     s == nil -> no-op return (void; fires before s.mu.Lock / the closed /
//     pumpErr / cancel / established path)
//   - :628 (*nativeSession).localPacketTerminationError() error
//     s == nil -> session.ErrClosed (fires before s.mu.Lock / the pumpErr read;
//     the sentinel ErrClosed distinguishes the nil-receiver path from a non-nil
//     session that returns its captured pumpErr)
//   - :714 (*nativeSession).close() error
//     s == nil -> nil (fires before s.mu.Lock / the closed / established close)
//
// These are nil-RECEIVER first-statement guards. None take a context, so there
// is no SA1012 surface. No network, no goroutine, no cgo, no native session
// handles — each guard returns before any mutex / registry / session-field
// access, so this test cannot trigger the
// TestNativeSessionFFIStopsOnCarrierCancellation handle-lifecycle flake. The
// test is in-package (package main, //go:build cgo) matching the existing
// mobile test-file convention.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/session"
)

func TestNativeSessionRegistryNilReceiverGuard(t *testing.T) {
	// 119: a nil *nativeSessionRegistry returns at the first statement of begin
	// rather than dereferencing r.now / running the deferred
	// zeroNativeProvisioning. The "registry is unavailable" message distinguishes
	// the nil-receiver path from a non-nil registry (which would hit the
	// invalid-time error). begin takes a NativeProvisioning value; a zero value
	// is safe because the guard returns before it is read.
	var r *nativeSessionRegistry
	work, err := r.begin(client.NativeProvisioning{})
	if err == nil {
		t.Fatal("nil.begin() err = nil, want non-nil (:119 should reject)")
	} else if !strings.Contains(err.Error(), "registry is unavailable") {
		t.Fatalf("nil.begin() err = %q, want substring \"registry is unavailable\" (:119)", err.Error())
	}
	// nativeIssuerWork contains a []byte (RequestBody) so it is not comparable
	// with !=; assert on the Handle uint64 scalar, which is 0 for the zero value
	// (a populated issuer work would carry a non-zero handle).
	if work.Handle != 0 {
		t.Fatalf("nil.begin() work.Handle = %d, want 0 (zero nativeIssuerWork{} :119)", work.Handle)
	}
}

func TestNativeSessionNilReceiverGuards(t *testing.T) {
	// 604/628/714: a nil *nativeSession returns at the first statement of
	// finishDuplex / localPacketTerminationError / close rather than
	// dereferencing s.mu / s.closed / s.pumpErr / s.cancel / s.established.
	var s *nativeSession

	// 604: finishDuplex is void; the s==nil guard fires before s.mu.Lock.
	// No-panic proof.
	s.finishDuplex(nil)

	// 628: localPacketTerminationError returns the session.ErrClosed sentinel;
	// the s==nil guard fires before s.mu.Lock / the pumpErr read. The sentinel
	// distinguishes the nil-receiver path from a non-nil session that returns its
	// captured pumpErr.
	if err := s.localPacketTerminationError(); err != session.ErrClosed {
		t.Fatalf("nil.localPacketTerminationError() err = %v, want session.ErrClosed (:628)", err)
	}

	// 714: close returns nil; the s==nil guard fires before s.mu.Lock.
	if err := s.close(); err != nil {
		t.Fatalf("nil.close() err = %v, want nil (:714)", err)
	}
}
