package main

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across cmd/aurorac/main.go. Each guard exists so a caller that holds a
// nil *componentFailure — or passes a nil listener / nil provisioning value to
// the unexported helpers — does not panic or proceed past an uninitialised
// state: the function returns at its very first statement, before any field is
// dereferenced (e.err, e.name) or any helper / device method is called. The
// existing aurorac tests only ever drive a populated componentFailure along the
// live proxy path and real listeners / provisioning values, so the nil guards
// stayed count-0 even though each is plainly reachable.
//
// These are nil-RECEIVER / nil-ARGUMENT guards. None take a context, so there
// is no SA1012 surface. No network, no goroutine, no crypto — each call returns
// at the first statement. The test is in-package (package main) because
// componentFailure, closeProxyListener, and zeroProxyProvisioning are
// unexported.
//
//   - :71  (*componentFailure).Error()    e == nil
//     -> "client: component failure is unavailable" (the e==nil guard fires
//     before the e.err==nil guard at 76)
//   - :81  (*componentFailure).Unwrap()   e == nil -> nil
//   - :771 closeProxyListener(listener)    listener == nil -> nil
//   - :873 zeroProxyProvisioning(provisioning)  provisioning == nil -> no-op
//     return (void; no-panic proof)
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestComponentFailureNilReceiverGuards(t *testing.T) {
	// 71/81: a nil *componentFailure returns at the first statement of Error /
	// Unwrap rather than dereferencing e.err / e.name. The e==nil guard in Error
	// fires before the e.err==nil guard at :76.
	var e *componentFailure

	// 71: Error returns "component failure is unavailable".
	if msg := e.Error(); !strings.Contains(msg, "component failure is unavailable") {
		t.Fatalf("nil.Error = %q, want substring \"component failure is unavailable\" (:71)", msg)
	}

	// 81: Unwrap returns nil.
	if err := e.Unwrap(); err != nil {
		t.Fatalf("nil.Unwrap = %v, want nil (:81)", err)
	}
}

func TestCloseProxyListenerAndZeroProxyProvisioningNilArgumentGuards(t *testing.T) {
	// 771/873: the two unexported helpers return at their first statement when
	// given a nil value, before touching the listener / provisioning fields.
	// closeProxyListener returns nil; zeroProxyProvisioning is void — the proof
	// is that the call completes without panicking (a panic surfaces as a test
	// failure).

	// 771: closeProxyListener(nil) returns nil.
	if err := closeProxyListener(nil); err != nil {
		t.Fatalf("closeProxyListener(nil) err = %v, want nil (:771 should return nil)", err)
	}

	// 873: zeroProxyProvisioning(nil) is a void no-op; no-panic proof.
	zeroProxyProvisioning(nil)
}
