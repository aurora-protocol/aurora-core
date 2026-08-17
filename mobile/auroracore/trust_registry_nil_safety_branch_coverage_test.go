//go:build cgo

package main

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards in mobile/auroracore/native_output_registry.go and
// mobile/auroracore/native_provisioning_trust.go. Each guard exists so a caller
// that passes a nil output pointer — or holds a nil
// *nativeProvisioningTrustConfig — does not panic or proceed into the registry
// / parse / lock path: the function returns at its very first statement,
// before any field is dereferenced (c.mu, c.encoded, c.value) or any
// map/mutex/parse operation runs (nativeOutputs.mu, nativeOutputs.lengths,
// client.ParseNativeProvisioningTrust, client.EncodeNativeProvisioningTrust).
// The existing mobile tests only ever drive real output pointers and a
// configured trust config along the live native path, so the nil guards stayed
// count-0 even though each is plainly reachable.
//
//   - native_output_registry.go:18 registerNativeOutput(p unsafe.Pointer, length int)
//     p == nil -> no-op return (void; fires before nativeOutputs.mu.Lock / the
//     lengths map write)
//   - native_output_registry.go:27 takeNativeOutput(p unsafe.Pointer) (int, bool)
//     p == nil -> (0, false) (fires before nativeOutputs.mu.Lock / the lengths
//     map lookup+delete)
//   - native_provisioning_trust.go:18 (*nativeProvisioningTrustConfig).configure(encoded []byte) error
//     c == nil -> "auroracore: native provisioning trust configuration is
//     unavailable" (fires before client.ParseNativeProvisioningTrust; the
//     "unavailable" message distinguishes the nil-receiver path from a non-nil
//     config that hits the parse/already-configured errors)
//   - native_provisioning_trust.go:45 (*nativeProvisioningTrustConfig).load() (client.NativeProvisioningTrust, error)
//     c == nil -> (client.NativeProvisioningTrust{}, "auroracore: native
//     provisioning trust configuration is unavailable") (fires before c.mu.RLock;
//     the "unavailable" message distinguishes the nil-receiver path from a
//     non-nil but unconfigured config that returns ErrNativeProvisioningTrustRequired)
//
// These are nil-ARGUMENT (register/take) and nil-RECEIVER (configure/load)
// first-statement guards. None take a context, so there is no SA1012 surface.
// No network, no goroutine, no cgo, no native session handles — each guard
// returns before any unsafe.Pointer map operation or trust parse runs, so this
// test cannot trigger the TestNativeSessionFFIStopsOnCarrierCancellation
// handle-lifecycle flake. The test is in-package (package main, //go:build cgo)
// matching the existing mobile test-file convention.
//
// This test file adds only TestXxx entry points and uses existing unexported
// in-package symbols, so it adds no U1000 surface.

import (
	"strings"
	"testing"
)

func TestNativeOutputRegistryNilArgumentGuards(t *testing.T) {
	// 18: registerNativeOutput(nil, 0) is a void no-op; the p==nil guard fires
	// before the mutex/map write. No-panic proof.
	registerNativeOutput(nil, 0)

	// 27: takeNativeOutput(nil) returns (0, false); the p==nil guard fires before
	// the mutex/map lookup.
	length, ok := takeNativeOutput(nil)
	if length != 0 || ok {
		t.Fatalf("takeNativeOutput(nil) = (%d, %v), want (0, false) (:27)", length, ok)
	}
}

func TestNativeProvisioningTrustConfigNilReceiverGuards(t *testing.T) {
	// 18/45: a nil *nativeProvisioningTrustConfig returns at the first statement
	// of configure / load rather than dereferencing c.mu / c.encoded / c.value.
	// The "unavailable" message distinguishes the nil-receiver path from a
	// non-nil config (which would hit the parse error or
	// ErrNativeProvisioningTrustRequired).
	var c *nativeProvisioningTrustConfig

	// 18: configure returns "configuration is unavailable".
	if err := c.configure(nil); err == nil {
		t.Fatal("nil.configure(nil) err = nil, want non-nil (:18 should reject)")
	} else if !strings.Contains(err.Error(), "configuration is unavailable") {
		t.Fatalf("nil.configure(nil) err = %q, want substring \"configuration is unavailable\" (:18)", err.Error())
	}

	// 45: load returns the zero trust value and "configuration is unavailable".
	if _, err := c.load(); err == nil {
		t.Fatal("nil.load() err = nil, want non-nil (:45 should reject)")
	} else if !strings.Contains(err.Error(), "configuration is unavailable") {
		t.Fatalf("nil.load() err = %q, want substring \"configuration is unavailable\" (:45)", err.Error())
	}
}
