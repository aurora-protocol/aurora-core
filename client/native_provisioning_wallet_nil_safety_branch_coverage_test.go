package client

// Adversarial white-box coverage for the count-0 first-statement nil-safety
// guards across client/native_provisioning_wallet.go. Each guard exists so a
// caller that holds a nil *NativeProvisioningWallet / *NativeProvisioningReservation
// / *nativeProvisioningWalletEntry — or passes a nil credential / provisioning
// value to the zeroers — does not panic or proceed past an uninitialised state:
// the function returns at its very first statement, before any field is
// dereferenced (w.mu, w.entries, r.SpentHintKey, entry.encoded) or any helper
// is called (zeroNativeProvisioningBytes). The existing client tests only ever
// drive a fully-built wallet along the live encode → parse → reserve path, so
// the nil guards stayed count-0 even though each is plainly reachable.
//
// These are nil-RECEIVER / nil-ARGUMENT guards. None of the guarded methods take
// a context, so there is no SA1012 surface. No network, no goroutine, no crypto —
// each call returns at the first statement. The test is in-package because
// nativeProvisioningWalletEntry and the zero* helpers are unexported.
//
//   - :252 (*NativeProvisioningWallet).Reserve(alreadyReserved, now)   w == nil
//     -> NativeProvisioningReservation{}, ErrNoUsableNativeProvisioning (the
//     w==nil guard fires before the now.IsZero guard at 255)
//   - :293 (*NativeProvisioningWallet).BucketStatus(alreadyReserved, now)
//     w == nil -> nil (compound guard "w == nil || now.IsZero || now.Unix<0";
//     the || short-circuits on w==nil so now is never read)
//   - :341 (*NativeProvisioningWallet).Zero()              w == nil -> no-op return
//     (void; proven by absence of panic via a recover wrapper)
//   - :352 (*NativeProvisioningReservation).Zero()         r == nil -> no-op return
//     (void; proven by absence of panic via a recover wrapper)
//   - :385 (*nativeProvisioningWalletEntry).zero()        entry == nil -> no-op
//     return (UNEXPORTED; void; no-panic proof)
//   - :401 zeroNativeAccessHintCredential(credential)     credential == nil
//     -> no-op return (UNEXPORTED; void; no-panic proof)
//   - :412 zeroNativeProvisioning(provisioning)           provisioning == nil
//     -> no-op return (UNEXPORTED; void; no-panic proof)
//
// This test file adds only TestXxx entry points and uses existing exported (plus
// unexported, in-package) symbols, so it adds no U1000 surface.

import (
	"errors"
	"testing"
	"time"
)

func TestNativeProvisioningWalletNilReceiverGuards(t *testing.T) {
	// 252/293/341: a nil *NativeProvisioningWallet returns at the first statement
	// of Reserve / BucketStatus / Zero rather than dereferencing w.mu / w.entries.
	// Reserve and BucketStatus are driven with a valid now so the w==nil guard is
	// the one that fires (no time-validation path is exercised here).
	var w *NativeProvisioningWallet
	now := time.Now()

	// 252: Reserve returns ErrNoUsableNativeProvisioning and a zero reservation.
	reservation, err := w.Reserve(nil, now)
	if !errors.Is(err, ErrNoUsableNativeProvisioning) {
		t.Fatalf("nil.Reserve err = %v, want ErrNoUsableNativeProvisioning (:252 should reject)", err)
	}
	if reservation.SpentHintKey != nil || reservation.RelayBucketID != nil || reservation.AccessHintExpiryUnix != 0 || reservation.Provisioning.IssuerMetadata != nil {
		t.Fatalf("nil.Reserve reservation = %+v, want zero value (:252)", reservation)
	}

	// 293: BucketStatus returns nil (the w==nil side of the compound guard).
	if status := w.BucketStatus(nil, now); status != nil {
		t.Fatalf("nil.BucketStatus = %v, want nil (:293 should return nil)", status)
	}

	// 341: Zero is void; proven by absence of panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("nil.Zero panicked = %v, want no-op return (:341 should guard the nil receiver)", r)
			}
		}()
		w.Zero()
	}()
}

func TestNativeProvisioningReservationAndEntryNilReceiverGuards(t *testing.T) {
	// 352/385: a nil *NativeProvisioningReservation / *nativeProvisioningWalletEntry
	// returns at the first statement of Zero / zero rather than dereferencing
	// r.SpentHintKey / entry.encoded. Both are void; proven by absence of panic.
	var r *NativeProvisioningReservation
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("nil.(*NativeProvisioningReservation).Zero panicked = %v, want no-op return (:352 should guard the nil receiver)", rec)
			}
		}()
		r.Zero()
	}()

	var entry *nativeProvisioningWalletEntry
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("nil.(*nativeProvisioningWalletEntry).zero panicked = %v, want no-op return (:385 should guard the nil receiver)", rec)
			}
		}()
		entry.zero()
	}()
}

func TestNativeProvisioningWalletZeroerNilArgumentGuards(t *testing.T) {
	// 401/412: the two unexported zeroers return at their first statement when
	// given a nil pointer, before iterating the value's fields. Each is void; the
	// proof is that the call completes without panicking (a panic surfaces as a
	// test failure).
	zeroNativeAccessHintCredential(nil)
	zeroNativeProvisioning(nil)
}
