package client_test

// Adversarial white-box branch coverage for three count-0 pure input-validation
// guards in the exported wallet entry points (client/native_provisioning_wallet.go):
//
//	EncodeNativeProvisioningWallet (EncodeNativeProvisioningWallet:64):
//	    if len(provisioning) == 0 || len(provisioning) > maximumNativeProvisioningWalletEntries {
//	        return nil, fmt.Errorf("client: native provisioning wallet entry count is invalid")  // :65  <-- COUNT 0
//	    }
//	    for _, value := range provisioning {
//	        encoded, err := EncodeNativeProvisioning(value)
//	        if err != nil {
//	            return nil, fmt.Errorf("client: encode native provisioning wallet entry: %w", err)   // :73  <-- COUNT 0
//	        }
//	        ...
//	    }
//
//	ParseNativeProvisioningWalletWithTrust (ParseNativeProvisioningWalletWithTrust:116):
//	    if err := signedSeedTrust.validate(); err != nil {
//	        return nil, fmt.Errorf("client: native provisioning wallet trust: %w", err)            // :117 <-- COUNT 0
//	    }
//	    ...
//
// All three are reachable with trivially-constructed, zero-value/empty inputs and no
// cryptography, no goroutine, no network — they are pure argument checks at the very
// top of the exported functions, so the tests are fully deterministic.
//
//	- :65  -> an empty slice (len 0) or an overlong slice (len 65 > maximumNativeProvisioningWalletEntries=64).
//	- :73  -> a single zero-value NativeProvisioning entry: EncodeNativeProvisioning calls
//	          validateContainer first, which rejects the empty RelayURL at its very first
//	          check (validateNativeHTTPSURL("", required)), so EncodeNativeProvisioning
//	          returns an error and the wallet propagates it at :73.
//	- :117 -> a zero-value NativeProvisioningTrust (nil pinned roots): validate() calls
//	          NewSignedSeedTrustStore(nil), which rejects empty pinned bootstrap roots
//	          (trust/signed_seed.go:77), so validate() errors and the wallet propagates it
//	          at :117. This is the FIRST guard in ParseNativeProvisioningWalletWithTrust,
//          so the encoded/now arguments are never consulted.
//
// The dead-by-design siblings are deliberately NOT claimed:
//	- :77 (nativeProvisioningWalletEntryFor err) — reached only AFTER a fully-valid
//	  NativeProvisioning (all validateContainer fields valid) whose AccessHint still
//	  fails admission.DecodeAccessHintCredential; constructing that needs a complete
//	  valid provisioning (valid URLs, headers, trust roots, identifiers), which is heavy.
//	- :98 (encoder.Bytes err) and :101 (encoded > MaximumNativeProvisioningWalletBytes) —
//	  validateContainer bounds every field to its wire limit (opaque16/opaque24 max), so
//	  the per-entry encoder cannot overflow and the bounded entry set cannot exceed the
//	  wallet size limit; dominated by the validateContainer bounds check.
//
// The functions and the NativeProvisioning / NativeProvisioningTrust types are exported,
// so the test uses the external client_test package (no in-package access needed). The
// per-line coverage flips (:65 0->1, :73 0->1, :117 0->1) are the rigorous proof.

import (
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
)

func TestNativeProvisioningWalletInputValidationGuards(t *testing.T) {
	now := time.Unix(1700000000, 0)

	// :65 — empty slice: the entry-count guard fires before any entry is encoded.
	if _, err := client.EncodeNativeProvisioningWallet(nil); err == nil {
		t.Fatal("EncodeNativeProvisioningWallet(nil) err = nil, want non-nil (:65 count guard)")
	} else if !strings.Contains(err.Error(), "entry count is invalid") {
		t.Fatalf("EncodeNativeProvisioningWallet(nil) err = %v, want substring %q", err, "entry count is invalid")
	}

	// :65 — overlong slice (65 > maximumNativeProvisioningWalletEntries=64): the same
	// count guard fires via the upper-bound arm of the || before any entry is encoded.
	if _, err := client.EncodeNativeProvisioningWallet(make([]client.NativeProvisioning, 65)); err == nil {
		t.Fatal("EncodeNativeProvisioningWallet(65 entries) err = nil, want non-nil (:65 count guard)")
	} else if !strings.Contains(err.Error(), "entry count is invalid") {
		t.Fatalf("EncodeNativeProvisioningWallet(65 entries) err = %v, want substring %q", err, "entry count is invalid")
	}

	// :73 — a single zero-value entry passes the count guard (len 1 is in range) but
	// fails EncodeNativeProvisioning: validateContainer rejects the empty RelayURL at its
	// first check, so the wallet propagates the encode error at :73.
	if _, err := client.EncodeNativeProvisioningWallet([]client.NativeProvisioning{{}}); err == nil {
		t.Fatal("EncodeNativeProvisioningWallet([zero entry]) err = nil, want non-nil (:73 encode-err guard)")
	} else if !strings.Contains(err.Error(), "encode native provisioning wallet entry") {
		t.Fatalf("EncodeNativeProvisioningWallet([zero entry]) err = %v, want substring %q", err, "encode native provisioning wallet entry")
	}

	// :117 — a zero-value NativeProvisioningTrust (nil pinned roots) makes validate()
	// fail (NewSignedSeedTrustStore rejects empty pinned bootstrap roots), and the wallet
	// propagates it at :117. This is the first guard, so encoded/now are never read.
	if _, err := client.ParseNativeProvisioningWalletWithTrust([]byte{0x01}, client.NativeProvisioningTrust{}, now); err == nil {
		t.Fatal("ParseNativeProvisioningWalletWithTrust(zero trust) err = nil, want non-nil (:117 validate-err guard)")
	} else if !strings.Contains(err.Error(), "native provisioning wallet trust") {
		t.Fatalf("ParseNativeProvisioningWalletWithTrust(zero trust) err = %v, want substring %q", err, "native provisioning wallet trust")
	}
}
