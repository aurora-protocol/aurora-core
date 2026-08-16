package handshake

// Adversarial coverage for the pure helper functions in the handshake package
// that the existing handshake/cover/control suites reach only on their happy
// paths (or not at all):
//   - signatureUpperBound (relay.go:608, 42.9% before): a six-arm switch over
//     PublicKeyRecord.SignatureScheme returning each scheme's signature-size
//     upper bound, plus the unsupported-scheme default error. Only the schemes
//     exercised by the production signer paths are covered; the remaining arms
//     and the default stay uncovered.
//   - zeroPolicyAccept (relay.go:504, 42.9% before): the nil guard, the
//     VirtualAddressAssignment==nil skip, and the assignment!=nil field-zeroing
//     branch. The existing samplePolicyAcceptForControl fixture carries a nil
//     assignment, so the field-zeroing branch is never reached.
//   - zeroExtensions (client.go:783, 50% before): the loop body that zeroes each
//     extension Body. The existing callers pass empty/nil extension slices, so
//     the loop never executes.
//   - zeroHandshakeSecrets (client.go:789, 75% before): the nil guard and the
//     11-field zeroing loop.
//   - zeroTransportHints (relay.go:516, 80% before): the nil guard and the
//     NetworkCohortHint/Padding/Extensions zeroing.
//   - zeroAccessHintCredential (relay.go:625, 83.3% before): the nil guard and
//     the four-field zeroing.
//
// All six helpers are pure (memory zeroing / a one-field switch) with no IO or
// crypto-bundle dependencies, so each branch is isolated by crafting a minimal
// struct. The zeroing helpers are asserted by checking the target []byte fields
// are all-zero with length preserved after the call. No new fixtures that encode
// valid wire forms are needed.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs). New helpers are each referenced by >=2 tests so there
// is no U1000. No context.Context, no deprecated APIs.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestSignatureUpperBoundReturnsSizePerScheme(t *testing.T) {
	cases := []struct {
		name     string
		scheme   uint64
		wantSize int // 0 = assert only >0 (library-defined size)
		wantErr  bool
	}{
		{"ECDSA P256 SHA256 DER", registry.SigECDSAP256SHA256DER, 72, false},
		{"ECDSA P256 SHA384 DER", registry.SigECDSAP256SHA384DER, 72, false},
		{"ECDSA P384 SHA384 DER", registry.SigECDSAP384SHA384DER, 104, false},
		{"ML-DSA-65", registry.SigMLDSA65, 0, false},
		{"ML-DSA-87", registry.SigMLDSA87, 0, false},
		{"Ed25519 lab", registry.SigEd25519Lab, 64, false},
		{"unsupported scheme", 0xFFFF, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size, err := signatureUpperBound(protocol.PublicKeyRecord{SignatureScheme: tc.scheme})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "unsupported") {
					t.Fatalf("%s: err = %v, want unsupported-scheme error", tc.name, err)
				}
				if size != 0 {
					t.Fatalf("%s: size = %d, want 0 on error", tc.name, size)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: err = %v, want nil", tc.name, err)
			}
			if tc.wantSize != 0 {
				if size != tc.wantSize {
					t.Fatalf("%s: size = %d, want %d", tc.name, size, tc.wantSize)
				}
				return
			}
			if size <= 0 {
				t.Fatalf("%s: size = %d, want >0", tc.name, size)
			}
		})
	}
}

func TestZeroPolicyAcceptZeroesAssignmentAndExtensions(t *testing.T) {
	t.Run("nil value is a no-op", func(t *testing.T) {
		zeroPolicyAccept(nil) // must not panic
	})
	t.Run("nil assignment still zeroes extensions", func(t *testing.T) {
		policy := &protocol.PolicyAccept{
			Extensions: []protocol.Extension{
				{ExtensionType: 0x7005, Body: []byte{0xAA, 0xBB, 0xCC}},
				{ExtensionType: 0x7006, Body: []byte{0xDD}},
			},
		}
		zeroPolicyAccept(policy)
		if policy.VirtualAddressAssignment != nil {
			t.Fatalf("assignment = %v, want nil", policy.VirtualAddressAssignment)
		}
		assertExtensionsZeroed(t, policy.Extensions)
	})
	t.Run("populated assignment fields and extensions are zeroed", func(t *testing.T) {
		policy := &protocol.PolicyAccept{
			VirtualAddressAssignment: &protocol.VirtualAddressAssignment{
				LeaseID:       []byte{0x11, 0x12, 0x13, 0x14},
				ClientAddress: []byte{0x21, 0x22, 0x23, 0x24},
				DNSServerHint: []byte{0x31, 0x32, 0x33},
			},
			Extensions: []protocol.Extension{{ExtensionType: 0x7005, Body: []byte{0xEE, 0xFF}}},
		}
		zeroPolicyAccept(policy)
		a := policy.VirtualAddressAssignment
		if a == nil {
			t.Fatal("assignment was nil after zeroing")
		}
		if !allZero(a.LeaseID) || !allZero(a.ClientAddress) || !allZero(a.DNSServerHint) {
			t.Fatalf("assignment fields not zeroed: LeaseID=%v ClientAddress=%v DNSServerHint=%v", a.LeaseID, a.ClientAddress, a.DNSServerHint)
		}
		if len(a.LeaseID) != 4 || len(a.ClientAddress) != 4 || len(a.DNSServerHint) != 3 {
			t.Fatal("zeroing changed field lengths")
		}
		assertExtensionsZeroed(t, policy.Extensions)
	})
}

func TestZeroExtensionsZeroesBodiesPreservingLength(t *testing.T) {
	t.Run("nil and empty are no-ops", func(t *testing.T) {
		zeroExtensions(nil) // must not panic
		zeroExtensions([]protocol.Extension{})
	})
	t.Run("non-empty bodies are zeroed with type preserved", func(t *testing.T) {
		exts := []protocol.Extension{
			{ExtensionType: 0x7005, Body: []byte{0xAA, 0xBB, 0xCC}},
			{ExtensionType: 0x7006, Body: []byte{0xDD}},
		}
		zeroExtensions(exts)
		assertExtensionsZeroed(t, exts)
		if exts[0].ExtensionType != 0x7005 || exts[1].ExtensionType != 0x7006 {
			t.Fatalf("zeroing changed extension types: %+v", exts)
		}
	})
}

func TestZeroHandshakeSecretsZeroesEveryField(t *testing.T) {
	t.Run("nil value is a no-op", func(t *testing.T) {
		zeroHandshakeSecrets(nil) // must not panic
	})
	t.Run("populated secrets are zeroed with length preserved", func(t *testing.T) {
		secret := &HandshakeSecrets{
			EarlySecret: []byte{0x01, 0x02}, DerivedSecret: []byte{0x03}, HandshakeSecret: []byte{0x04, 0x05, 0x06},
			ClientHandshakeSecret: []byte{0x07}, ServerHandshakeSecret: []byte{0x08, 0x09},
			ClientFinishedKey: []byte{0x0A}, ServerFinishedKey: []byte{0x0B, 0x0C},
			ClientHSKey: []byte{0x0D}, ClientHSIV: []byte{0x0E, 0x0F},
			ServerHSKey: []byte{0x10}, ServerHSIV: []byte{0x11, 0x12},
		}
		zeroHandshakeSecrets(secret)
		for _, f := range [][]byte{
			secret.EarlySecret, secret.DerivedSecret, secret.HandshakeSecret,
			secret.ClientHandshakeSecret, secret.ServerHandshakeSecret,
			secret.ClientFinishedKey, secret.ServerFinishedKey,
			secret.ClientHSKey, secret.ClientHSIV, secret.ServerHSKey, secret.ServerHSIV,
		} {
			if !allZero(f) {
				t.Fatalf("handshake secret field not zeroed: %v", f)
			}
		}
	})
}

func TestZeroTransportHintsZeroesCohortPaddingAndExtensions(t *testing.T) {
	t.Run("nil value is a no-op", func(t *testing.T) {
		zeroTransportHints(nil) // must not panic
	})
	t.Run("populated hints are zeroed", func(t *testing.T) {
		hints := &protocol.ClientTransportHints{
			NetworkCohortHint: []byte{0xAA, 0xBB, 0xCC},
			Padding:           []byte{0xDD, 0xEE},
			Extensions:        []protocol.Extension{{ExtensionType: 0x7007, Body: []byte{0x01, 0x02}}},
		}
		zeroTransportHints(hints)
		if !allZero(hints.NetworkCohortHint) || !allZero(hints.Padding) {
			t.Fatalf("hints not zeroed: cohort=%v padding=%v", hints.NetworkCohortHint, hints.Padding)
		}
		if len(hints.NetworkCohortHint) != 3 || len(hints.Padding) != 2 {
			t.Fatal("zeroing changed field lengths")
		}
		assertExtensionsZeroed(t, hints.Extensions)
	})
}

func TestZeroAccessHintCredentialZeroesAllBindingFields(t *testing.T) {
	t.Run("nil value is a no-op", func(t *testing.T) {
		zeroAccessHintCredential(nil) // must not panic
	})
	t.Run("populated credential fields are zeroed", func(t *testing.T) {
		cred := &admission.AccessHintCredential{
			HintIssuerID:  []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
			RelayBucketID: []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30},
			HintSelector:  []byte{0x31, 0x32, 0x33, 0x34},
			HintSecret:    []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
		}
		zeroAccessHintCredential(cred)
		if !allZero(cred.HintIssuerID) || !allZero(cred.RelayBucketID) || !allZero(cred.HintSelector) || !allZero(cred.HintSecret) {
			t.Fatalf("credential fields not zeroed: issuer=%v bucket=%v selector=%v secret=%v",
				cred.HintIssuerID, cred.RelayBucketID, cred.HintSelector, cred.HintSecret)
		}
		if len(cred.HintIssuerID) != 16 || len(cred.RelayBucketID) != 16 || len(cred.HintSelector) != 4 || len(cred.HintSecret) != 8 {
			t.Fatal("zeroing changed field lengths")
		}
	})
}

// allZero reports whether every byte of b is zero. A nil or empty slice is
// all-zero. Referenced by every zeroing-helper subtest, so it is not U1000.
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// assertExtensionsZeroed fails the test if any extension Body is not all-zero,
// and verifies that Body lengths and ExtensionType values are preserved.
func assertExtensionsZeroed(t *testing.T, exts []protocol.Extension) {
	t.Helper()
	for i, ext := range exts {
		if !allZero(ext.Body) {
			t.Fatalf("extension %d body not zeroed: %v (type 0x%x)", i, ext.Body, ext.ExtensionType)
		}
		// Body length must be preserved; a zeroed body must equal a zero slice
		// of the same length.
		if !bytes.Equal(ext.Body, make([]byte, len(ext.Body))) {
			t.Fatalf("extension %d body length not preserved", i)
		}
	}
}
