package protocol

// Adversarial coverage for the key- and authority-record validators in
// protocol/records.go. The existing records_test.go covers a slice of the
// validateSignatureKeyEncodingCompatibility matrix (P-256 and ML-DSA-65 bad
// encodings), the SPKI parse-error and curve-mismatch paths, the fixed-length
// mismatches, and the AuthorityKeyRecord usage-bit check. The residual count-0
// branches are the other compatibility-matrix cells, the SPKI not-ECDSA and happy
// returns, and the AuthorityKeyRecord Validate / ValidateStructural rejection
// branches.
//
// This file covers them by calling the validators directly (white-box: the
// package-level helpers are accessible) with crafted records, perturbing exactly
// one field per case so the branch under test is the one that fires.
//
// Uncovered blocks (measured count 0 before this file):
//   - validateSignatureKeyEncodingCompatibility (65, 69.2%): P-384 bad encoding 72,
//     ML-DSA-87 bad encoding 80, Ed25519 bad encoding 84, unknown scheme 87.
//   - validateECDSASPKIPublicKey (93, 77.8%): not-ECDSA 99, happy return 105.
//   - AuthorityKeyRecord.Validate (150, 66.7%): structural propagation 151,
//     outside validity interval 154, status not usable 157.
//   - AuthorityKeyRecord.ValidateStructural (167, 54.5%): IDs not 16 bytes 168,
//     empty validity interval 171, reserved status 174, reserved usage bits 177,
//     public-key compatibility propagation 180.
//
// Dead-by-design (documented, not covered):
//   - PublicKeyRecord.ValidateCompatibility (59/62) — the `len(r.PublicKey) == 0`
//     fallthrough and the trailing `return nil`. validateSignatureKeyEncodingCompatibility
//     accepts exactly the five scheme groups (ECDSA P-256, ECDSA P-384, ML-DSA-65,
//     ML-DSA-87, Ed25519-lab), and the ValidateStructural switch at lines 41-58
//     matches exactly those same five groups with every case returning. So once
//     line 38's compatibility check passes, the switch always matches and always
//     returns; the post-switch code (59-62) is unreachable for any constructible
//     record. (The switch's own cases are already covered.)
//
// Not duplicated: the SPKI parse-error (95) and curve-mismatch (102) branches and
// the fixed-length mismatches are already covered by records_test.go and are not
// re-asserted here except where a complete table naturally includes them.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection asserts exactly one error substring so the
// failure is attributable to the perturbed field alone. No new package-level
// helpers are added; the SPKI keys for validateECDSASPKIPublicKey are generated
// locally inside its test (the package already generates ECDSA keys this way in
// records_test.go), so there is no U1000 concern. No context.Context, no
// deprecated APIs.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestValidateSignatureKeyEncodingCompatibilityDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name     string
		scheme   uint64
		encoding uint64
		wantSub  string
	}{
		{"P-384 incompatible encoding", registry.SigECDSAP384SHA384DER, registry.KeyP256SEC1Uncompressed, "ECDSA P-384 signature incompatible"},
		{"ML-DSA-87 incompatible encoding", registry.SigMLDSA87, registry.KeyMLDSA65RawPublic, "ML-DSA-87 signature incompatible"},
		{"Ed25519 incompatible encoding", registry.SigEd25519Lab, registry.KeyMLDSA65RawPublic, "Ed25519 lab signature incompatible"},
		{"unknown signature scheme", 0xBAD, registry.KeyP256SEC1Uncompressed, "unknown signature scheme"},
		{"P-256 valid accepted", registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed, ""},
		{"ML-DSA-65 valid accepted", registry.SigMLDSA65, registry.KeyMLDSA65RawPublic, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSignatureKeyEncodingCompatibility(tc.scheme, tc.encoding)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestValidateECDSASPKIPublicKeyDecidesPerCondition(t *testing.T) {
	// Generate real keys once so each table case reuses them; generating ECDSA/RSA
	// keys uses crypto/rand (the package already does this in records_test.go).
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	p256SPKI, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-256 SPKI: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	p384SPKI, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-384 SPKI: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaSPKI, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA SPKI: %v", err)
	}

	cases := []struct {
		name    string
		key     []byte
		curve   elliptic.Curve
		wantSub string
	}{
		{"malformed SPKI", []byte("not-spki"), elliptic.P256(), "invalid P-256 SPKI public key"},
		{"not ECDSA", rsaSPKI, elliptic.P256(), "P-256 SPKI public key is not ECDSA"},
		{"curve mismatch", p384SPKI, elliptic.P256(), "P-256 SPKI public key curve mismatch"},
		{"valid accepted", p256SPKI, elliptic.P256(), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateECDSASPKIPublicKey(tc.key, tc.curve, "P-256 SPKI public key")
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

// recordsCovValidAuthorityKey returns an AuthorityKeyRecord that passes
// ValidateStructural and Validate(now, 0) for any now in [10, 30). It is the
// baseline for the ValidateStructural and Validate rejection tables; each case
// perturbs exactly one field so the target branch is the one that fires. It uses
// the in-package fill() helper (defined in records_test.go) for fixed byte
// slices, so no crypto/rand is needed. Referenced by >=2 tests, so not U1000.
func recordsCovValidAuthorityKey() AuthorityKeyRecord {
	return AuthorityKeyRecord{
		AuthorityID:    fill(0x01, 16),
		AuthorityKeyID: fill(0x02, 16),
		AuthorityRole:  0x01,
		PublicKey: PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       fill(0x04, 65),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}
}

func TestAuthorityKeyRecordValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*AuthorityKeyRecord)
		wantSub string
	}{
		{"authority ID wrong length", func(r *AuthorityKeyRecord) { r.AuthorityID = fill(0x01, 15) }, "authority IDs must be 16 bytes"},
		{"empty validity interval", func(r *AuthorityKeyRecord) { r.ValidUntilUnix = r.ValidFromUnix }, "authority key validity interval is empty"},
		{"reserved key status", func(r *AuthorityKeyRecord) { r.KeyStatus = 3 }, "authority key status is reserved"},
		{"reserved usage bits", func(r *AuthorityKeyRecord) { r.UsageFlags = 0x40 }, "authority usage has reserved bits set"},
		{"public key incompatible", func(r *AuthorityKeyRecord) { r.PublicKey.KeyEncoding = registry.KeyMLDSA65RawPublic }, "incompatible with key encoding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := recordsCovValidAuthorityKey()
			tc.mutate(&r)
			err := r.ValidateStructural()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestAuthorityKeyRecordValidateDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*AuthorityKeyRecord)
		now     uint64
		wantSub string
	}{
		// ValidateStructural propagation (line 151): a structurally-invalid record
		// fails before the time/status/usage checks run.
		{"structural failure propagated", func(r *AuthorityKeyRecord) { r.AuthorityID = fill(0x01, 15) }, 20, "authority IDs must be 16 bytes"},
		// Outside validity interval (line 154): now before ValidFromUnix.
		{"now before validity interval", nil, 5, "authority key outside validity interval"},
		// now at/after ValidUntilUnix (ValidUntilUnix is exclusive).
		{"now at validity end", nil, 30, "authority key outside validity interval"},
		// Status not usable (line 157): AuthorityRevoked passes ValidateStructural
		// (it accepts Active, RetiringVerifyOnly, Revoked) but Validate rejects it.
		{"revoked status not usable", func(r *AuthorityKeyRecord) { r.KeyStatus = registry.AuthorityRevoked }, 20, "authority key status not usable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := recordsCovValidAuthorityKey()
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			err := r.Validate(tc.now, 0)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}
