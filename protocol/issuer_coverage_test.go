package protocol

// Adversarial coverage for the pure issuer-record validators in protocol/issuer.go
// that the existing issuer_test.go suite reaches only on its happy paths (or not at
// all). Every function under test is pure: it reads only struct fields and registry
// constants (plus a sha256 for token-key-id matching), so each branch is isolated by
// crafting a minimal record and perturbing exactly one field. The uncovered blocks
// (measured count 0 before this file):
//
//   - IssuerTokenKeyRecord.ValidateWithOptions (line 45, 51.9% before): key-id length,
//     validity interval, status, the BlindRSA arm (scheme mismatch + production key-id
//     mismatch), the OpaqueIssuer private-scheme-range reject, the Lab scheme mismatch
//     + non-empty-key reject (both with the relevant gate enabled), and the unknown
//     proof type. The existing TestIssuerTokenKeyRecordMatchesProofTypeToKeyScheme only
//     exercises the VOPRF scheme mismatch and the VOPRF production key-id mismatch; the
//     BlindRSA arm and the OpaqueIssuer/Lab private rejects are untouched.
//   - IssuerTokenKeyRecord.validateStructuralWithOptions (line 93, 28% before): the
//     structural twin of the above (key-id length, empty validity interval, status,
//     VOPRF/BlindRSA scheme mismatch + production key-id mismatch, OpaqueIssuer
//     private-disabled + scheme-range, Lab disabled + scheme mismatch + non-empty key,
//     unknown proof type).
//   - IssuerMetadata.ValidateStructuralWithOptions (line 410, 57.1% before): version,
//     issuer id, validity, signing key id, lab-signature disabled, signature/key
//     encoding incompatibility, token-key validate propagation, origin-policy empty
//     interval, relay-scope id length, relay-scope empty interval, auxiliary-binding
//     proof-type propagation, and the extensions check. The existing
//     TestIssuerMetadataValidateStructuralRejectsReservedVerifierServiceIDs covers the
//     happy path and the reserved verifier-service kind/protocol rejects (and
//     TestIssuerMetadataAndVerifierPayloadsRoundTrip covers encode/decode only) — those
//     are NOT duplicated.
//   - validateIssuerProofTypeKnown (line 468, 55.6% before): the Lab case (allowed->nil
//     and disabled->error) and the unknown-default. The OpaqueIssuer arm is already
//     covered.
//   - IssuerVerifierServiceRecord.validateStructuralWithOptions (line 487, 68.4%
//     before): service id length, validity interval, status propagation, public-key
//     compatibility propagation, allowed-proof-type propagation, and relay-bucket id
//     length. The reserved-kind/protocol rejects are covered by the existing reserved-IDs
//     test — NOT duplicated.
//   - validateVerifierServiceKind (line 519, 71.4% before): the private 0x7000-0x7eff
//     range and the lab 0x7f00-0x7fff range (with allowLab).
//   - validateVerifierServiceProtocol (line 533, 80% before): the private 0x7000-0x7eff
//     range.
//   - validateIssuerStatusKnown (line 543, 66.7% before): the reserved-status default.
//   - validateIssuerPublicKeyCompatibility (line 552, 66.7% before): the lab-signature
//     disabled reject (without allowLab).
//   - IssuerVerifierServiceRecord.Allows (line 271, 80% before): service kind, service
//     protocol, validity, status, and proof-not-allowed. The empty-allowlist,
//     request-auth-policy, wrong-proof-type, and happy paths are already covered — NOT
//     duplicated.
//   - IssuerMetadata.Unsigned (line 559, 0%) and IssuerVerifierResponse.Unsigned (line
//     728, 0%): the signature-clearing copies.
//   - IssuerVerifierRequest.EncodedLen (line 608, 0%): the happy (length, true) path, the
//     field-length mismatch reject, the over-long TokenAuthenticator reject, and the
//     varint-out-of-range reject.
//
// Dead-by-design branches (documented, not contrived):
//   - IssuerVerifierRequest.EncodedLen:648-650 and :659-661 (addEncodedLength overflow).
//     addEncodedLength (frames.go:85) returns (0,false) only when total+next would
//     overflow int. The accumulated length is bounded: eleven fixed-length fields (16,
//     32, or 48 bytes each), a TokenAuthenticator capped at 0xffff by the 629 guard, a
//     constant 27-byte fixed portion, and three varints of at most 8 bytes. The maximum
//     total is well under 70 KB, far below int's max (~2^31-1 on 32-bit), so the overflow
//     branches in both loops cannot fire.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection case asserts exactly one error so the failure is
// attributable to the perturbed field alone. New fixtures are each referenced by >=2
// tests so there is no U1000. No context.Context, no deprecated APIs.

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// validTokenKeyRecord returns a structurally-valid IssuerTokenKeyRecord for the given
// proof type: the token-verification-key scheme matches the proof type, the TokenKeyID
// is the sha256 of the verification key (so validateProductionTokenKeyId passes for the
// production arms), and the validity interval [10,30) is non-empty with an Active
// status. Lab static records use an empty key and a zero id (Lab does not call
// validateProductionTokenKeyId). Referenced by the ValidateWithOptions and
// validateStructuralWithOptions tables and by validIssuerMetadata, so it is not U1000.
func validTokenKeyRecord(proofType uint64) IssuerTokenKeyRecord {
	switch proofType {
	case registry.ProofLabStaticToken:
		return IssuerTokenKeyRecord{
			ProofType:  registry.ProofLabStaticToken,
			TokenKeyID: fill(0, 32),
			TokenVerificationKey: TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyLabStaticNoKey,
			},
			ValidFromUnix:  10,
			ValidUntilUnix: 30,
			KeyStatus:      registry.IssuerStatusActive,
		}
	case registry.ProofOpaqueIssuer:
		key := fill(0x07, 64)
		id := sha256.Sum256(key)
		return IssuerTokenKeyRecord{
			ProofType:  registry.ProofOpaqueIssuer,
			TokenKeyID: id[:],
			TokenVerificationKey: TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: 0x7050, // inside the private 0x7000-0x7eff range
				TokenVerificationKey:       key,
			},
			ValidFromUnix:  10,
			ValidUntilUnix: 30,
			KeyStatus:      registry.IssuerStatusActive,
		}
	case registry.ProofBlindRSA2048:
		key := fill(0x07, 64)
		id := sha256.Sum256(key)
		return IssuerTokenKeyRecord{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: id[:],
			TokenVerificationKey: TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       key,
			},
			ValidFromUnix:  10,
			ValidUntilUnix: 30,
			KeyStatus:      registry.IssuerStatusActive,
		}
	default: // VOPRF
		key := fill(0x07, 64)
		id := sha256.Sum256(key)
		return IssuerTokenKeyRecord{
			ProofType:  registry.ProofVOPRFP384SHA384,
			TokenKeyID: id[:],
			TokenVerificationKey: TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyVOPRFP384SHA384,
				TokenVerificationKey:       key,
			},
			ValidFromUnix:  10,
			ValidUntilUnix: 30,
			KeyStatus:      registry.IssuerStatusActive,
		}
	}
}

// validVerifierService returns an IssuerVerifierServiceRecord that passes
// validateStructuralWithOptions(ProofValidationOptions{}) and Allows: its auth key is a
// non-lab ECDSA P-256 key (verifierServiceFixture uses SigEd25519Lab, which the
// allowLab=false path rejects). Referenced by validIssuerMetadata and by the verifier
// service structural/Allows tests, so it is not U1000.
func validVerifierService() IssuerVerifierServiceRecord {
	return IssuerVerifierServiceRecord{
		ServiceID:         fill(0x22, 16),
		ServiceKind:       registry.VerifierServiceKindVOPRF,
		ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
		ServiceLocator: RoutingRecord{
			RoutingRecordID: fill(0x02, 16),
			LocatorType:     registry.LocatorOpaque,
			LocatorBody:     []byte("issuer-verifier"),
			NotBeforeUnix:   10,
			NotAfterUnix:    30,
		},
		ServiceAuthKey: PublicKeyRecord{
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			PublicKey:       fill(0x23, 65),
		},
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{fill(0x04, 16)},
		RequestAuthPolicyID:   1,
		ValidFromUnix:         10,
		ValidUntilUnix:        30,
		ServiceStatus:         registry.IssuerStatusActive,
	}
}

// validIssuerMetadata returns an IssuerMetadata that passes
// ValidateStructuralWithOptions(20, ProofValidationOptions{}): version 0x20, 16-byte
// issuer id, non-empty validity [10,30), 16-byte signing key id, a non-lab ECDSA
// P-256 signature/key-encoding pair, a valid VOPRF token key mapping, a valid origin
// policy, a valid relay bucket scope, a valid VOPRF auxiliary binding policy, and a
// valid verifier service. Referenced by the metadata structural table and the Unsigned
// test, so it is not U1000.
func validIssuerMetadata() IssuerMetadata {
	return IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            fill(0x20, 16),
		ValidFromUnix:       10,
		ValidUntilUnix:      30,
		IssuerName:          []byte("issuer"),
		SupportedProofTypes: []uint64{registry.ProofVOPRFP384SHA384},
		TokenKeyMappings:    []IssuerTokenKeyRecord{validTokenKeyRecord(registry.ProofVOPRFP384SHA384)},
		OriginInfoPolicies: []OriginInfoPolicy{{
			PolicyID:             1,
			OriginInfo:           []byte("origin"),
			AllowEmptyOriginInfo: true,
			ValidFromUnix:        10,
			ValidUntilUnix:       30,
		}},
		RelayBucketScopes: []RelayBucketScope{{
			RelayBucketID:         fill(0x33, 16),
			TokenScopeID:          fill(0x34, 16),
			AllowedOriginPolicyID: []uint64{1},
			ValidFromUnix:         10,
			ValidUntilUnix:        30,
		}},
		AuxiliaryBindingPolicies: []AuxiliaryBindingPolicy{{
			ProofType:            registry.ProofVOPRFP384SHA384,
			BindingProofRequired: true,
			MaxBindingProofLen:   128,
			BindingPolicyID:      9,
		}},
		VerifierServices:     []IssuerVerifierServiceRecord{validVerifierService()},
		MetadataSigningKeyID: fill(0x21, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
}

func TestIssuerTokenKeyRecordValidateWithOptionsDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		base    func() IssuerTokenKeyRecord
		mutate  func(*IssuerTokenKeyRecord)
		now     uint64
		opts    ProofValidationOptions
		wantSub string // "" = expect nil (happy path)
	}{
		{"token key id wrong length", nil, func(k *IssuerTokenKeyRecord) { k.TokenKeyID = fill(0xee, 31) }, 20, ProofValidationOptions{}, "issuer token key id must be 32 bytes"},
		{"outside validity interval", nil, func(k *IssuerTokenKeyRecord) {}, 30, ProofValidationOptions{}, "issuer token key outside validity interval"},
		{"status not usable", nil, func(k *IssuerTokenKeyRecord) { k.KeyStatus = 0x05 }, 20, ProofValidationOptions{}, "issuer token key status not usable"},
		{"BlindRSA scheme mismatch", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofBlindRSA2048) }, func(k *IssuerTokenKeyRecord) {
			k.TokenVerificationKey.TokenVerificationKeyScheme = registry.TokenKeyVOPRFP384SHA384
		}, 20, ProofValidationOptions{}, "Blind RSA proof requires Blind RSA token key scheme"},
		{"BlindRSA production key id mismatch", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofBlindRSA2048) }, func(k *IssuerTokenKeyRecord) { k.TokenKeyID = fill(0xee, 32) }, 20, ProofValidationOptions{}, "token key id does not match token verification key"},
		{"OpaqueIssuer private scheme out of range", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofOpaqueIssuer) }, func(k *IssuerTokenKeyRecord) { k.TokenVerificationKey.TokenVerificationKeyScheme = 0x8000 }, 20, ProofValidationOptions{AllowPrivateProofTypes: true}, "opaque issuer proof requires private token key scheme"},
		{"Lab scheme mismatch", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofLabStaticToken) }, func(k *IssuerTokenKeyRecord) { k.TokenVerificationKey.TokenVerificationKeyScheme = 0x1234 }, 20, ProofValidationOptions{AllowLabProofs: true}, "lab static proof requires lab token key scheme"},
		{"Lab non-empty key", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofLabStaticToken) }, func(k *IssuerTokenKeyRecord) { k.TokenVerificationKey.TokenVerificationKey = fill(0x07, 64) }, 20, ProofValidationOptions{AllowLabProofs: true}, "lab static token key must be empty"},
		{"unknown proof type", nil, func(k *IssuerTokenKeyRecord) { k.ProofType = 0xBAD }, 20, ProofValidationOptions{}, "unknown issuer proof type"},
		{"BlindRSA valid accepted", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofBlindRSA2048) }, nil, 20, ProofValidationOptions{}, ""},
		{"OpaqueIssuer private accepted", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofOpaqueIssuer) }, nil, 20, ProofValidationOptions{AllowPrivateProofTypes: true}, ""},
		{"Lab accepted with gate", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofLabStaticToken) }, nil, 20, ProofValidationOptions{AllowLabProofs: true}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := validTokenKeyRecord(registry.ProofVOPRFP384SHA384)
			if tc.base != nil {
				key = tc.base()
			}
			if tc.mutate != nil {
				tc.mutate(&key)
			}
			err := key.ValidateWithOptions(tc.now, tc.opts)
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

func TestIssuerTokenKeyRecordValidateStructuralWithOptionsDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		base    func() IssuerTokenKeyRecord
		mutate  func(*IssuerTokenKeyRecord)
		opts    ProofValidationOptions
		wantSub string
	}{
		{"token key id wrong length", nil, func(k *IssuerTokenKeyRecord) { k.TokenKeyID = fill(0xee, 31) }, ProofValidationOptions{}, "issuer token key id must be 32 bytes"},
		{"empty validity interval", nil, func(k *IssuerTokenKeyRecord) { k.ValidUntilUnix = 10 }, ProofValidationOptions{}, "issuer token key validity interval is empty"},
		{"status not known", nil, func(k *IssuerTokenKeyRecord) { k.KeyStatus = 0x05 }, ProofValidationOptions{}, "issuer token key status is reserved"},
		{"VOPRF scheme mismatch", nil, func(k *IssuerTokenKeyRecord) {
			k.TokenVerificationKey.TokenVerificationKeyScheme = registry.TokenKeyBlindRSA2048
		}, ProofValidationOptions{}, "VOPRF proof requires VOPRF token key scheme"},
		{"VOPRF production key id mismatch", nil, func(k *IssuerTokenKeyRecord) { k.TokenKeyID = fill(0xee, 32) }, ProofValidationOptions{}, "token key id does not match token verification key"},
		{"BlindRSA scheme mismatch", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofBlindRSA2048) }, func(k *IssuerTokenKeyRecord) {
			k.TokenVerificationKey.TokenVerificationKeyScheme = registry.TokenKeyVOPRFP384SHA384
		}, ProofValidationOptions{}, "Blind RSA proof requires Blind RSA token key scheme"},
		{"BlindRSA production key id mismatch", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofBlindRSA2048) }, func(k *IssuerTokenKeyRecord) { k.TokenKeyID = fill(0xee, 32) }, ProofValidationOptions{}, "token key id does not match token verification key"},
		{"OpaqueIssuer private disabled", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofOpaqueIssuer) }, nil, ProofValidationOptions{}, "private issuer token key proof type 0x3 disabled"},
		{"OpaqueIssuer private scheme out of range", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofOpaqueIssuer) }, func(k *IssuerTokenKeyRecord) { k.TokenVerificationKey.TokenVerificationKeyScheme = 0x8000 }, ProofValidationOptions{AllowPrivateProofTypes: true}, "opaque issuer proof requires private token key scheme"},
		{"Lab disabled", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofLabStaticToken) }, nil, ProofValidationOptions{}, "lab issuer token key disabled"},
		{"Lab scheme mismatch", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofLabStaticToken) }, func(k *IssuerTokenKeyRecord) { k.TokenVerificationKey.TokenVerificationKeyScheme = 0x1234 }, ProofValidationOptions{AllowLabProofs: true}, "lab static proof requires lab token key scheme"},
		{"Lab non-empty key", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofLabStaticToken) }, func(k *IssuerTokenKeyRecord) { k.TokenVerificationKey.TokenVerificationKey = fill(0x07, 64) }, ProofValidationOptions{AllowLabProofs: true}, "lab static token key must be empty"},
		{"unknown proof type", nil, func(k *IssuerTokenKeyRecord) { k.ProofType = 0xBAD }, ProofValidationOptions{}, "unknown issuer proof type"},
		{"VOPRF valid accepted", nil, nil, ProofValidationOptions{}, ""},
		{"BlindRSA valid accepted", func() IssuerTokenKeyRecord { return validTokenKeyRecord(registry.ProofBlindRSA2048) }, nil, ProofValidationOptions{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := validTokenKeyRecord(registry.ProofVOPRFP384SHA384)
			if tc.base != nil {
				key = tc.base()
			}
			if tc.mutate != nil {
				tc.mutate(&key)
			}
			err := key.validateStructuralWithOptions(tc.opts)
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

func TestIssuerMetadataValidateStructuralWithOptionsDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*IssuerMetadata)
		now     uint64
		opts    ProofValidationOptions
		wantSub string
	}{
		{"unsupported metadata version", func(m *IssuerMetadata) { m.MetadataVersion = 0 }, 20, ProofValidationOptions{}, "unsupported issuer metadata version"},
		{"issuer id wrong length", func(m *IssuerMetadata) { m.IssuerID = fill(0x20, 15) }, 20, ProofValidationOptions{}, "issuer id must be 16 bytes"},
		{"outside validity interval", func(m *IssuerMetadata) {}, 30, ProofValidationOptions{}, "issuer metadata outside validity interval"},
		{"signing key id wrong length", func(m *IssuerMetadata) { m.MetadataSigningKeyID = fill(0x21, 15) }, 20, ProofValidationOptions{}, "metadata signing key id must be 16 bytes"},
		{"lab signature scheme disabled", func(m *IssuerMetadata) { m.SignatureScheme = registry.SigEd25519Lab }, 20, ProofValidationOptions{}, "lab signature scheme disabled"},
		{"signature/key encoding incompatible", func(m *IssuerMetadata) { m.KeyEncoding = registry.KeyP384SEC1Uncompressed }, 20, ProofValidationOptions{}, "ECDSA P-256 signature incompatible"},
		{"token key validate error propagates", func(m *IssuerMetadata) { m.TokenKeyMappings[0].TokenKeyID = fill(0xee, 31) }, 20, ProofValidationOptions{}, "issuer token key id must be 32 bytes"},
		{"origin policy empty interval", func(m *IssuerMetadata) { m.OriginInfoPolicies[0].ValidUntilUnix = 10 }, 20, ProofValidationOptions{}, "origin info policy validity interval is empty"},
		{"relay scope id wrong length", func(m *IssuerMetadata) { m.RelayBucketScopes[0].RelayBucketID = fill(0x33, 15) }, 20, ProofValidationOptions{}, "relay bucket scope ids must be 16 bytes"},
		{"relay scope empty interval", func(m *IssuerMetadata) { m.RelayBucketScopes[0].ValidUntilUnix = 10 }, 20, ProofValidationOptions{}, "relay bucket scope validity interval is empty"},
		{"auxiliary binding proof type error propagates", func(m *IssuerMetadata) { m.AuxiliaryBindingPolicies[0].ProofType = 0xBAD }, 20, ProofValidationOptions{}, "unknown issuer proof type"},
		{"unknown critical extension rejected", func(m *IssuerMetadata) {
			m.Extensions = []Extension{{ExtensionType: 0x9999, Critical: true, Body: []byte("x")}}
		}, 20, ProofValidationOptions{}, "unknown critical extension"},
		{"valid metadata accepted", nil, 20, ProofValidationOptions{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validIssuerMetadata()
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			err := m.ValidateStructuralWithOptions(tc.now, tc.opts)
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

func TestValidateIssuerProofTypeKnownDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name      string
		proofType uint64
		opts      ProofValidationOptions
		wantSub   string
	}{
		{"Lab accepted with gate", registry.ProofLabStaticToken, ProofValidationOptions{AllowLabProofs: true}, ""},
		{"Lab disabled without gate", registry.ProofLabStaticToken, ProofValidationOptions{}, "lab proof type disabled"},
		{"unknown proof type", 0xBAD, ProofValidationOptions{}, "unknown issuer proof type"},
		{"VOPRF accepted", registry.ProofVOPRFP384SHA384, ProofValidationOptions{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIssuerProofTypeKnown(tc.proofType, tc.opts)
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

func TestIssuerVerifierServiceRecordValidateStructuralWithOptionsDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*IssuerVerifierServiceRecord)
		opts    ProofValidationOptions
		wantSub string
	}{
		{"service id wrong length", func(s *IssuerVerifierServiceRecord) { s.ServiceID = fill(0x22, 15) }, ProofValidationOptions{}, "verifier service id must be 16 bytes"},
		{"empty validity interval", func(s *IssuerVerifierServiceRecord) { s.ValidUntilUnix = 10 }, ProofValidationOptions{}, "verifier service validity interval is empty"},
		{"status reserved", func(s *IssuerVerifierServiceRecord) { s.ServiceStatus = 0x05 }, ProofValidationOptions{}, "verifier service status is reserved"},
		{"public key incompatible", func(s *IssuerVerifierServiceRecord) { s.ServiceAuthKey.KeyEncoding = registry.KeyP384SEC1Uncompressed }, ProofValidationOptions{}, "ECDSA P-256 signature incompatible"},
		{"allowed proof type error propagates", func(s *IssuerVerifierServiceRecord) { s.AllowedProofTypes = []uint64{0xBAD} }, ProofValidationOptions{}, "unknown issuer proof type"},
		{"relay bucket id wrong length", func(s *IssuerVerifierServiceRecord) { s.AllowedRelayBucketIDs = [][]byte{fill(0x04, 15)} }, ProofValidationOptions{}, "verifier service relay bucket id must be 16 bytes"},
		{"valid service accepted", nil, ProofValidationOptions{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validVerifierService()
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			err := s.validateStructuralWithOptions(tc.opts)
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

func TestValidateVerifierServiceKindAcceptsPrivateAndLabRanges(t *testing.T) {
	if err := validateVerifierServiceKind(0x7050, false); err != nil {
		t.Fatalf("private service kind 0x7050 rejected: %v", err)
	}
	if err := validateVerifierServiceKind(0x7f50, true); err != nil {
		t.Fatalf("lab service kind 0x7f50 rejected with allowLab: %v", err)
	}
	if err := validateVerifierServiceKind(0x7f50, false); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("lab service kind 0x7f50 without allowLab err = %v, want reserved", err)
	}
}

func TestValidateVerifierServiceProtocolAcceptsPrivateRange(t *testing.T) {
	if err := validateVerifierServiceProtocol(0x7050); err != nil {
		t.Fatalf("private service protocol 0x7050 rejected: %v", err)
	}
	if err := validateVerifierServiceProtocol(0x1000); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved service protocol 0x1000 err = %v, want reserved", err)
	}
}

func TestValidateIssuerStatusKnownRejectsReservedStatus(t *testing.T) {
	if err := validateIssuerStatusKnown(0x05, "issuer token key"); err == nil || !strings.Contains(err.Error(), "issuer token key status is reserved") {
		t.Fatalf("reserved status err = %v, want reserved", err)
	}
	if err := validateIssuerStatusKnown(registry.IssuerStatusRevoked, "issuer token key"); err != nil {
		t.Fatalf("revoked status rejected: %v", err)
	}
}

func TestValidateIssuerPublicKeyCompatibilityRejectsLabSignatureWithoutAllowLab(t *testing.T) {
	key := PublicKeyRecord{
		SignatureScheme: registry.SigEd25519Lab,
		KeyEncoding:     registry.KeyEd25519RawPublic,
		PublicKey:       fill(0x03, 32),
	}
	if err := validateIssuerPublicKeyCompatibility(key, false); err == nil || !strings.Contains(err.Error(), "lab signature scheme disabled") {
		t.Fatalf("lab signature without allowLab err = %v, want lab disabled", err)
	}
	if err := validateIssuerPublicKeyCompatibility(key, true); err != nil {
		t.Fatalf("lab signature with allowLab rejected: %v", err)
	}
}

func TestIssuerVerifierServiceAllowsRejectsEachCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*IssuerVerifierServiceRecord)
		now     uint64
		wantSub string
	}{
		{"service kind not VOPRF", func(s *IssuerVerifierServiceRecord) { s.ServiceKind = 0x1000 }, 20, "verifier service kind is not VOPRF"},
		{"service protocol unsupported", func(s *IssuerVerifierServiceRecord) { s.ServiceProtocolID = 0x1000 }, 20, "verifier service protocol unsupported"},
		{"outside validity interval", func(s *IssuerVerifierServiceRecord) {}, 30, "verifier service outside validity interval"},
		{"status not usable", func(s *IssuerVerifierServiceRecord) { s.ServiceStatus = 0x05 }, 20, "verifier service status not usable"},
		{"proof type not allowed", func(s *IssuerVerifierServiceRecord) { s.AllowedProofTypes = []uint64{registry.ProofBlindRSA2048} }, 20, "verifier service proof type not allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validVerifierService()
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			err := s.Allows(registry.ProofVOPRFP384SHA384, fill(0x04, 16), tc.now, true)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestIssuerMetadataUnsignedClearsSignature(t *testing.T) {
	m := validIssuerMetadata()
	m.MetadataSignature = []byte("metadata-signature")
	unsigned := m.Unsigned()
	if unsigned.MetadataSignature != nil {
		t.Fatalf("Unsigned().MetadataSignature = %v, want nil", unsigned.MetadataSignature)
	}
	if m.MetadataSignature == nil {
		t.Fatal("Unsigned mutated the receiver's signature")
	}
}

func TestIssuerVerifierResponseUnsignedClearsSignature(t *testing.T) {
	r := IssuerVerifierResponse{
		ResponseVersion:  registry.Version20,
		ServiceID:        fill(0x41, 16),
		RequestHash:      fill(0x42, 48),
		Decision:         registry.VerifierDecisionAccept,
		TokenSpentKey:    fill(0x43, 48),
		ValidUntilUnix:   180,
		ResponseNonce:    fill(0x44, 32),
		ServiceSignature: []byte("service-signature"),
	}
	unsigned := r.Unsigned()
	if unsigned.ServiceSignature != nil {
		t.Fatalf("Unsigned().ServiceSignature = %v, want nil", unsigned.ServiceSignature)
	}
	if r.ServiceSignature == nil {
		t.Fatal("Unsigned mutated the receiver's signature")
	}
}

func TestIssuerVerifierRequestEncodedLenDecidesPerCondition(t *testing.T) {
	validRequest := func() IssuerVerifierRequest {
		return IssuerVerifierRequest{
			RequestVersion:            registry.Version20,
			ServiceID:                 fill(0x36, 16),
			IssuerID:                  fill(0x37, 16),
			IssuerMetadataHash:        fill(0x38, 48),
			RelayDescriptorHash:       fill(0x39, 48),
			RelayBucketID:             fill(0x3a, 16),
			RouteInstanceID:           77,
			HopIndex:                  2,
			ProofType:                 registry.ProofVOPRFP384SHA384,
			TokenKeyID:                fill(0x3b, 32),
			TokenNonce:                fill(0x3c, 32),
			ChallengeDigest:           fill(0x3d, 32),
			AuthenticatorInputHash:    fill(0x3e, 48),
			TokenAuthenticator:        []byte("token-authenticator"),
			TokenSpentKey:             fill(0x3f, 48),
			ReplayEpochID:             88,
			ReplayEpochValidUntilUnix: 300,
			RequestNonce:              fill(0x40, 32),
			RequestTimeUnix:           150,
		}
	}

	t.Run("valid request returns positive length", func(t *testing.T) {
		length, ok := validRequest().EncodedLen()
		if !ok || length <= 0 {
			t.Fatalf("EncodedLen(valid) = (%d, %v), want (positive, true)", length, ok)
		}
	})

	t.Run("field length mismatch rejected", func(t *testing.T) {
		req := validRequest()
		req.ServiceID = fill(0x36, 15) // EncodedLen checks ServiceID is 16 bytes
		if _, ok := req.EncodedLen(); ok {
			t.Fatal("EncodedLen accepted a wrong-length field")
		}
	})

	t.Run("over-long TokenAuthenticator rejected", func(t *testing.T) {
		req := validRequest()
		req.TokenAuthenticator = make([]byte, 0x10000) // exceeds the 0xffff cap
		if _, ok := req.EncodedLen(); ok {
			t.Fatal("EncodedLen accepted an over-long TokenAuthenticator")
		}
	})

	t.Run("varint out of range rejected", func(t *testing.T) {
		// RequestVersion > MaxVarint (1<<62 - 1) makes wire.VarintLen error, which
		// EncodedLen surfaces as (0, false). All field lengths stay valid so the only
		// failing check is the varint length computation.
		req := validRequest()
		req.RequestVersion = ^uint64(0)
		if _, ok := req.EncodedLen(); ok {
			t.Fatal("EncodedLen accepted an out-of-range varint")
		}
	})
}
