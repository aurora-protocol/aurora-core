package protocol

// Adversarial coverage for the pure validation helpers in protocol/admission.go
// that the existing bootstrap / private-proof / issuer suites reach only on
// their happy paths (or not at all):
//   - AdmissionProof.ValidateStructuralWithOptions (line 70, 58.3% before): every
//     rejection branch stays uncovered — version, expiry, the Lab proof-type gate,
//     the unknown-proof-type default, the six fixed-length field checks, the
//     zero-binding-proof requirement (VOPRF/BlindRSA/Lab), the production-token
//     metadata decode error, the ValidateForProof propagation, and the extensions
//     check. (The OpaqueIssuer private gate at 80 and the oversized-opaque-binding
//     check at 125 are already covered by private_proof_test.go — not duplicated.)
//   - AuroraTokenMetadata.ValidateForProof (line 174, 53.8% before): all six
//     rejection branches (proof-type overflow, token-type mismatch, challenge
//     digest length, token key id mismatch, empty issuer name, issuer-metadata
//     hash mismatch) are uncovered; driven directly with crafted structs.
//   - AdmissionProof.ValidateStructural (line ~62 wrapper, 53.8% before): the
//     allowLab=true dispatch is only reached indirectly; covered directly here.
//   - DecodeAuroraTokenMetadataBytes (line 162, 71.4% before): the r.Err
//     (malformed payload) and trailing-bytes branches are uncovered.
//   - ReplayProof.ValidateStructural (line 228, 53.8% before): every rejection
//     branch uncovered; driven via the existing sampleReplayProof fixture.
//   - ClientTransportHints.ValidatePrototype (line 292, 71.4% before): the
//     hint_flags and network_cohort_hint rejection branches uncovered.
//
// Reuses the in-package fixtures sampleAdmissionProof (valid BlindRSA base with
// a valid encoded AuroraTokenMetadata), sampleReplayProof, sampleClientTransportHints,
// the fill(b,n) helper, and the package Encode. New helpers are each referenced by
// >=2 tests so there is no U1000. No context.Context, no deprecated APIs.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one error so the
// failure is attributable to the perturbed field alone.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestAdmissionProofValidateStructuralWithOptionsDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		base    func() AdmissionProof
		mutate  func(*AdmissionProof)
		opts    ProofValidationOptions
		wantSub string // "" = expect nil (happy path)
	}{
		{
			name:    "unsupported proof version",
			mutate:  func(p *AdmissionProof) { p.ProofVersion = 0 },
			wantSub: "unsupported admission proof version",
		},
		{
			name:    "expired proof",
			mutate:  func(p *AdmissionProof) { p.ExpiryUnix = 1 }, // now(20) >= 1
			wantSub: "admission proof expired",
		},
		{
			name:    "issuer id wrong length",
			mutate:  func(p *AdmissionProof) { p.IssuerID = fill(0x10, 15) },
			wantSub: "issuer id must be 16 bytes",
		},
		{
			name:    "token key id wrong length",
			mutate:  func(p *AdmissionProof) { p.TokenKeyID = fill(0x11, 31) },
			wantSub: "token key id must be 32 bytes",
		},
		{
			name:    "relay bucket id wrong length",
			mutate:  func(p *AdmissionProof) { p.RelayBucketID = fill(0x12, 15) },
			wantSub: "relay bucket id must be 16 bytes",
		},
		{
			name:    "token scope id wrong length",
			mutate:  func(p *AdmissionProof) { p.TokenScopeID = fill(0x13, 15) },
			wantSub: "token scope id must be 16 bytes",
		},
		{
			name:    "token nonce wrong length",
			mutate:  func(p *AdmissionProof) { p.TokenNonce = fill(0x14, 31) },
			wantSub: "token nonce must be 32 bytes",
		},
		{
			name:    "redemption context hash wrong length",
			mutate:  func(p *AdmissionProof) { p.RedemptionContextHash = fill(0x15, 47) },
			wantSub: "redemption context hash must be 48 bytes",
		},
		{
			name:    "non-zero binding proof for production proof type",
			mutate:  func(p *AdmissionProof) { p.BindingProof = []byte{0x01} },
			wantSub: "requires zero-length binding proof",
		},
		{
			name: "malformed production token metadata",
			mutate: func(p *AdmissionProof) {
				// Two bytes decode the leading RFC9577TokenType but the 32-byte
				// challenge digest read that follows runs short, so the reader
				// surfaces r.Err and ValidateStructuralWithOptions wraps it.
				p.TokenPublicMetadata = []byte{0x00, 0x01}
			},
			wantSub: "invalid production token metadata",
		},
		{
			name: "production token metadata fails ValidateForProof",
			mutate: func(p *AdmissionProof) {
				bad := validTokenMetadataForProof(*p)
				bad.RFC9577TokenKeyID = fill(0xEE, 32) // != proof.TokenKeyID
				enc, err := Encode(bad)
				if err != nil {
					t.Fatalf("encode bad metadata: %v", err)
				}
				p.TokenPublicMetadata = enc
			},
			wantSub: "token key id mismatch",
		},
		{
			name: "unknown critical extension rejected",
			mutate: func(p *AdmissionProof) {
				p.Extensions = []Extension{{ExtensionType: 0x7005, Critical: true, Body: []byte("x")}}
			},
			wantSub: "unknown critical extension",
		},
		{
			name:    "unknown proof type",
			mutate:  func(p *AdmissionProof) { p.ProofType = 0x1234 },
			wantSub: "unknown admission proof type",
		},
		{
			name:    "valid BlindRSA proof accepted",
			wantSub: "",
		},
		{
			name:    "lab proof rejected without lab gate",
			base:    validLabAdmissionProofForCoverage,
			wantSub: "lab admission proof disabled",
		},
		{
			name:    "valid lab proof accepted with lab gate",
			base:    validLabAdmissionProofForCoverage,
			opts:    ProofValidationOptions{AllowLabProofs: true},
			wantSub: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := sampleAdmissionProof
			if tc.base != nil {
				base = tc.base
			}
			proof := base()
			if tc.mutate != nil {
				tc.mutate(&proof)
			}
			err := proof.ValidateStructuralWithOptions(20, tc.opts)
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

func TestAdmissionProofValidateStructuralDispatchesAllowLabGate(t *testing.T) {
	t.Run("lab proofs accepted when allowLab is true", func(t *testing.T) {
		proof := validLabAdmissionProofForCoverage()
		if err := proof.ValidateStructural(20, true); err != nil {
			t.Fatalf("ValidateStructural(Lab, allowLab=true) rejected: %v", err)
		}
	})
	t.Run("lab proofs rejected when allowLab is false", func(t *testing.T) {
		proof := validLabAdmissionProofForCoverage()
		err := proof.ValidateStructural(20, false)
		if err == nil || !strings.Contains(err.Error(), "lab admission proof disabled") {
			t.Fatalf("ValidateStructural(Lab, allowLab=false) err = %v, want lab gate error", err)
		}
	})
}

func TestAuroraTokenMetadataValidateForProofDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(meta *AuroraTokenMetadata, proof *AdmissionProof, hash *[]byte)
		wantSub string
	}{
		{
			name:    "proof type does not fit RFC token type",
			mutate:  func(m *AuroraTokenMetadata, p *AdmissionProof, h *[]byte) { p.ProofType = 0x10000 },
			wantSub: "does not fit RFC token type",
		},
		{
			name: "token type mismatch",
			mutate: func(m *AuroraTokenMetadata, p *AdmissionProof, h *[]byte) {
				p.ProofType = registry.ProofVOPRFP384SHA384
			},
			wantSub: "token metadata proof type mismatch",
		},
		{
			name:    "challenge digest wrong length",
			mutate:  func(m *AuroraTokenMetadata, p *AdmissionProof, h *[]byte) { m.RFC9577ChallengeDigest = fill(0x90, 31) },
			wantSub: "challenge digest must be 32 bytes",
		},
		{
			name:    "token key id mismatch",
			mutate:  func(m *AuroraTokenMetadata, p *AdmissionProof, h *[]byte) { m.RFC9577TokenKeyID = fill(0xEE, 32) },
			wantSub: "token key id mismatch",
		},
		{
			name:    "issuer name empty",
			mutate:  func(m *AuroraTokenMetadata, p *AdmissionProof, h *[]byte) { m.IssuerName = nil },
			wantSub: "issuer name is empty",
		},
		{
			name:    "issuer metadata hash mismatch",
			mutate:  func(m *AuroraTokenMetadata, p *AdmissionProof, h *[]byte) { *h = fill(0x92, 48) },
			wantSub: "issuer metadata hash mismatch",
		},
		{
			name:    "matching metadata accepted",
			wantSub: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, proof, hash := baseForProofValidation()
			if tc.mutate != nil {
				tc.mutate(&meta, &proof, &hash)
			}
			err := meta.ValidateForProof(proof, hash)
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

func TestDecodeAuroraTokenMetadataBytesRejectsMalformedAndTrailing(t *testing.T) {
	t.Run("malformed payload returns decode error", func(t *testing.T) {
		// Two bytes decode the leading token type, then the 32-byte challenge
		// digest read runs short, surfacing r.Err.
		if _, err := DecodeAuroraTokenMetadataBytes([]byte{0x00, 0x01}); err == nil {
			t.Fatal("DecodeAuroraTokenMetadataBytes accepted a malformed payload")
		}
	})
	t.Run("trailing bytes rejected", func(t *testing.T) {
		enc, err := Encode(validTokenMetadataForProof(AdmissionProof{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: fill(0x11, 32),
		}))
		if err != nil {
			t.Fatalf("encode metadata: %v", err)
		}
		enc = append(enc, 0x00)
		_, err = DecodeAuroraTokenMetadataBytes(enc)
		if err == nil || !strings.Contains(err.Error(), "trailing token metadata bytes") {
			t.Fatalf("err = %v, want trailing-bytes error", err)
		}
	})
	t.Run("valid payload round-trips", func(t *testing.T) {
		enc, err := Encode(validTokenMetadataForProof(AdmissionProof{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: fill(0x11, 32),
		}))
		if err != nil {
			t.Fatalf("encode metadata: %v", err)
		}
		got, err := DecodeAuroraTokenMetadataBytes(enc)
		if err != nil {
			t.Fatalf("DecodeAuroraTokenMetadataBytes: %v", err)
		}
		if got.RFC9577TokenType != uint16(registry.ProofBlindRSA2048) || string(got.IssuerName) != "issuer.example" {
			t.Fatalf("decoded metadata = %+v, want BlindRSA / issuer.example", got)
		}
	})
}

func TestReplayProofValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ReplayProof)
		wantSub string
	}{
		{"unsupported proof version", func(p *ReplayProof) { p.ProofVersion = 0 }, "unsupported replay proof version"},
		{"redemption hash wrong length", func(p *ReplayProof) { p.TokenRedemptionHash = fill(0x16, 47) }, "replay token redemption hash must be 48 bytes"},
		{"client replay nonce wrong length", func(p *ReplayProof) { p.ClientReplayNonce = fill(0x17, 31) }, "client replay nonce must be 32 bytes"},
		{"replay context hash wrong length", func(p *ReplayProof) { p.ReplayContextHash = fill(0x18, 47) }, "replay context hash must be 48 bytes"},
		{"replay window id wrong length", func(p *ReplayProof) { p.ReplayWindowID = fill(0x19, 15) }, "replay window id must be 16 bytes"},
		{"unknown critical extension", func(p *ReplayProof) {
			p.Extensions = []Extension{{ExtensionType: 0x7006, Critical: true, Body: []byte("x")}}
		}, "unknown critical extension"},
		{"valid replay proof accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := sampleReplayProof()
			if tc.mutate != nil {
				tc.mutate(&proof)
			}
			err := proof.ValidateStructural()
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

func TestClientTransportHintsValidatePrototypeDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ClientTransportHints)
		wantSub string
	}{
		{"non-zero hint flags", func(h *ClientTransportHints) { h.HintFlags = 1 }, "hint_flags must be zero"},
		{"network cohort hint too long", func(h *ClientTransportHints) { h.NetworkCohortHint = fill(0xAA, 17) }, "network_cohort_hint length 17 exceeds 16"},
		{"unknown critical extension", func(h *ClientTransportHints) {
			h.Extensions = []Extension{{ExtensionType: 0x7007, Critical: true, Body: []byte("x")}}
		}, "unknown critical extension"},
		{"valid hints accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hints := sampleClientTransportHints()
			if tc.mutate != nil {
				tc.mutate(&hints)
			}
			err := hints.ValidatePrototype()
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

// validLabAdmissionProofForCoverage returns a LabStatic AdmissionProof that passes
// ValidateStructuralWithOptions when AllowLabProofs is true: it reuses the valid
// BlindRSA base's field lengths, switches the proof type to LabStaticToken (which
// requires a zero-length binding proof and skips the production-metadata decode),
// and drops the metadata payload. Referenced by the
// ValidateStructuralWithOptions table and the ValidateStructural wrapper tests.
func validLabAdmissionProofForCoverage() AdmissionProof {
	p := sampleAdmissionProof()
	p.ProofType = registry.ProofLabStaticToken
	p.TokenPublicMetadata = nil // Lab proofs do not carry production token metadata.
	p.BindingProof = nil        // Lab proofs require a zero-length binding proof.
	return p
}

// validTokenMetadataForProof returns an AuroraTokenMetadata that passes
// ValidateForProof for the given proof: matching RFC9577 token type, a 32-byte
// challenge digest, a token key id equal to the proof's, a non-empty issuer
// name, and a 48-byte issuer metadata hash. Used by the
// ValidateStructuralWithOptions metadata-mismatch case and the
// DecodeAuroraTokenMetadataBytes round-trip cases.
func validTokenMetadataForProof(proof AdmissionProof) AuroraTokenMetadata {
	return AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: fill(0x90, 32),
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             []byte("issuer.example"),
		OriginInfo:             []byte("origin.example"),
		IssuerMetadataHash:     fill(0x91, 48),
	}
}

// baseForProofValidation returns a mutually-consistent (metadata, proof,
// issuerMetadataHash) triple that passes ValidateForProof, so each
// ValidateForProof rejection case can perturb exactly one of the three inputs.
func baseForProofValidation() (AuroraTokenMetadata, AdmissionProof, []byte) {
	proof := AdmissionProof{ProofType: registry.ProofBlindRSA2048, TokenKeyID: fill(0x11, 32)}
	meta := validTokenMetadataForProof(proof)
	return meta, proof, fill(0x91, 48)
}
