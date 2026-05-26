package protocol

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestAdmissionProofRequiresExplicitPrivateProofGate(t *testing.T) {
	proof := privateAdmissionProofForTest()
	if err := proof.ValidateStructural(20, false); err == nil {
		t.Fatalf("private admission proof accepted without explicit private-proof gate")
	} else if !strings.Contains(err.Error(), "private") {
		t.Fatalf("private admission proof error = %v, want private-proof gate", err)
	}
	if err := proof.ValidateStructuralWithOptions(20, ProofValidationOptions{
		AllowPrivateProofTypes: true,
	}); err != nil {
		t.Fatalf("private admission proof rejected with explicit private-proof gate: %v", err)
	}
	proof.BindingProof = fill(0x99, 4097)
	if err := proof.ValidateStructuralWithOptions(20, ProofValidationOptions{
		AllowPrivateProofTypes: true,
	}); err == nil {
		t.Fatalf("oversized private binding proof accepted")
	}
}

func TestIssuerPrivateProofTypesRequireExplicitGate(t *testing.T) {
	key := privateIssuerTokenKeyForTest()
	if err := key.Validate(20); err == nil {
		t.Fatalf("private issuer token key accepted without explicit private-proof gate")
	} else if !strings.Contains(err.Error(), "private") {
		t.Fatalf("private issuer token key error = %v, want private-proof gate", err)
	}
	if err := key.ValidateWithOptions(20, ProofValidationOptions{
		AllowPrivateProofTypes: true,
	}); err != nil {
		t.Fatalf("private issuer token key rejected with explicit private-proof gate: %v", err)
	}

	metadata := IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            fill(0x20, 16),
		ValidFromUnix:       10,
		ValidUntilUnix:      30,
		IssuerName:          []byte("issuer"),
		SupportedProofTypes: []uint64{registry.ProofOpaqueIssuer},
		TokenKeyMappings:    []IssuerTokenKeyRecord{key},
		AuxiliaryBindingPolicies: []AuxiliaryBindingPolicy{{
			ProofType:            registry.ProofOpaqueIssuer,
			BindingProofRequired: true,
			MaxBindingProofLen:   256,
			BindingPolicyID:      1,
		}},
		MetadataSigningKeyID: fill(0x21, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	if err := metadata.ValidateStructural(20, false); err == nil {
		t.Fatalf("private issuer metadata accepted without explicit private-proof gate")
	} else if !strings.Contains(err.Error(), "private") {
		t.Fatalf("private issuer metadata error = %v, want private-proof gate", err)
	}
	if err := metadata.ValidateStructuralWithOptions(20, ProofValidationOptions{
		AllowPrivateProofTypes: true,
	}); err != nil {
		t.Fatalf("private issuer metadata rejected with explicit private-proof gate: %v", err)
	}
}

func privateAdmissionProofForTest() AdmissionProof {
	return AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofOpaqueIssuer,
		IssuerID:              fill(0x01, 16),
		TokenKeyID:            fill(0x02, 32),
		RelayBucketID:         fill(0x03, 16),
		TokenScopeID:          fill(0x04, 16),
		ExpiryUnix:            100,
		TokenNonce:            fill(0x05, 32),
		RedemptionContextHash: fill(0x06, 48),
		TokenPublicMetadata:   []byte("private-metadata"),
		TokenAuthenticator:    []byte("private-token"),
		BindingProof:          []byte("private-binding"),
	}
}

func privateIssuerTokenKeyForTest() IssuerTokenKeyRecord {
	return IssuerTokenKeyRecord{
		ProofType:  registry.ProofOpaqueIssuer,
		TokenKeyID: fill(0x10, 32),
		TokenVerificationKey: TokenVerificationKeyRecord{
			TokenVerificationKeyScheme: 0x7000,
			TokenVerificationKey:       []byte("private-verifier-key"),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.IssuerStatusActive,
	}
}
