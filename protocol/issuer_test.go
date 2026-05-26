package protocol

import (
	"crypto/sha256"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func verifierServiceFixture() IssuerVerifierServiceRecord {
	return IssuerVerifierServiceRecord{
		ServiceID:         fill(0x01, 16),
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
			SignatureScheme: registry.SigEd25519Lab,
			KeyEncoding:     registry.KeyEd25519RawPublic,
			PublicKey:       fill(0x03, 32),
		},
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{fill(0x04, 16)},
		RequestAuthPolicyID:   7,
		ValidFromUnix:         10,
		ValidUntilUnix:        30,
		ServiceStatus:         registry.IssuerStatusActive,
	}
}

func TestIssuerVerifierServiceRequiresExplicitAllowlists(t *testing.T) {
	service := verifierServiceFixture()
	service.AllowedProofTypes = nil
	if err := service.Allows(registry.ProofVOPRFP384SHA384, fill(0x04, 16), 20, true); err == nil {
		t.Fatalf("empty proof allowlist accepted")
	}
	service = verifierServiceFixture()
	service.AllowedRelayBucketIDs = nil
	if err := service.Allows(registry.ProofVOPRFP384SHA384, fill(0x04, 16), 20, true); err == nil {
		t.Fatalf("empty relay-bucket allowlist accepted")
	}
}

func TestIssuerVerifierServiceGatesProofBucketAndRequestAuthPolicy(t *testing.T) {
	service := verifierServiceFixture()
	if err := service.Allows(registry.ProofVOPRFP384SHA384, fill(0x04, 16), 20, true); err != nil {
		t.Fatalf("valid verifier service rejected: %v", err)
	}
	if err := service.Allows(registry.ProofBlindRSA2048, fill(0x04, 16), 20, true); err == nil {
		t.Fatalf("wrong proof type accepted")
	}
	if err := service.Allows(registry.ProofVOPRFP384SHA384, fill(0x05, 16), 20, true); err == nil {
		t.Fatalf("wrong relay bucket accepted")
	}
	if err := service.Allows(registry.ProofVOPRFP384SHA384, fill(0x04, 16), 20, false); err == nil {
		t.Fatalf("unsupported request auth policy accepted")
	}
}

func TestIssuerTokenKeyRecordMatchesProofTypeToKeyScheme(t *testing.T) {
	tokenKey := fill(0x07, 64)
	tokenKeyID := sha256.Sum256(tokenKey)
	key := IssuerTokenKeyRecord{
		ProofType:  registry.ProofVOPRFP384SHA384,
		TokenKeyID: tokenKeyID[:],
		TokenVerificationKey: TokenVerificationKeyRecord{
			TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
			TokenVerificationKey:       tokenKey,
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.IssuerStatusActive,
	}
	if err := key.Validate(20); err == nil {
		t.Fatalf("mismatched proof/key scheme accepted")
	}
	key.TokenVerificationKey.TokenVerificationKeyScheme = registry.TokenKeyVOPRFP384SHA384
	if err := key.Validate(20); err != nil {
		t.Fatalf("valid proof/key scheme rejected: %v", err)
	}
	key.TokenKeyID = fill(0xee, 32)
	if err := key.Validate(20); err == nil {
		t.Fatalf("token key id mismatch accepted")
	}
}

func TestLabStaticTokenKeyRecordRequiresEmptyKeyMaterial(t *testing.T) {
	key := IssuerTokenKeyRecord{
		ProofType:  registry.ProofLabStaticToken,
		TokenKeyID: fill(0, 32),
		TokenVerificationKey: TokenVerificationKeyRecord{
			TokenVerificationKeyScheme: registry.TokenKeyLabStaticNoKey,
			TokenVerificationKey:       []byte("not-empty"),
		},
		ValidFromUnix:  10,
		ValidUntilUnix: 30,
		KeyStatus:      registry.IssuerStatusActive,
	}
	if err := key.Validate(20); err == nil {
		t.Fatalf("lab static token key material accepted")
	}
}
