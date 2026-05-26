package protocol

import (
	"crypto/sha256"
	"reflect"
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

func TestIssuerVerifierServiceRejectsBlindRSAEvenIfAllowlisted(t *testing.T) {
	service := verifierServiceFixture()
	service.AllowedProofTypes = []uint64{registry.ProofBlindRSA2048}
	if err := service.Allows(registry.ProofBlindRSA2048, fill(0x04, 16), 20, true); err == nil {
		t.Fatalf("Blind RSA proof was accepted by VOPRF verifier service")
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

func TestIssuerMetadataAndVerifierPayloadsRoundTrip(t *testing.T) {
	tokenKey := fill(0x31, 64)
	tokenKeyID := sha256.Sum256(tokenKey)
	metadata := IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            fill(0x32, 16),
		ValidFromUnix:       100,
		ValidUntilUnix:      200,
		IssuerName:          []byte("issuer"),
		SupportedProofTypes: []uint64{registry.ProofBlindRSA2048, registry.ProofVOPRFP384SHA384},
		TokenKeyMappings: []IssuerTokenKeyRecord{{
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: tokenKeyID[:],
			TokenVerificationKey: TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       tokenKey,
			},
			ValidFromUnix:  100,
			ValidUntilUnix: 200,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []OriginInfoPolicy{{
			PolicyID:             1,
			OriginInfo:           []byte("origin"),
			AllowEmptyOriginInfo: true,
			ValidFromUnix:        100,
			ValidUntilUnix:       200,
		}},
		RelayBucketScopes: []RelayBucketScope{{
			RelayBucketID:         fill(0x33, 16),
			TokenScopeID:          fill(0x34, 16),
			AllowedOriginPolicyID: []uint64{1},
			ValidFromUnix:         100,
			ValidUntilUnix:        200,
		}},
		AuxiliaryBindingPolicies: []AuxiliaryBindingPolicy{{
			ProofType:            registry.ProofBlindRSA2048,
			BindingProofRequired: true,
			MaxBindingProofLen:   128,
			BindingPolicyID:      9,
		}},
		VerifierServices:     []IssuerVerifierServiceRecord{verifierServiceFixture()},
		MetadataSigningKeyID: fill(0x35, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
		MetadataSignature:    []byte("metadata-signature"),
		Extensions:           []Extension{{ExtensionType: 0x7010, Body: []byte("metadata")}},
	}
	encodedMetadata, err := Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeIssuerMetadata(bytesReader(encodedMetadata)); !reflect.DeepEqual(got, metadata) {
		t.Fatalf("IssuerMetadata round trip mismatch:\n got=%+v\nwant=%+v", got, metadata)
	}

	request := IssuerVerifierRequest{
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
	encodedRequest, err := Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeIssuerVerifierRequest(bytesReader(encodedRequest)); !reflect.DeepEqual(got, request) {
		t.Fatalf("IssuerVerifierRequest round trip mismatch:\n got=%+v\nwant=%+v", got, request)
	}

	response := IssuerVerifierResponse{
		ResponseVersion:  registry.Version20,
		ServiceID:        fill(0x41, 16),
		RequestHash:      fill(0x42, 48),
		Decision:         registry.VerifierDecisionAccept,
		DecisionDetail:   registry.VerifierDecisionRejectReplayOrSpent,
		TokenSpentKey:    fill(0x43, 48),
		ValidUntilUnix:   180,
		ResponseNonce:    fill(0x44, 32),
		ServiceSignature: []byte("service-signature"),
	}
	encodedResponse, err := Encode(response)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeIssuerVerifierResponse(bytesReader(encodedResponse)); !reflect.DeepEqual(got, response) {
		t.Fatalf("IssuerVerifierResponse round trip mismatch:\n got=%+v\nwant=%+v", got, response)
	}
}
