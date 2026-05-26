package trust

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func issuerVerifierRequestFixture(t *testing.T) (protocol.IssuerVerifierServiceRecord, protocol.IssuerVerifierRequest, protocol.IssuerVerifierResponse) {
	t.Helper()
	service := protocol.IssuerVerifierServiceRecord{
		ServiceID:             rb(0x10, 16),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{rb(0x11, 16)},
		RequestAuthPolicyID:   1,
		ValidFromUnix:         100,
		ValidUntilUnix:        1000,
		ServiceStatus:         registry.IssuerStatusActive,
	}
	req := protocol.IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 service.ServiceID,
		IssuerID:                  rb(0x12, 16),
		IssuerMetadataHash:        rb(0x13, 48),
		RelayDescriptorHash:       rb(0x14, 48),
		RelayBucketID:             rb(0x11, 16),
		RouteInstanceID:           7,
		HopIndex:                  0,
		ProofType:                 registry.ProofVOPRFP384SHA384,
		TokenKeyID:                rb(0x15, 32),
		TokenNonce:                rb(0x16, 32),
		ChallengeDigest:           rb(0x17, 32),
		AuthenticatorInputHash:    rb(0x18, 48),
		TokenAuthenticator:        rb(0x19, 64),
		TokenSpentKey:             rb(0x1a, 48),
		ReplayEpochID:             9,
		ReplayEpochValidUntilUnix: 900,
		RequestNonce:              rb(0x1b, 32),
		RequestTimeUnix:           200,
	}
	requestHash, err := IssuerVerifierRequestHash(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := protocol.IssuerVerifierResponse{
		ResponseVersion:  registry.Version20,
		ServiceID:        service.ServiceID,
		RequestHash:      requestHash,
		Decision:         registry.VerifierDecisionAccept,
		TokenSpentKey:    req.TokenSpentKey,
		ValidUntilUnix:   250,
		ResponseNonce:    rb(0x1c, 32),
		ServiceSignature: []byte("signature"),
	}
	return service, req, resp
}

func TestIssuerMetadataHashIgnoresSignatureBytes(t *testing.T) {
	m := protocol.IssuerMetadata{
		MetadataVersion:      registry.Version20,
		IssuerID:             rb(0x20, 16),
		ValidFromUnix:        100,
		ValidUntilUnix:       200,
		IssuerName:           []byte("issuer.example"),
		SupportedProofTypes:  []uint64{registry.ProofBlindRSA2048},
		MetadataSigningKeyID: rb(0x21, 16),
		SignatureScheme:      registry.SigEd25519Lab,
		KeyEncoding:          registry.KeyEd25519RawPublic,
		MetadataSignature:    []byte("first"),
	}
	h1, err := IssuerMetadataHash(m)
	if err != nil {
		t.Fatal(err)
	}
	m.MetadataSignature = []byte("second")
	h2, err := IssuerMetadataHash(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("issuer metadata hash included signature bytes")
	}
}

func TestIssuerVerifierResponseSignatureInputIgnoresSignatureBytes(t *testing.T) {
	_, req, resp := issuerVerifierRequestFixture(t)
	in1, err := IssuerVerifierResponseSignatureInput(resp.RequestHash, resp)
	if err != nil {
		t.Fatal(err)
	}
	resp.ServiceSignature = []byte("other")
	in2, err := IssuerVerifierResponseSignatureInput(resp.RequestHash, resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in1, in2) {
		t.Fatalf("response signature input included signature bytes")
	}
	resp.TokenSpentKey = rb(0xee, 48)
	in3, err := IssuerVerifierResponseSignatureInput(resp.RequestHash, resp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(in1, in3) {
		t.Fatalf("response signature input ignored signed response body")
	}
	_ = req
}

func TestValidateIssuerVerifierResponseFreshness(t *testing.T) {
	service, req, resp := issuerVerifierRequestFixture(t)
	if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, 220, 300); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	resp.ValidUntilUnix = req.RequestTimeUnix + 301
	if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, 220, 300); err == nil {
		t.Fatalf("overlong verifier freshness window accepted")
	}
	resp = func() protocol.IssuerVerifierResponse {
		_, _, r := issuerVerifierRequestFixture(t)
		return r
	}()
	resp.TokenSpentKey = rb(0xee, 48)
	if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, 220, 300); err == nil {
		t.Fatalf("mismatched token spent key accepted")
	}
}
