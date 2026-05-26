package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestVerifyIssuerMetadataSignatureAcceptsAuthorizedAuthority(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := protocol.IssuerMetadata{
		MetadataVersion:      registry.Version20,
		IssuerID:             rb(0x20, 16),
		ValidFromUnix:        100,
		ValidUntilUnix:       300,
		IssuerName:           []byte("issuer.example"),
		SupportedProofTypes:  []uint64{registry.ProofBlindRSA2048},
		MetadataSigningKeyID: rb(0x21, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	input, err := IssuerMetadataSignatureInput(m)
	if err != nil {
		t.Fatal(err)
	}
	m.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, priv, input)
	if err != nil {
		t.Fatal(err)
	}
	keys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    rb(0x22, 16),
		AuthorityKeyID: m.MetadataSigningKeyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: m.SignatureScheme,
			KeyEncoding:     m.KeyEncoding,
			PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
		},
		ValidFromUnix:  90,
		ValidUntilUnix: 400,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}}
	if err := VerifyIssuerMetadataSignature(m, keys, 200); err != nil {
		t.Fatalf("valid issuer metadata signature rejected: %v", err)
	}
	m.IssuerName = []byte("tampered.example")
	if err := VerifyIssuerMetadataSignature(m, keys, 200); err == nil {
		t.Fatalf("tampered issuer metadata accepted")
	}
	m.IssuerName = []byte("issuer.example")
	keys[0].UsageFlags = registry.UsageMaySignDirectoryConsensus
	if err := VerifyIssuerMetadataSignature(m, keys, 200); err == nil {
		t.Fatalf("issuer metadata signing key without issuer usage accepted")
	}
}

func TestVerifyIssuerMetadataSignatureRejectsAmbiguousSigningKey(t *testing.T) {
	m := protocol.IssuerMetadata{
		MetadataVersion:      registry.Version20,
		IssuerID:             rb(0x20, 16),
		ValidFromUnix:        100,
		ValidUntilUnix:       300,
		IssuerName:           []byte("issuer.example"),
		MetadataSigningKeyID: rb(0x21, 16),
		SignatureScheme:      registry.SigEd25519Lab,
		KeyEncoding:          registry.KeyEd25519RawPublic,
		MetadataSignature:    []byte("not reached because lookup is ambiguous"),
	}
	base := protocol.AuthorityKeyRecord{
		AuthorityID:    rb(0x22, 16),
		AuthorityKeyID: m.MetadataSigningKeyID,
		PublicKey: protocol.PublicKeyRecord{
			SignatureScheme: m.SignatureScheme,
			KeyEncoding:     m.KeyEncoding,
			PublicKey:       rb(0x33, 32),
		},
		ValidFromUnix:  90,
		ValidUntilUnix: 400,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}
	other := base
	other.AuthorityID = rb(0x23, 16)
	if err := VerifyIssuerMetadataSignature(m, []protocol.AuthorityKeyRecord{base, other}, 200); err == nil {
		t.Fatalf("ambiguous metadata signing key accepted")
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

func TestVerifyIssuerVerifierResponseVerifiesServiceSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, req, resp := issuerVerifierRequestFixture(t)
	service.ServiceAuthKey = protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y),
	}
	input, err := IssuerVerifierResponseSignatureInput(resp.RequestHash, resp)
	if err != nil {
		t.Fatal(err)
	}
	resp.ServiceSignature, err = ecdsa.SignASN1(rand.Reader, priv, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIssuerVerifierResponse(req, service, resp, 220, 300); err != nil {
		t.Fatalf("valid issuer verifier response rejected: %v", err)
	}
	resp.ResponseNonce = rb(0xee, 32)
	if err := VerifyIssuerVerifierResponse(req, service, resp, 220, 300); err == nil {
		t.Fatalf("tampered issuer verifier response accepted")
	}
}

func TestValidateIssuerServiceAuthKeySeparationRejectsAuthorityKeyReuse(t *testing.T) {
	publicKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigEd25519Lab,
		KeyEncoding:     registry.KeyEd25519RawPublic,
		PublicKey:       rb(0x33, 32),
	}
	m := protocol.IssuerMetadata{
		MetadataVersion: registry.Version20,
		IssuerID:        rb(0x20, 16),
		ValidFromUnix:   100,
		ValidUntilUnix:  300,
		VerifierServices: []protocol.IssuerVerifierServiceRecord{{
			ServiceID:      rb(0x10, 16),
			ServiceAuthKey: publicKey,
			ValidFromUnix:  100,
			ValidUntilUnix: 300,
			ServiceStatus:  registry.IssuerStatusActive,
		}},
	}
	keys := []protocol.AuthorityKeyRecord{{
		AuthorityID:    rb(0x22, 16),
		AuthorityKeyID: rb(0x21, 16),
		PublicKey:      publicKey,
		ValidFromUnix:  90,
		ValidUntilUnix: 400,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignIssuerMetadata,
	}}
	if err := ValidateIssuerServiceAuthKeySeparation(m, keys, 200); err == nil {
		t.Fatalf("issuer service auth key reused an authority key")
	}
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

func TestValidateIssuerVerifierResponseFreshnessRejectsUnusableService(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.IssuerVerifierServiceRecord, *protocol.IssuerVerifierResponse)
	}{
		{
			name: "not yet valid",
			mutate: func(service *protocol.IssuerVerifierServiceRecord, resp *protocol.IssuerVerifierResponse) {
				service.ValidFromUnix = 221
				resp.ValidUntilUnix = 250
			},
		},
		{
			name: "expired at current time",
			mutate: func(service *protocol.IssuerVerifierServiceRecord, resp *protocol.IssuerVerifierResponse) {
				service.ValidUntilUnix = 220
				resp.ValidUntilUnix = 220
			},
		},
		{
			name: "revoked",
			mutate: func(service *protocol.IssuerVerifierServiceRecord, resp *protocol.IssuerVerifierResponse) {
				service.ServiceStatus = registry.IssuerStatusRevoked
				resp.ValidUntilUnix = 250
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service, req, resp := issuerVerifierRequestFixture(t)
			tc.mutate(&service, &resp)
			if err := ValidateIssuerVerifierResponseFreshness(req, service, resp, 220, 300); err == nil {
				t.Fatalf("unusable verifier service accepted")
			}
		})
	}
}
