package issuerd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestNewProductionBlindRSAServiceIssuesCurrentToken(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x44, 32),
		RedemptionContextHash: fill(0x45, 48),
		ExpiryUnix:            *nowUnix + 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, options.Metadata, *nowUnix); err != nil {
		t.Fatalf("issued production proof did not verify: %v", err)
	}
}

func TestNewProductionBlindRSAServiceRejectsVOPRFMetadata(t *testing.T) {
	options, _ := productionBlindRSAServiceOptionsForTest(t, true)
	service, err := NewProductionBlindRSAService(options)
	if err == nil || service != nil {
		t.Fatalf("NewProductionBlindRSAService accepted VOPRF metadata: service=%v err=%v", service != nil, err)
	}
	if !strings.Contains(err.Error(), "VOPRF") {
		t.Fatalf("VOPRF metadata error = %v", err)
	}
}

func TestProductionBlindRSAServiceUsesLiveClockForIssuance(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	*nowUnix = options.Metadata.ValidUntilUnix
	if _, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x46, 32),
		RedemptionContextHash: fill(0x47, 48),
		ExpiryUnix:            options.Metadata.ValidUntilUnix,
	}); err == nil || !strings.Contains(err.Error(), "validity") {
		t.Fatalf("issuance after metadata expiry error = %v", err)
	}
}

func TestProductionBlindRSAServiceRejectsExpiredIssuanceScope(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	service.issuanceScope.ValidUntilUnix = *nowUnix + 1
	*nowUnix++
	if _, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x48, 32),
		RedemptionContextHash: fill(0x49, 48),
		ExpiryUnix:            *nowUnix + 100,
	}); err == nil || !strings.Contains(err.Error(), "issuance scope") {
		t.Fatalf("issuance after scope expiry error = %v", err)
	}
}

func TestNewProductionBlindRSAServiceRejectsMismatchedPrivateKey(t *testing.T) {
	options, _ := productionBlindRSAServiceOptionsForTest(t, false)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	options.BlindRSAKey = privateKey
	service, err := NewProductionBlindRSAService(options)
	if err == nil || service != nil {
		t.Fatalf("NewProductionBlindRSAService accepted mismatched private key: service=%v err=%v", service != nil, err)
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Fatalf("mismatched private-key error = %v", err)
	}
}

func TestNewProductionBlindRSAServiceRejectsNonCanonicalAuthorityKeyID(t *testing.T) {
	options, _ := productionBlindRSAServiceOptionsForTest(t, false)
	options.AuthorityKeys[0].AuthorityKeyID[0] ^= 0xff
	service, err := NewProductionBlindRSAService(options)
	if err == nil || service != nil {
		t.Fatalf("NewProductionBlindRSAService accepted a non-canonical authority key id: service=%v err=%v", service != nil, err)
	}
	if !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("non-canonical authority-key error = %v", err)
	}
}

func TestProductionBlindRSAServiceDoesNotExposeHarnessIssuanceEndpoints(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(service)
	metadata := serveHTTP(t, handler, http.MethodGet, "/issuer-metadata", nil)
	if metadata.Code != http.StatusOK {
		t.Fatalf("production metadata response = %d %s", metadata.Code, metadata.Body.String())
	}
	issue := serveHTTP(t, handler, http.MethodPost, "/blind-rsa/issue", mustJSON(t, IssueRequest{
		TokenNonce:            strings.Repeat("44", 32),
		RedemptionContextHash: strings.Repeat("45", 48),
		ExpiryUnix:            *nowUnix + 100,
	}))
	if issue.Code != http.StatusNotFound {
		t.Fatalf("production issuer exposed harness issuance endpoint: %d", issue.Code)
	}
}

func TestProductionBlindRSAServiceMetadataPublicationIsDefensive(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	published := service.PublishIssuerMetadata()
	published.TokenKeyMappings[0].TokenVerificationKey.TokenVerificationKey[0] ^= 0xff
	published.RelayBucketScopes[0].RelayBucketID[0] ^= 0xff
	if _, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x4a, 32),
		RedemptionContextHash: fill(0x4b, 48),
		ExpiryUnix:            *nowUnix + 100,
	}); err != nil {
		t.Fatalf("issuer state was modified through published metadata: %v", err)
	}
}

func TestProductionBlindRSAServiceCopiesCallerOwnedConfiguration(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	options.Metadata.TokenKeyMappings[0].TokenVerificationKey.TokenVerificationKey[0] ^= 0xff
	options.AuthorityKeys[0].PublicKey.PublicKey[0] ^= 0xff
	options.BlindRSAKey.N.SetInt64(1)

	if _, err := service.IssueBlindRSA2048(IssueBlindRSA2048Request{
		TokenNonce:            fill(0x4c, 32),
		RedemptionContextHash: fill(0x4d, 48),
		ExpiryUnix:            *nowUnix + 100,
	}); err != nil {
		t.Fatalf("issuer state was modified through caller-owned configuration: %v", err)
	}
	if err := auroratrust.VerifyIssuerMetadataSignature(service.PublishIssuerMetadata(), service.AuthorityKeys(), *nowUnix); err != nil {
		t.Fatalf("issuer authority keys were modified through caller-owned configuration: %v", err)
	}
}

func TestProductionBlindRSAServiceAuthorityPublicationIsDefensive(t *testing.T) {
	options, nowUnix := productionBlindRSAServiceOptionsForTest(t, false)
	service, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	published := service.AuthorityKeys()
	published[0].PublicKey.PublicKey[0] ^= 0xff
	if err := auroratrust.VerifyIssuerMetadataSignature(service.PublishIssuerMetadata(), service.AuthorityKeys(), *nowUnix); err != nil {
		t.Fatalf("issuer authority keys were modified through published data: %v", err)
	}
}

func TestProductionBlindRSAServiceDisallowsUntrustedCarrierIssuance(t *testing.T) {
	options, _ := productionBlindRSAServiceOptionsForTest(t, false)
	production, err := NewProductionBlindRSAService(options)
	if err != nil {
		t.Fatal(err)
	}
	if production.AllowsUntrustedCarrierIssuance() {
		t.Fatal("production issuer allows untrusted carrier issuance")
	}
	harness, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	if !harness.AllowsUntrustedCarrierIssuance() {
		t.Fatal("harness issuer does not allow its carrier issuance checks")
	}
}

func productionBlindRSAServiceOptionsForTest(t *testing.T, includeVOPRF bool) (ProductionBlindRSAServiceOptions, *uint64) {
	t.Helper()
	harness, err := NewHarnessService(200)
	if err != nil {
		t.Fatal(err)
	}
	metadata := harness.PublishIssuerMetadata()
	if !includeVOPRF {
		metadata.SupportedProofTypes = []uint64{registry.ProofBlindRSA2048}
		metadata.TokenKeyMappings = []protocol.IssuerTokenKeyRecord{metadata.TokenKeyMappings[0]}
		metadata.VerifierServices = nil
	}
	authoritySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityPublicKey, err := authoritySigner.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	metadata.SignatureScheme = registry.SigECDSAP256SHA384DER
	metadata.KeyEncoding = registry.KeyP256SEC1Uncompressed
	authorityPublicRecord := protocol.PublicKeyRecord{
		SignatureScheme: metadata.SignatureScheme,
		KeyEncoding:     metadata.KeyEncoding,
		PublicKey:       authorityPublicKey,
	}
	encodedAuthorityPublicRecord, err := protocol.Encode(authorityPublicRecord)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSigningKeyID = auroratrust.AuthorityKeyID(encodedAuthorityPublicRecord)
	input, err := auroratrust.IssuerMetadataSignatureInput(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, authoritySigner, input)
	if err != nil {
		t.Fatal(err)
	}
	current := uint64(200)
	return ProductionBlindRSAServiceOptions{
		Metadata: metadata,
		AuthorityKeys: []protocol.AuthorityKeyRecord{{
			AuthorityID:    fill(0xa5, 16),
			AuthorityKeyID: append([]byte(nil), metadata.MetadataSigningKeyID...),
			PublicKey:      authorityPublicRecord,
			ValidFromUnix:  100,
			ValidUntilUnix: metadata.ValidUntilUnix,
			KeyStatus:      registry.AuthorityActive,
			UsageFlags:     registry.UsageMaySignIssuerMetadata,
		}},
		BlindRSAKey:        harness.blindRSAKey,
		SpentTokenCache:    admission.NewMemoryReplayCache(),
		RelayBucketID:      append([]byte(nil), metadata.RelayBucketScopes[0].RelayBucketID...),
		OriginInfoPolicyID: metadata.OriginInfoPolicies[0].PolicyID,
		NowUnix:            func() uint64 { return current },
	}, &current
}
