package ops

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	auroratrust "github.com/aurora-protocol/aurora-core/trust"
)

func TestVerifyIssuerOperationsProfileAcceptsProductionControls(t *testing.T) {
	profile, _ := issuerOperationsProfileFixture(t)
	report, err := VerifyIssuerOperationsProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("issuer operations profile failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"metadata":             report.MetadataVerified,
		"hint_provisioning":    report.HintProvisioning,
		"atomic_replay_store":  report.AtomicReplayStore,
		"verifier_fail_closed": report.VerifierFailClosed,
		"redacted_logs":        report.SensitiveLogsRedacted,
		"public_relay_policy":  report.PublicRelayProofPolicy,
	} {
		if !passed {
			t.Fatalf("%s control was not covered: %+v", name, report)
		}
	}

	selector := rb(0x55, 16)
	credential, err := BuildAccessHintCredential(profile.HintEpochs[0], selector, 300, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantSecret, err := admission.DeriveHintSecret(profile.HintEpochs[0].VerifierSecret, profile.Metadata.IssuerID, profile.Metadata.RelayBucketScopes[0].RelayBucketID, profile.HintEpochs[0].HintEpochID, selector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(credential.HintSecret, wantSecret) {
		t.Fatalf("credential did not derive the bucket-scoped hint secret")
	}
	if credential.MaxUses != 1 || credential.ExpiryUnix != 300 {
		t.Fatalf("credential usage controls = max_uses %d expiry %d", credential.MaxUses, credential.ExpiryUnix)
	}
}

func TestVerifyIssuerOperationsProfileRejectsUnsafeHintProvisioning(t *testing.T) {
	profile, _ := issuerOperationsProfileFixture(t)
	profile.HintEpochs[0].OperatorChannelAuthenticated = false
	profile.HintEpochs[0].UserSpecificHintTable = true

	report, err := VerifyIssuerOperationsProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("unsafe hint provisioning passed: %+v", report)
	}
	for _, want := range []string{
		"hint epoch operator channel lacks mutual authentication",
		"hint epoch uses user-specific hint table",
	} {
		if !reportHasFinding(report, want) {
			t.Fatalf("issuer operations report missing %q: %+v", want, report)
		}
	}
}

func TestVerifyIssuerOperationsProfileRequiresBlindRSAForUncoordinatedPublicRelay(t *testing.T) {
	profile, authoritySigner := issuerOperationsProfileFixture(t)
	profile.Metadata.SupportedProofTypes = []uint64{registry.ProofVOPRFP384SHA384}
	profile.Metadata.TokenKeyMappings = profile.Metadata.TokenKeyMappings[:1]
	signIssuerMetadata(t, &profile.Metadata, authoritySigner)

	report, err := VerifyIssuerOperationsProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("uncoordinated public relay without Blind RSA passed: %+v", report)
	}
	if !reportHasFinding(report, "public relay without issuer coordination must advertise Blind RSA") {
		t.Fatalf("issuer operations report missing public relay proof policy finding: %+v", report)
	}
}

func TestBuildAccessHintCredentialRejectsInvalidEpochUse(t *testing.T) {
	profile, _ := issuerOperationsProfileFixture(t)
	provision := profile.HintEpochs[0]
	if _, err := BuildAccessHintCredential(provision, rb(0x55, 16), provision.ValidUntilUnix+1, 100); err == nil {
		t.Fatalf("credential expiry past hint epoch was accepted")
	}
	provision.Revoked = true
	if _, err := BuildAccessHintCredential(provision, rb(0x55, 16), 300, 100); err == nil {
		t.Fatalf("revoked hint epoch produced a credential")
	}
}

func issuerOperationsProfileFixture(t *testing.T) (IssuerOperationsProfile, *ecdsa.PrivateKey) {
	t.Helper()
	authoritySigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serviceSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	voprfKey := []byte("oprf-serialize-element-for-test")
	voprfKeyID := sha256.Sum256(voprfKey)
	blindRSAKey := []byte("blind-rsa-spki-for-test")
	blindRSAKeyID := sha256.Sum256(blindRSAKey)
	metadata := protocol.IssuerMetadata{
		MetadataVersion:     registry.Version20,
		IssuerID:            rb(0x80, 16),
		ValidFromUnix:       100,
		ValidUntilUnix:      1000,
		IssuerName:          []byte("issuer.example"),
		SupportedProofTypes: []uint64{registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048},
		TokenKeyMappings: []protocol.IssuerTokenKeyRecord{{
			ProofType:  registry.ProofVOPRFP384SHA384,
			TokenKeyID: voprfKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyVOPRFP384SHA384,
				TokenVerificationKey:       voprfKey,
			},
			ValidFromUnix:  100,
			ValidUntilUnix: 1000,
			KeyStatus:      registry.IssuerStatusActive,
		}, {
			ProofType:  registry.ProofBlindRSA2048,
			TokenKeyID: blindRSAKeyID[:],
			TokenVerificationKey: protocol.TokenVerificationKeyRecord{
				TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
				TokenVerificationKey:       blindRSAKey,
			},
			ValidFromUnix:  100,
			ValidUntilUnix: 1000,
			KeyStatus:      registry.IssuerStatusActive,
		}},
		OriginInfoPolicies: []protocol.OriginInfoPolicy{{
			PolicyID:             7,
			OriginInfo:           []byte("origin.example"),
			AllowEmptyOriginInfo: false,
			ValidFromUnix:        100,
			ValidUntilUnix:       1000,
		}},
		RelayBucketScopes: []protocol.RelayBucketScope{{
			RelayBucketID:         rb(0x81, 16),
			TokenScopeID:          rb(0x82, 16),
			AllowedOriginPolicyID: []uint64{7},
			ValidFromUnix:         100,
			ValidUntilUnix:        1000,
		}},
		VerifierServices: []protocol.IssuerVerifierServiceRecord{{
			ServiceID:         rb(0x83, 16),
			ServiceKind:       registry.VerifierServiceKindVOPRF,
			ServiceProtocolID: registry.IssuerVerifierVOPRFMTLS13,
			ServiceAuthKey: protocol.PublicKeyRecord{
				SignatureScheme: registry.SigECDSAP256SHA384DER,
				KeyEncoding:     registry.KeyP256SEC1Uncompressed,
				PublicKey:       elliptic.Marshal(elliptic.P256(), serviceSigner.PublicKey.X, serviceSigner.PublicKey.Y),
			},
			AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
			AllowedRelayBucketIDs: [][]byte{rb(0x81, 16)},
			RequestAuthPolicyID:   9,
			ValidFromUnix:         100,
			ValidUntilUnix:        1000,
			ServiceStatus:         registry.IssuerStatusActive,
		}},
		MetadataSigningKeyID: rb(0x84, 16),
		SignatureScheme:      registry.SigECDSAP256SHA384DER,
		KeyEncoding:          registry.KeyP256SEC1Uncompressed,
	}
	signIssuerMetadata(t, &metadata, authoritySigner)
	return IssuerOperationsProfile{
		Metadata: metadata,
		AuthorityKeys: []protocol.AuthorityKeyRecord{{
			AuthorityID:    rb(0x85, 16),
			AuthorityKeyID: metadata.MetadataSigningKeyID,
			PublicKey: protocol.PublicKeyRecord{
				SignatureScheme: metadata.SignatureScheme,
				KeyEncoding:     metadata.KeyEncoding,
				PublicKey:       elliptic.Marshal(elliptic.P256(), authoritySigner.PublicKey.X, authoritySigner.PublicKey.Y),
			},
			ValidFromUnix:  90,
			ValidUntilUnix: 1100,
			KeyStatus:      registry.AuthorityActive,
			UsageFlags:     registry.UsageMaySignIssuerMetadata,
		}},
		HintEpochs: []HintEpochProvision{{
			IssuerID:                     append([]byte(nil), metadata.IssuerID...),
			RelayBucketID:                rb(0x81, 16),
			HintEpochID:                  11,
			VerifierSecret:               rb(0x86, 32),
			ValidFromUnix:                100,
			ValidUntilUnix:               500,
			OperatorChannelAuthenticated: true,
			OperatorChannelEncrypted:     true,
			RotationAuditID:              "rotation-11",
		}},
		NowUnix:                                 200,
		PublicRelay:                             true,
		IssuerCoordinatedVOPRF:                  false,
		ReplayStoreAtomicInsertIfAbsent:         true,
		VerifierOutageFailsClosed:               true,
		OperationalLogsRedactSensitiveMaterial:  true,
		MaxHintEpochSeconds:                     86400,
		VerifierServiceRTTMillis:                50,
		MaxVerifierServiceRTTMillis:             200,
		ImplementedVerifierRequestAuthPolicyIDs: map[uint64]bool{9: true},
	}, authoritySigner
}

func signIssuerMetadata(t *testing.T, metadata *protocol.IssuerMetadata, signer *ecdsa.PrivateKey) {
	t.Helper()
	metadata.MetadataSignature = nil
	input, err := auroratrust.IssuerMetadataSignatureInput(*metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSignature, err = ecdsa.SignASN1(rand.Reader, signer, input)
	if err != nil {
		t.Fatal(err)
	}
}

func reportHasFinding(report IssuerOperationsReport, want string) bool {
	for _, finding := range report.Findings {
		if finding == want {
			return true
		}
	}
	return false
}
