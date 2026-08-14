package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestParseNativeProvisioningRejectsMalformedAndTrailingBytes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RelayURL != input.RelayURL || parsed.IssuerURL != input.IssuerURL || parsed.IssuerCarrierPath != input.IssuerCarrierPath ||
		parsed.RequestClassID != input.RequestClassID || parsed.Suite != input.Suite || parsed.RelayExpectedStatus != input.RelayExpectedStatus ||
		!bytes.Equal(parsed.IssuerMetadata, input.IssuerMetadata) || !bytes.Equal(parsed.SignedSeed, input.SignedSeed) ||
		!bytes.Equal(parsed.Descriptor, input.Descriptor) || !bytes.Equal(parsed.Template, input.Template) ||
		!bytes.Equal(parsed.AccessHint, input.AccessHint) || !bytes.Equal(parsed.PolicyOffer, input.PolicyOffer) ||
		!bytes.Equal(parsed.TransportHints, input.TransportHints) || !bytes.Equal(parsed.RelayRequestHeaders, input.RelayRequestHeaders) ||
		!bytes.Equal(parsed.RelayResponseHeaders, input.RelayResponseHeaders) || !bytes.Equal(parsed.RelayTrustRoots, input.RelayTrustRoots) {
		t.Fatalf("parsed provisioning did not preserve canonical fields: %+v", parsed)
	}
	input.Descriptor[0] ^= 0xff
	if bytes.Equal(parsed.Descriptor, input.Descriptor) {
		t.Fatal("parsed provisioning aliases caller input")
	}

	for _, malformed := range [][]byte{
		nil,
		encoded[:len(encoded)-1],
		append(append([]byte(nil), encoded...), 0),
		make([]byte, maximumNativeProvisioningBytes+1),
	} {
		if _, err := ParseNativeProvisioningWithTrust(malformed, input.signedSeedTrust, now); err == nil {
			t.Fatalf("malformed native provisioning accepted: %d bytes", len(malformed))
		}
	}
}

func TestParseNativeProvisioningRequiresIndependentTrust(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioning(encoded, now); err == nil {
		t.Fatal("native provisioning was accepted without an independently configured trust root")
	}
}

func TestParseNativeProvisioningWithTrustRejectsSubstitutedSignedSeedRoot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	seed, err := decodeNativeSignedSeed(input.SignedSeed)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := decodeNativeIssuerMetadata(input.IssuerMetadata)
	if err != nil {
		t.Fatal(err)
	}
	replacementSeed, replacementTrust := nativeProvisioningSignedSeedAndTrust(
		t,
		now,
		metadata,
		seed.BootstrapAuthorityKeys,
		seed.TokenIssuerHint,
		nil,
	)
	input.SignedSeed = replacementSeed
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeProvisioningBytes(encoded)
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted a signed seed authorized only by substituted roots")
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, replacementTrust, now); err != nil {
		t.Fatalf("native provisioning rejected the independently supplied matching trust: %v", err)
	}
}

func TestNativeProvisioningRejectsInvalidAccessHint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	input.AccessHint = append([]byte(nil), input.AccessHint...)
	input.AccessHint[len(input.AccessHint)-1] = 0
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted invalid access hint")
	}
}

func TestNativeProvisioningVerifiesDeploymentBeforeUse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := parsed.VerifiedDeployment(now)
	if err != nil {
		t.Fatal(err)
	}
	if !deployment.Valid() || deployment.Suite() != input.Suite || deployment.RequestClass().ClassID != input.RequestClassID {
		t.Fatalf("unexpected verified deployment: %+v", deployment)
	}
	config, err := parsed.ClientDriverConfig(now, nativeProvisioningProofProvider{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Suite != input.Suite || !config.RequirePQ || config.SessionLimits.MaxQueuedBytes == 0 {
		t.Fatalf("unexpected client driver configuration: %+v", config)
	}
	if _, err := handshake.NewClientDriver(config); err != nil {
		t.Fatalf("native provisioning produced an unusable client driver configuration: %v", err)
	}

	input.TrustedDescriptorHash[0] ^= 0xff
	encoded, err = EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted a descriptor hash mismatch")
	}
}

func TestNativeProvisioningRequiresSignedIssuerMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	input.IssuerMetadata = nil
	input.SignedSeed = nil
	if _, err := EncodeNativeProvisioning(input); err == nil {
		t.Fatal("native provisioning accepted an issuer without signed metadata")
	}
}

func TestNativeProvisioningRejectsUnboundSignedSeed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	seed, err := decodeNativeSignedSeed(input.SignedSeed)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := decodeNativeIssuerMetadata(input.IssuerMetadata)
	if err != nil {
		t.Fatal(err)
	}
	wrongMetadataHash := append([]byte(nil), seed.IssuerMetadataHash...)
	wrongMetadataHash[0] ^= 0xff
	input.SignedSeed, input.signedSeedTrust = nativeProvisioningSignedSeedAndTrust(t, now, metadata, seed.BootstrapAuthorityKeys, seed.TokenIssuerHint, wrongMetadataHash)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted a seed not bound to issuer metadata")
	}
}

func TestNativeProvisioningRejectsSignedSeedIssuerMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	seed, err := decodeNativeSignedSeed(input.SignedSeed)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := decodeNativeIssuerMetadata(input.IssuerMetadata)
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuerID := append([]byte(nil), seed.TokenIssuerHint...)
	wrongIssuerID[0] ^= 0xff
	input.SignedSeed, input.signedSeedTrust = nativeProvisioningSignedSeedAndTrust(t, now, metadata, seed.BootstrapAuthorityKeys, wrongIssuerID, nil)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted a seed with a different issuer hint")
	}
}

func TestNativeProvisioningRejectsTamperedSignedSeedRoot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	tamperedTrust := input.signedSeedTrust
	tamperedTrust.roots = cloneNativeProvisioningAuthorityKeys(tamperedTrust.roots)
	tamperedTrust.roots[0].PublicKey.PublicKey[0] ^= 0xff
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, tamperedTrust, now); err == nil {
		t.Fatal("native provisioning accepted a tampered signed seed root")
	}
}

func TestNativeProvisioningRejectsTamperedIssuerMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	metadata, err := decodeNativeIssuerMetadata(input.IssuerMetadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.MetadataSignature[0] ^= 0xff
	input.IssuerMetadata, err = protocol.Encode(metadata)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted tampered issuer metadata")
	}
}

func TestNativeProvisioningRejectsIssuerScopeMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	hint, err := admission.DecodeAccessHintCredential(input.AccessHint)
	if err != nil {
		t.Fatal(err)
	}
	hint.RelayBucketID[0] ^= 0xff
	input.AccessHint, err = admission.EncodeAccessHintCredential(hint)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
		t.Fatal("native provisioning accepted an issuer scope mismatch")
	}
}

func TestNativeProvisioningBuildsPinnedHTTP2Carrier(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	requestSeen := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" {
			requestSeen <- fmt.Errorf("unexpected relay connection: proto=%s tls=%+v", r.Proto, r.TLS)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/assets/upload/42" || r.Header.Get("X-Cover-Mode") != "ordinary" {
			requestSeen <- fmt.Errorf("unexpected relay request: method=%s path=%s headers=%v", r.Method, r.URL.Path, r.Header)
			return
		}
		requestSeen <- nil
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test server did not provide a certificate")
	}
	input := validNativeProvisioningWithOriginSPKI(t, now, auroracrypto.PreHash(certificate.RawSubjectPublicKeyInfo))
	configureNativeProvisioningRelay(t, &input, server.URL+"/assets/upload/42", certificate.Raw)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := provisioning.NewHTTP2ClientCarrierOpener(now)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := opener.Open(context.Background(), bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = carrier.Close() })
	select {
	case err := <-requestSeen:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("native provisioning carrier did not reach the relay")
	}
}

func TestNativeProvisioningRejectsWrongCarrierSPKIPin(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test server did not provide a certificate")
	}
	input := validNativeProvisioning(t, now)
	configureNativeProvisioningRelay(t, &input, server.URL+"/assets/upload/42", certificate.Raw)
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := provisioning.NewHTTP2ClientCarrierOpener(now)
	if err != nil {
		t.Fatal(err)
	}
	if carrier, err := opener.Open(context.Background(), bytes.Repeat([]byte{0x31}, 32)); err == nil {
		_ = carrier.Close()
		t.Fatal("native provisioning accepted a mismatched relay SPKI pin")
	}
}

func TestNativeProvisioningRejectsNonCanonicalCarrierConfiguration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	input := validNativeProvisioning(t, now)
	input.RelayRequestHeaders = []byte{2, 3, 'X', '-', 'A', 0, 1, 'a', 3, 'X', '-', 'A', 0, 1, 'a'}
	if _, err := EncodeNativeProvisioning(input); err == nil {
		t.Fatal("native provisioning accepted duplicate carrier headers")
	}
	if _, err := EncodeNativeHeaders(http.Header{"X-Aurora-Mode": {"ordinary"}}); err == nil {
		t.Fatal("native provisioning accepted a visible protocol marker")
	}
}

func TestParseNativeProvisioningRejectsStaleAndUnsignedDeployment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, mutate := range []struct {
		name  string
		apply func(testing.TB, *NativeProvisioning)
	}{
		{
			name: "stale access hint",
			apply: func(t testing.TB, input *NativeProvisioning) {
				credential, err := admission.DecodeAccessHintCredential(input.AccessHint)
				if err != nil {
					t.Fatal(err)
				}
				credential.ExpiryUnix = uint64(now.Add(-time.Second).Unix())
				input.AccessHint, err = admission.EncodeAccessHintCredential(credential)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "template signature mismatch",
			apply: func(t testing.TB, input *NativeProvisioning) {
				template, err := nativeProvisioningTemplate(input.Template)
				if err != nil {
					t.Fatal(err)
				}
				template.TemplateFamilySignature[0] ^= 0xff
				input.Template, err = protocol.Encode(template)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			input := validNativeProvisioning(t, now)
			mutate.apply(t, &input)
			encoded, err := EncodeNativeProvisioning(input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, now); err == nil {
				t.Fatal("invalid native provisioning was accepted")
			}
		})
	}
}

func FuzzParseNativeProvisioning(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	input := validNativeProvisioning(f, time.Unix(1_700_000_000, 0))
	encoded, err := EncodeNativeProvisioning(input)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = ParseNativeProvisioningWithTrust(encoded, input.signedSeedTrust, time.Unix(1_700_000_000, 0))
	})
}

func FuzzParseNativeProvisioningTrust(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00})
	input := validNativeProvisioning(f, time.Unix(1_700_000_000, 0))
	encoded, err := EncodeNativeProvisioningTrust(input.signedSeedTrust)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		trust, err := ParseNativeProvisioningTrust(encoded)
		if err != nil {
			return
		}
		canonical, err := EncodeNativeProvisioningTrust(trust)
		if err != nil {
			t.Fatal(err)
		}
		defer zeroNativeProvisioningBytes(canonical)
		if !bytes.Equal(encoded, canonical) {
			t.Fatal("native provisioning trust parser accepted a non-canonical encoding")
		}
	})
}

type nativeProvisioningProofProvider struct{}

func (nativeProvisioningProofProvider) BuildProofs(_ context.Context, _ handshake.ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	return protocol.AdmissionProof{}, protocol.ReplayProof{}, nil
}

func validNativeProvisioning(t testing.TB, now time.Time) NativeProvisioning {
	return validNativeProvisioningWithOriginSPKI(t, now, nativeProvisioningBytes(0x03, 48))
}

func validNativeProvisioningWithOriginSPKI(t testing.TB, now time.Time, originSPKIHash []byte) NativeProvisioning {
	t.Helper()
	nowUnix := uint64(now.Unix())
	longtermClassical := nativeProvisioningECDSAKey(t)
	epochClassical := nativeProvisioningECDSAKey(t)
	templateAuthority := nativeProvisioningECDSAKey(t)
	longtermPQPublic, longtermPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPQPublic, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       nativeProvisioningBytes(0x01, 16),
		TemplateFamilyID: nativeProvisioningBytes(0x02, 16),
		ValidFromUnix:    nowUnix - 60,
		ValidUntilUnix:   nowUnix + 3600,
		OriginSPKIHash:   append([]byte(nil), originSPKIHash...),
		PublicNameHash:   nativeProvisioningBytes(0x04, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      nativeProvisioningBytes(0x05, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{nativeProvisioningBytes(0x06, 48)},
		OriginPassThroughSlotCommitments: [][]byte{nativeProvisioningBytes(0x07, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  nativeProvisioningBytes(0x08, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: nativeProvisioningBytes(0x09, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               nativeProvisioningBytes(0x0a, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   nativeProvisioningBytes(0x0b, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: nativeProvisioningBytes(0x0c, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: nativeProvisioningBytes(0x0d, 16),
			DatagramRateDistributionID: nativeProvisioningBytes(0x0e, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: nativeProvisioningBytes(0x0f, 16),
		},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope: protocol.TimingEnvelope{
			TimingPolicyID:       5,
			JitterDistributionID: nativeProvisioningBytes(0x10, 16),
		},
	}
	commitment, err := trust.CoverOriginCommitment(template)
	if err != nil {
		t.Fatal(err)
	}
	template.CoverOriginCommitment = commitment
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}

	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:         registry.Version20,
		RelayID:                   nativeProvisioningBytes(0x11, 32),
		RoleFlags:                 1,
		ValidFromUnix:             nowUnix - 60,
		ValidUntilUnix:            nowUnix + 3600,
		RelayLongtermClassicalKey: nativeProvisioningPublicRecord(t, longtermClassical),
		RelayLongtermPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       longtermPQPublic.Bytes(),
		},
		EpochID:               9,
		EpochAuthClassicalKey: nativeProvisioningPublicRecord(t, epochClassical),
		EpochAuthPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       epochPQPublic.Bytes(),
		},
		EpochValidFromUnix:           nowUnix - 60,
		EpochValidUntilUnix:          nowUnix + 1800,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    nowUnix + 1800,
		ReplayWindowID:               nativeProvisioningBytes(0x12, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: nativeProvisioningBytes(0x13, 48),
		SupportedShapeIDsCommitment:  nativeProvisioningBytes(0x14, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         nativeProvisioningBytes(0x15, 48),
		AbusePolicyCommitment:        nativeProvisioningBytes(0x16, 48),
	}
	descriptorInput, err := trust.RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermClassical, err = ecdsa.SignASN1(rand.Reader, longtermClassical, descriptorInput)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(longtermPQPrivate, descriptorInput, nil, false, descriptor.SignatureByLongtermPQ); err != nil {
		t.Fatal(err)
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	templateFamilyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, templateFamilyInput)
	if err != nil {
		t.Fatal(err)
	}
	templateInstanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, templateInstanceInput)
	if err != nil {
		t.Fatal(err)
	}

	descriptorBytes, err := protocol.Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	templateBytes, err := protocol.Encode(template)
	if err != nil {
		t.Fatal(err)
	}
	templateAuthorityBytes, err := protocol.Encode(nativeProvisioningPublicRecord(t, templateAuthority))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := issuerd.NewHarnessService(nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	issuerMetadataBytes, err := protocol.Encode(issuer.PublishIssuerMetadata())
	if err != nil {
		t.Fatal(err)
	}
	issuerMetadata := issuer.PublishIssuerMetadata()
	accessHintBytes, err := admission.EncodeAccessHintCredential(admission.AccessHintCredential{
		HintIssuerID:  append([]byte(nil), issuerMetadata.IssuerID...),
		RelayBucketID: append([]byte(nil), issuerMetadata.RelayBucketScopes[0].RelayBucketID...),
		HintEpochID:   3,
		HintSelector:  nativeProvisioningBytes(0x23, 16),
		HintSecret:    nativeProvisioningBytes(0x24, 32),
		ExpiryUnix:    nowUnix + 1800,
		MaxUses:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	signedSeed, signedSeedRoots := nativeProvisioningSignedSeed(t, now, issuerMetadata, issuer.AuthorityKeys(), issuerMetadata.IssuerID, nil)
	policyBytes, err := protocol.Encode(protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{registry.SuiteHybrid768P256AESGCM},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         registry.PolicyFastWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteFast1,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
	})
	if err != nil {
		t.Fatal(err)
	}
	hintsBytes, err := protocol.Encode(protocol.ClientTransportHints{Padding: nativeProvisioningBytes(0x25, 8)})
	if err != nil {
		t.Fatal(err)
	}
	requestHeaders, err := EncodeNativeHeaders(http.Header{"X-Cover-Mode": {"ordinary"}})
	if err != nil {
		t.Fatal(err)
	}
	responseHeaders, err := EncodeNativeHeaders(http.Header{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		t.Fatal(err)
	}
	trustRoots, err := EncodeNativeTrustRoots(nil)
	if err != nil {
		t.Fatal(err)
	}
	signedSeedTrust, err := NewNativeProvisioningTrust(signedSeedRoots)
	if err != nil {
		t.Fatal(err)
	}
	return NativeProvisioning{
		RelayURL:              "https://relay.example/assets/upload/42",
		IssuerURL:             "https://issuer.example",
		IssuerCarrierPath:     "/assets/issue/42",
		IssuerMetadata:        issuerMetadataBytes,
		SignedSeed:            signedSeed,
		Descriptor:            descriptorBytes,
		TrustedDescriptorHash: descriptorHash,
		Template:              templateBytes,
		TemplateAuthorityKey:  templateAuthorityBytes,
		RequestClassID:        7,
		Suite:                 registry.SuiteHybrid768P256AESGCM,
		AccessHint:            accessHintBytes,
		PolicyOffer:           policyBytes,
		TransportHints:        hintsBytes,
		RelayExpectedStatus:   http.StatusOK,
		RelayRequestHeaders:   requestHeaders,
		RelayResponseHeaders:  responseHeaders,
		RelayTrustRoots:       trustRoots,
		signedSeedTrust:       signedSeedTrust,
	}
}

func nativeProvisioningSignedSeed(t testing.TB, now time.Time, metadata protocol.IssuerMetadata, bootstrapKeys []protocol.AuthorityKeyRecord, issuerID, metadataHashOverride []byte) ([]byte, []protocol.AuthorityKeyRecord) {
	t.Helper()
	privateKey := nativeProvisioningECDSAKey(t)
	publicKey, err := privateKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rootPublicKey := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       publicKey,
	}
	encodedRootPublicKey, err := protocol.Encode(rootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := protocol.AuthorityKeyRecord{
		AuthorityID:    nativeProvisioningBytes(0x26, 16),
		AuthorityKeyID: trust.AuthorityKeyID(encodedRootPublicKey),
		AuthorityRole:  1,
		PublicKey:      rootPublicKey,
		ValidFromUnix:  uint64(now.Unix()) - 60,
		ValidUntilUnix: uint64(now.Add(time.Hour).Unix()),
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}
	metadataHash, err := trust.IssuerMetadataHash(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if metadataHashOverride != nil {
		metadataHash = append([]byte(nil), metadataHashOverride...)
	}
	seed := protocol.SignedSeedRecord{
		SeedVersion:                registry.Version20,
		SeedID:                     nativeProvisioningBytes(0x27, 16),
		ValidFromUnix:              uint64(now.Unix()) - 60,
		ValidUntilUnix:             uint64(now.Add(time.Hour).Unix()),
		DirectoryConsensusHint:     []byte("directory"),
		BridgeBucketHint:           []byte("bridge"),
		TokenIssuerHint:            append([]byte(nil), issuerID...),
		IssuerMetadataHash:         metadataHash,
		BootstrapAuthorityKeys:     cloneNativeProvisioningAuthorityKeys(bootstrapKeys),
		BootstrapCoverTemplateHash: nativeProvisioningBytes(0x28, 48),
		NextSeedCommitment:         nativeProvisioningBytes(0x29, 48),
		SoftwareUpdateEpoch:        1,
		SeedSignature: protocol.ObjectSignature{
			SignerKeyID:     append([]byte(nil), root.AuthorityKeyID...),
			SignatureScheme: root.PublicKey.SignatureScheme,
			KeyEncoding:     root.PublicKey.KeyEncoding,
		},
	}
	input, err := trust.SignedSeedRecordSignatureInput(seed)
	if err != nil {
		t.Fatal(err)
	}
	seed.SeedSignature.Signature, err = ecdsa.SignASN1(rand.Reader, privateKey, input)
	if err != nil {
		t.Fatal(err)
	}
	encodedSeed, err := protocol.Encode(seed)
	if err != nil {
		t.Fatal(err)
	}
	return encodedSeed, []protocol.AuthorityKeyRecord{root}
}

func nativeProvisioningSignedSeedAndTrust(t testing.TB, now time.Time, metadata protocol.IssuerMetadata, bootstrapKeys []protocol.AuthorityKeyRecord, issuerID, metadataHashOverride []byte) ([]byte, NativeProvisioningTrust) {
	t.Helper()
	seed, roots := nativeProvisioningSignedSeed(t, now, metadata, bootstrapKeys, issuerID, metadataHashOverride)
	trusted, err := NewNativeProvisioningTrust(roots)
	zeroNativeProvisioningAuthorityKeys(roots)
	if err != nil {
		t.Fatal(err)
	}
	return seed, trusted
}

func configureNativeProvisioningRelay(t testing.TB, input *NativeProvisioning, relayURL string, trustRoot []byte) {
	t.Helper()
	trustRoots, err := EncodeNativeTrustRoots([][]byte{trustRoot})
	if err != nil {
		t.Fatal(err)
	}
	input.RelayURL = relayURL
	input.RelayExpectedStatus = http.StatusOK
	input.RelayTrustRoots = trustRoots
}

func nativeProvisioningECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func nativeProvisioningPublicRecord(t testing.TB, key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	t.Helper()
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       publicKey,
	}
}

func nativeProvisioningBytes(value byte, length int) []byte {
	return bytes.Repeat([]byte{value}, length)
}

func nativeProvisioningTemplate(encoded []byte) (protocol.CoverTemplate, error) {
	reader := wire.NewReader(encoded)
	template := protocol.DecodeCoverTemplate(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.CoverTemplate{}, fmt.Errorf("decode cover template")
	}
	return template, nil
}
