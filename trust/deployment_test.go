package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	deploymentNow     uint64 = 200
	deploymentClassID uint64 = 7
)

type deploymentFixture struct {
	input RelayDeploymentVerification
}

func TestVerifyRelayDeploymentAcceptsSignedPinnedDeployment(t *testing.T) {
	fixture := newDeploymentFixture(t)
	verified, err := VerifyRelayDeployment(fixture.input)
	if err != nil {
		t.Fatalf("valid deployment rejected: %v", err)
	}
	if !verified.Valid() {
		t.Fatal("verified deployment reports invalid")
	}
	if !bytes.Equal(verified.DescriptorHash(), fixture.input.TrustedDescriptorHash) {
		t.Fatal("verified descriptor hash mismatch")
	}
	templateHash, err := CoverTemplateHash(fixture.input.Template)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified.TemplateHash(), templateHash) {
		t.Fatal("verified template hash mismatch")
	}
	class := verified.RequestClass()
	if class.ClassID != deploymentClassID || class.ClassType != registry.RequestGatewayOwnedSlot || class.AllowedMethodFamily != registry.MethodWebH2Stream {
		t.Fatalf("unexpected verified request class: %+v", class)
	}
}

func TestVerifyRelayDeploymentRejectsInvalidTrustOrCompatibility(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RelayDeploymentVerification)
	}{
		{name: "trusted descriptor hash", mutate: func(in *RelayDeploymentVerification) { in.TrustedDescriptorHash[0] ^= 0xff }},
		{name: "classical descriptor signature", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.SignatureByLongtermClassical[0] ^= 0xff }},
		{name: "pq descriptor signature", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.SignatureByLongtermPQ[0] ^= 0xff }},
		{name: "template authority signature", mutate: func(in *RelayDeploymentVerification) { in.Template.TemplateFamilySignature[0] ^= 0xff }},
		{name: "template instance signature", mutate: func(in *RelayDeploymentVerification) { in.Template.TemplateInstanceSignature[0] ^= 0xff }},
		{name: "descriptor expired", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.ValidUntilUnix = deploymentNow }},
		{name: "descriptor not yet valid", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.ValidFromUnix = deploymentNow + 1 }},
		{name: "epoch expired", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.EpochValidUntilUnix = deploymentNow }},
		{name: "epoch not yet valid", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.EpochValidFromUnix = deploymentNow + 1 }},
		{name: "replay epoch expired", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.ReplayEpochValidUntilUnix = deploymentNow }},
		{name: "template expired", mutate: func(in *RelayDeploymentVerification) { in.Template.ValidUntilUnix = deploymentNow }},
		{name: "template commitment missing", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.CoverTemplateInstanceHashes = nil }},
		{name: "template commitment duplicate", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.CoverTemplateInstanceHashes = append(in.Descriptor.CoverTemplateInstanceHashes, append([]byte(nil), in.Descriptor.CoverTemplateInstanceHashes[0]...))
		}},
		{name: "suite unsupported", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.SupportedSuiteIDs = []uint64{registry.SuiteHybrid1024AESGCM}
		}},
		{name: "method unsupported", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.SupportedMethodIDs = []uint64{registry.MethodWebH1WS}
		}},
		{name: "class not gateway owned", mutate: func(in *RelayDeploymentVerification) {
			in.Template.RequestClasses[0].ClassType = registry.RequestOriginPassThrough
		}},
		{name: "class cannot carry prelude", mutate: func(in *RelayDeploymentVerification) { in.Template.RequestClasses[0].MayCarryPrelude = false }},
		{name: "class cannot carry capsule", mutate: func(in *RelayDeploymentVerification) { in.Template.RequestClasses[0].MayCarryCapsule = false }},
		{name: "class method mismatch", mutate: func(in *RelayDeploymentVerification) {
			in.Template.RequestClasses[0].AllowedMethodFamily = registry.MethodWebH1WS
		}},
		{name: "class missing", mutate: func(in *RelayDeploymentVerification) { in.RequestClassID++ }},
		{name: "invalid template authority key", mutate: func(in *RelayDeploymentVerification) { in.TemplateAuthorityKey.PublicKey = nil }},
		{name: "pq proof required but absent", mutate: func(in *RelayDeploymentVerification) { in.Descriptor.SignatureByLongtermPQ = nil }},
		{name: "classical key uses PQ scheme", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.RelayLongtermClassicalKey = in.Descriptor.RelayLongtermPQKey
		}},
		{name: "pq key uses classical scheme", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.RelayLongtermPQKey = in.Descriptor.RelayLongtermClassicalKey
		}},
		{name: "duplicate suite", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.SupportedSuiteIDs = append(in.Descriptor.SupportedSuiteIDs, in.Descriptor.SupportedSuiteIDs[0])
		}},
		{name: "duplicate method", mutate: func(in *RelayDeploymentVerification) {
			in.Descriptor.SupportedMethodIDs = append(in.Descriptor.SupportedMethodIDs, in.Descriptor.SupportedMethodIDs[0])
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeploymentFixture(t)
			test.mutate(&fixture.input)
			if _, err := VerifyRelayDeployment(fixture.input); err == nil {
				t.Fatalf("invalid deployment accepted")
			}
		})
	}
}

func TestVerifiedRelayDeploymentOwnsInputsAndAccessors(t *testing.T) {
	fixture := newDeploymentFixture(t)
	verified, err := VerifyRelayDeployment(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	wantDescriptorHash := append([]byte(nil), fixture.input.TrustedDescriptorHash...)
	wantTemplateID := append([]byte(nil), fixture.input.Template.TemplateID...)

	fixture.input.TrustedDescriptorHash[0] ^= 0xff
	fixture.input.Descriptor.RelayID[0] ^= 0xff
	fixture.input.Template.TemplateID[0] ^= 0xff
	fixture.input.Template.RequestClasses[0].PathTemplateID[0] ^= 0xff

	if !bytes.Equal(verified.DescriptorHash(), wantDescriptorHash) {
		t.Fatal("verified descriptor hash aliased caller input")
	}
	if !bytes.Equal(verified.Template().TemplateID, wantTemplateID) {
		t.Fatal("verified template aliased caller input")
	}

	descriptor := verified.Descriptor()
	template := verified.Template()
	class := verified.RequestClass()
	hash := verified.DescriptorHash()
	descriptor.RelayID[0] ^= 0xff
	template.TemplateID[0] ^= 0xff
	class.PathTemplateID[0] ^= 0xff
	hash[0] ^= 0xff

	if !bytes.Equal(verified.DescriptorHash(), wantDescriptorHash) {
		t.Fatal("descriptor hash accessor exposed internal storage")
	}
	if !bytes.Equal(verified.Template().TemplateID, wantTemplateID) {
		t.Fatal("template accessor exposed internal storage")
	}
	if bytes.Equal(class.PathTemplateID, verified.RequestClass().PathTemplateID) {
		t.Fatal("request class accessor exposed internal storage")
	}
}

func TestZeroVerifiedRelayDeploymentIsInvalid(t *testing.T) {
	var deployment VerifiedRelayDeployment
	if deployment.Valid() {
		t.Fatal("zero deployment reports valid")
	}
}

func newDeploymentFixture(t *testing.T) deploymentFixture {
	t.Helper()
	longtermClassical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochClassical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	templateAuthority, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
		TemplateID:       rb(0x01, 16),
		TemplateFamilyID: rb(0x02, 16),
		ValidFromUnix:    100,
		ValidUntilUnix:   400,
		OriginSPKIHash:   rb(0x03, 48),
		PublicNameHash:   rb(0x04, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             deploymentClassID,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      rb(0x05, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{rb(0x06, 48)},
		OriginPassThroughSlotCommitments: [][]byte{rb(0x07, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  rb(0x08, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: rb(0x09, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               rb(0x0a, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   rb(0x0b, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: rb(0x0c, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: rb(0x0d, 16),
			DatagramRateDistributionID: rb(0x0e, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: rb(0x0f, 16),
		},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope: protocol.TimingEnvelope{
			TimingPolicyID:       5,
			JitterDistributionID: rb(0x10, 16),
		},
	}
	commitment, err := CoverOriginCommitment(template)
	if err != nil {
		t.Fatal(err)
	}
	template.CoverOriginCommitment = commitment
	templateHash, err := CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}

	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:         registry.Version20,
		RelayID:                   rb(0x11, 32),
		RoleFlags:                 1,
		ValidFromUnix:             100,
		ValidUntilUnix:            400,
		RelayLongtermClassicalKey: ecdsaPublicRecord(longtermClassical),
		RelayLongtermPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       longtermPQPublic.Bytes(),
		},
		EpochID:               9,
		EpochAuthClassicalKey: ecdsaPublicRecord(epochClassical),
		EpochAuthPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       epochPQPublic.Bytes(),
		},
		EpochValidFromUnix:           150,
		EpochValidUntilUnix:          300,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    290,
		ReplayWindowID:               rb(0x12, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: rb(0x13, 48),
		SupportedShapeIDsCommitment:  rb(0x14, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         rb(0x15, 48),
		AbusePolicyCommitment:        rb(0x16, 48),
	}
	descriptorInput, err := RelayDescriptorSignatureInput(descriptor)
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
	descriptorHash, err := RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}

	templateFamilyInput, err := CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, templateFamilyInput)
	if err != nil {
		t.Fatal(err)
	}
	templateInstanceInput, err := CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, templateInstanceInput)
	if err != nil {
		t.Fatal(err)
	}

	return deploymentFixture{input: RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     ecdsaPublicRecord(templateAuthority),
		RequestClassID:           deploymentClassID,
		Suite:                    registry.SuiteHybrid768P256AESGCM,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  deploymentNow,
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	}}
}

func ecdsaPublicRecord(key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y),
	}
}
