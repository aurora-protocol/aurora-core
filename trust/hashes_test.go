package trust

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func rb(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func testPK() protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigEd25519Lab,
		KeyEncoding:     registry.KeyEd25519RawPublic,
		PublicKey:       rb(0x11, 32),
	}
}

func TestDirectoryConsensusHashIgnoresAuthoritySignatureBytes(t *testing.T) {
	c := protocol.DirectoryConsensus{
		Version:                 registry.Version20,
		Epoch:                   1,
		ValidFromUnix:           10,
		ValidUntilUnix:          20,
		PreviousConsensusHash:   rb(0, 48),
		RelayDescriptorRoot:     rb(1, 48),
		CoverTemplateFamilyRoot: rb(2, 48),
		RevocationRoot:          rb(3, 48),
		PolicyRoot:              rb(4, 48),
		BridgeBucketCommitment:  rb(5, 48),
		IssuerMetadataRoot:      rb(6, 48),
		AuthoritySignatures: []protocol.SignatureEntry{{
			AuthorityID:     rb(0xaa, 16),
			AuthorityKeyID:  rb(0xbb, 16),
			SignatureScheme: registry.SigEd25519Lab,
			KeyEncoding:     registry.KeyEd25519RawPublic,
			Signature:       []byte("first"),
		}},
	}
	h1, err := DirectoryConsensusHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.AuthoritySignatures[0].Signature = []byte("second")
	h2, err := DirectoryConsensusHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("consensus hash included signature bytes")
	}
}

func TestRelayDescriptorHashIgnoresSignatureBytes(t *testing.T) {
	d := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      rb(1, 32),
		ValidFromUnix:                10,
		ValidUntilUnix:               20,
		RelayLongtermClassicalKey:    testPK(),
		RelayLongtermPQKey:           testPK(),
		EpochAuthClassicalKey:        testPK(),
		EpochAuthPQKey:               testPK(),
		ReplayWindowID:               rb(2, 16),
		SupportedPolicyIDsCommitment: rb(3, 48),
		SupportedShapeIDsCommitment:  rb(4, 48),
		ExitPolicyCommitment:         rb(5, 48),
		AbusePolicyCommitment:        rb(6, 48),
		SignatureByLongtermClassical: []byte("first"),
		SignatureByLongtermPQ:        []byte("first"),
	}
	h1, err := RelayDescriptorHash(d)
	if err != nil {
		t.Fatal(err)
	}
	d.SignatureByLongtermClassical = []byte("second")
	d.SignatureByLongtermPQ = []byte("second")
	h2, err := RelayDescriptorHash(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("descriptor hash included signature bytes")
	}
}

func TestCoverTemplateHashAndValidation(t *testing.T) {
	tpl := protocol.CoverTemplate{
		TemplateVersion:       registry.Version20,
		TemplateID:            rb(1, 16),
		TemplateFamilyID:      rb(2, 16),
		ValidFromUnix:         10,
		ValidUntilUnix:        20,
		OriginSPKIHash:        rb(3, 48),
		PublicNameHash:        rb(4, 48),
		CoverOriginCommitment: rb(5, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             registry.RequestGatewayOwnedSlot,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      rb(6, 16),
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{rb(7, 48)},
		OriginPassThroughSlotCommitments: [][]byte{rb(8, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  rb(9, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: rb(10, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               rb(11, 16),
			BodySizeDistributionID:   rb(12, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                1,
			RecordSizeDistributionID: rb(13, 16),
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  2,
			DatagramSizeDistributionID: rb(14, 16),
			DatagramRateDistributionID: rb(15, 16),
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               3,
			FrameSizeDistributionID: rb(16, 16),
		},
		CacheCookiePolicy:         protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:            protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: rb(17, 16)},
		TemplateFamilySignature:   []byte("family"),
		TemplateInstanceSignature: []byte("instance"),
	}
	if err := ValidateCoverTemplateTime(tpl, 12, 120); err != nil {
		t.Fatal(err)
	}
	for _, class := range tpl.RequestClasses {
		if err := ValidateRequestClass(class); err != nil {
			t.Fatal(err)
		}
	}
	h1, err := CoverTemplateHash(tpl)
	if err != nil {
		t.Fatal(err)
	}
	tpl.TemplateFamilySignature = []byte("other")
	tpl.TemplateInstanceSignature = []byte("other")
	h2, err := CoverTemplateHash(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("cover template hash included signature bytes")
	}
}
