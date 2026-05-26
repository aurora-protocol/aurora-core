package protocol

import (
	"reflect"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestDirectoryAndCoverRecordsRoundTrip(t *testing.T) {
	consensus := DirectoryConsensus{
		Version:                 registry.Version20,
		Epoch:                   7,
		ValidFromUnix:           1700000000,
		ValidUntilUnix:          1700003600,
		PreviousConsensusHash:   fill(0x01, 48),
		RelayDescriptorRoot:     fill(0x02, 48),
		CoverTemplateFamilyRoot: fill(0x03, 48),
		RevocationRoot:          fill(0x04, 48),
		PolicyRoot:              fill(0x05, 48),
		BridgeBucketCommitment:  fill(0x06, 48),
		IssuerMetadataRoot:      fill(0x07, 48),
		AuthoritySignatures: []SignatureEntry{{
			AuthorityID:     fill(0x08, 16),
			AuthorityKeyID:  fill(0x09, 16),
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			Signature:       []byte("directory-signature"),
		}},
	}
	encodedConsensus, err := Encode(consensus)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeDirectoryConsensus(bytesReader(encodedConsensus)); !reflect.DeepEqual(got, consensus) {
		t.Fatalf("DirectoryConsensus round trip mismatch:\n got=%+v\nwant=%+v", got, consensus)
	}

	descriptor := sampleRelayDescriptor()
	encodedDescriptor, err := Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeRelayDescriptor(bytesReader(encodedDescriptor)); !reflect.DeepEqual(got, descriptor) {
		t.Fatalf("RelayDescriptor round trip mismatch:\n got=%+v\nwant=%+v", got, descriptor)
	}

	template := sampleCoverTemplate()
	encodedTemplate, err := Encode(template)
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeCoverTemplate(bytesReader(encodedTemplate)); !reflect.DeepEqual(got, template) {
		t.Fatalf("CoverTemplate round trip mismatch:\n got=%+v\nwant=%+v", got, template)
	}
}

func sampleRelayDescriptor() RelayDescriptor {
	return RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      fill(0x10, 32),
		RoleFlags:                    0x03,
		ValidFromUnix:                1700000000,
		ValidUntilUnix:               1700007200,
		RelayLongtermClassicalKey:    samplePublicKeyRecord(0x11),
		RelayLongtermPQKey:           sampleMLDSAPublicKeyRecord(0x12),
		EpochID:                      9,
		EpochAuthClassicalKey:        samplePublicKeyRecord(0x13),
		EpochAuthPQKey:               sampleMLDSAPublicKeyRecord(0x14),
		EpochValidFromUnix:           1700000000,
		EpochValidUntilUnix:          1700003600,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    1700003600,
		ReplayWindowID:               fill(0x15, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream, registry.MethodWebH1WS},
		SupportedPolicyIDsCommitment: fill(0x16, 48),
		SupportedShapeIDsCommitment:  fill(0x17, 48),
		PublicRoutingRecords: []RoutingRecord{{
			RoutingRecordID:   fill(0x18, 16),
			TransportFamilyID: registry.MethodWebH2Stream,
			LocatorType:       registry.LocatorAuthority,
			LocatorBody:       []byte("cover.example"),
			Priority:          1,
			NotBeforeUnix:     1700000000,
			NotAfterUnix:      1700003600,
		}},
		CoverTemplateInstanceHashes:  [][]byte{fill(0x19, 48)},
		ExitPolicyCommitment:         fill(0x1a, 48),
		AbusePolicyCommitment:        fill(0x1b, 48),
		SignatureByLongtermClassical: []byte("classical-signature"),
		SignatureByLongtermPQ:        []byte("pq-signature"),
	}
}

func sampleCoverTemplate() CoverTemplate {
	return CoverTemplate{
		TemplateVersion:       registry.Version20,
		TemplateID:            fill(0x20, 16),
		TemplateFamilyID:      fill(0x21, 16),
		ValidFromUnix:         1700000000,
		ValidUntilUnix:        1700003600,
		OriginSPKIHash:        fill(0x22, 48),
		PublicNameHash:        fill(0x23, 48),
		CoverOriginCommitment: fill(0x24, 48),
		RequestClasses: []RequestClass{{
			ClassID:             1,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      fill(0x25, 16),
			BodyPolicyID:        2,
			ResponsePolicyID:    3,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{fill(0x26, 48)},
		OriginPassThroughSlotCommitments: [][]byte{fill(0x27, 48)},
		PreludeEnvelope: PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         2048,
			RequestSizeDistributionID:  fill(0x28, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: fill(0x29, 16),
			ContentTypeFamilyID:        4,
			ChunkingPolicyID:           5,
			ResponseTimingPolicyID:     6,
		},
		CapsuleEnvelope: CapsuleEnvelope{
			EnvelopeID:               fill(0x2a, 16),
			MinCapsuleBodySize:       2048,
			MaxCapsuleBodySize:       4096,
			BodySizeDistributionID:   fill(0x2b, 16),
			AllowedContentTypeIDs:    []uint64{7, 8},
			ChunkingPolicyID:         9,
			FailureResponseFamilyID:  10,
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: H2CoverProfile{
			ProfileID:                  11,
			H2SettingsFamilyID:         12,
			PseudoHeaderOrderFamilyID:  13,
			HPACKBehaviorFamilyID:      14,
			MaxConcurrentStreamsBucket: 15,
			InitialWindowBucket:        16,
			RequestGraphFamilyID:       17,
			RecordSizeDistributionID:   fill(0x2c, 16),
			IdleTimeoutPolicyID:        18,
		},
		H3Profile: H3CoverProfile{
			ProfileID:                  19,
			H3SettingsFamilyID:         20,
			QPACKBehaviorFamilyID:      21,
			SupportsH3Datagram:         true,
			SupportsWebTransportH3:     true,
			WebTransportProfileID:      22,
			QUICDatagramRequired:       true,
			ResetStreamAtRequired:      true,
			RequestGraphFamilyID:       23,
			DatagramSizeDistributionID: fill(0x2d, 16),
			DatagramRateDistributionID: fill(0x2e, 16),
			FallbackMethodID:           registry.MethodWebH2Stream,
		},
		WebSocketProfile: WebSocketCoverProfile{
			ProfileID:               24,
			UpgradeFamilyID:         25,
			SubprotocolFamilyID:     26,
			FrameSizeDistributionID: fill(0x2f, 16),
			PingPolicyID:            27,
			CloseBehaviorID:         28,
			StreamLifetimePolicyID:  29,
		},
		CacheCookiePolicy: CacheCookiePolicy{
			PolicyID:                 30,
			CookieBehaviorFamilyID:   31,
			CacheControlFamilyID:     32,
			ETagBehaviorFamilyID:     33,
			VaryHeaderFamilyID:       34,
			RedirectBehaviorFamilyID: 35,
		},
		TimingEnvelope: TimingEnvelope{
			TimingPolicyID:       36,
			MinResponseDelayMS:   37,
			MaxResponseDelayMS:   38,
			JitterDistributionID: fill(0x30, 16),
			TimeoutFamilyID:      39,
			RetryFamilyID:        40,
			CloseTimingFamilyID:  41,
		},
		TemplateFamilySignature:   []byte("family-signature"),
		TemplateInstanceSignature: []byte("instance-signature"),
	}
}

func samplePublicKeyRecord(marker byte) PublicKeyRecord {
	return PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       fill(marker, 65),
	}
}

func sampleMLDSAPublicKeyRecord(marker byte) PublicKeyRecord {
	return PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       fill(marker, 32),
	}
}
