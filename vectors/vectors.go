package vectors

import (
	"encoding/hex"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/route"
	"github.com/aurora-protocol/aurora-core/wire"
)

type StructuralBundle struct {
	ControlAAD                    string
	RouteWrapCiphertextTag        string
	PreviousHopFullTranscriptHash string
	AuthorityKeyID                string
	PublicKeyRecord               string
	AuthorityKeyRecord            string
	ObjectSignature               string
	ObjectSignatureUnsigned       string
	ObjectSignatureHash           string
	DirectoryConsensus            string
	RelayDescriptor               string
	CoverTemplate                 string
	FlowOpen                      string
	UDPTargetConfirm              string
	FlowClose                     string
}

func GenerateStructuralBundle() (StructuralBundle, error) {
	controlAAD, err := auroracrypto.ControlAAD(auroracrypto.ControlAADInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		MsgType:                         registry.MsgCoverCapsule1,
		RouteInstanceID:                 1,
		HandshakeBindingContext:         repeated(0xaa, 48),
		PreludeTranscriptHashForThisHop: repeated(0xbb, 48),
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	_, _, _, _, sealed, err := auroracrypto.SealRoutePrelude(auroracrypto.RouteWrapInput{
		RouteInstanceID:                1,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: repeated(0x41, 48),
		NextRelayDescriptorHash:        repeated(0x42, 48),
		HintIssuerID:                   repeated(0x34, 16),
		RelayBucketID:                  repeated(0x35, 16),
		HintEpochID:                    7,
		HintSelector:                   repeated(0x31, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      repeated(0x32, 16),
		HintSecret:                     repeated(0x33, 32),
	}, repeated(0x44, 16))
	if err != nil {
		return StructuralBundle{}, err
	}
	previousHopFullTranscript, err := route.PreviousHopFullTranscriptHash(registry.SuiteHybrid768AESGCM, repeated(0x66, 48))
	if err != nil {
		return StructuralBundle{}, err
	}
	pk := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       repeated(0x04, 65),
	}
	encodedPK, err := wire.Encode(pk)
	if err != nil {
		return StructuralBundle{}, err
	}
	keyID := auroracrypto.Truncate128(auroracrypto.PreHashLabel("aurora v2.0 authority key id", encodedPK))
	akr := protocol.AuthorityKeyRecord{
		AuthorityID:    repeated(0x11, 16),
		AuthorityKeyID: keyID,
		AuthorityRole:  1,
		PublicKey:      pk,
		ValidFromUnix:  1700000000,
		ValidUntilUnix: 1800000000,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageAllKnownAuthority,
	}
	encodedAKR, err := wire.Encode(akr)
	if err != nil {
		return StructuralBundle{}, err
	}
	objSig := protocol.ObjectSignature{
		SignerKeyID:     keyID,
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		Signature:       repeated(0x55, 8),
	}
	encodedSig, err := wire.Encode(objSig)
	if err != nil {
		return StructuralBundle{}, err
	}
	unsignedSig, err := wire.Encode(objSig.Unsigned())
	if err != nil {
		return StructuralBundle{}, err
	}
	sigHash := auroracrypto.PreHashLabel("aurora v2.0 structural object signature", unsignedSig)
	encodedConsensus, err := wire.Encode(sampleDirectoryConsensus())
	if err != nil {
		return StructuralBundle{}, err
	}
	encodedDescriptor, err := wire.Encode(sampleRelayDescriptor())
	if err != nil {
		return StructuralBundle{}, err
	}
	encodedTemplate, err := wire.Encode(sampleCoverTemplate())
	if err != nil {
		return StructuralBundle{}, err
	}
	flowOpen, err := wire.Encode(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           7,
		FlowKind:         0x02,
		TargetKind:       0x01,
		TargetHost:       []byte{93, 184, 216, 34},
		TargetPort:       443,
		UDPFQDNMode:      0x01,
		NameBindingID:    repeated(0x51, 16),
		DNSAnswerSetHash: repeated(0x52, 48),
		LocalBindingMode: 0x02,
		PriorityClass:    0x03,
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	udpConfirm, err := wire.Encode(protocol.UDPTargetConfirm{
		FlowID:           7,
		TargetKind:       0x01,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: repeated(0x52, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	flowClose, err := wire.Encode(protocol.FlowClose{
		FlowID:                   7,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
		FinalSequenceHint:        99,
		Reason:                   []byte("done"),
	})
	if err != nil {
		return StructuralBundle{}, err
	}
	return StructuralBundle{
		ControlAAD:                    hex.EncodeToString(controlAAD),
		RouteWrapCiphertextTag:        hex.EncodeToString(sealed),
		PreviousHopFullTranscriptHash: hex.EncodeToString(previousHopFullTranscript),
		AuthorityKeyID:                hex.EncodeToString(keyID),
		PublicKeyRecord:               hex.EncodeToString(encodedPK),
		AuthorityKeyRecord:            hex.EncodeToString(encodedAKR),
		ObjectSignature:               hex.EncodeToString(encodedSig),
		ObjectSignatureUnsigned:       hex.EncodeToString(unsignedSig),
		ObjectSignatureHash:           hex.EncodeToString(sigHash),
		DirectoryConsensus:            hex.EncodeToString(encodedConsensus),
		RelayDescriptor:               hex.EncodeToString(encodedDescriptor),
		CoverTemplate:                 hex.EncodeToString(encodedTemplate),
		FlowOpen:                      hex.EncodeToString(flowOpen),
		UDPTargetConfirm:              hex.EncodeToString(udpConfirm),
		FlowClose:                     hex.EncodeToString(flowClose),
	}, nil
}

func sampleDirectoryConsensus() protocol.DirectoryConsensus {
	return protocol.DirectoryConsensus{
		Version:                 registry.Version20,
		Epoch:                   7,
		ValidFromUnix:           1700000000,
		ValidUntilUnix:          1700003600,
		PreviousConsensusHash:   repeated(0x01, 48),
		RelayDescriptorRoot:     repeated(0x02, 48),
		CoverTemplateFamilyRoot: repeated(0x03, 48),
		RevocationRoot:          repeated(0x04, 48),
		PolicyRoot:              repeated(0x05, 48),
		BridgeBucketCommitment:  repeated(0x06, 48),
		IssuerMetadataRoot:      repeated(0x07, 48),
		AuthoritySignatures: []protocol.SignatureEntry{{
			AuthorityID:     repeated(0x08, 16),
			AuthorityKeyID:  repeated(0x09, 16),
			SignatureScheme: registry.SigECDSAP256SHA384DER,
			KeyEncoding:     registry.KeyP256SEC1Uncompressed,
			Signature:       repeated(0x5a, 8),
		}},
	}
}

func sampleRelayDescriptor() protocol.RelayDescriptor {
	return protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      repeated(0x10, 32),
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
		ReplayWindowID:               repeated(0x15, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream, registry.MethodWebH1WS},
		SupportedPolicyIDsCommitment: repeated(0x16, 48),
		SupportedShapeIDsCommitment:  repeated(0x17, 48),
		PublicRoutingRecords: []protocol.RoutingRecord{{
			RoutingRecordID:   repeated(0x18, 16),
			TransportFamilyID: registry.MethodWebH2Stream,
			LocatorType:       registry.LocatorAuthority,
			LocatorBody:       []byte("cover.example"),
			Priority:          1,
			NotBeforeUnix:     1700000000,
			NotAfterUnix:      1700003600,
		}},
		CoverTemplateInstanceHashes:  [][]byte{repeated(0x19, 48)},
		ExitPolicyCommitment:         repeated(0x1a, 48),
		AbusePolicyCommitment:        repeated(0x1b, 48),
		SignatureByLongtermClassical: repeated(0x5b, 8),
		SignatureByLongtermPQ:        repeated(0x5c, 8),
	}
}

func sampleCoverTemplate() protocol.CoverTemplate {
	return protocol.CoverTemplate{
		TemplateVersion:       registry.Version20,
		TemplateID:            repeated(0x20, 16),
		TemplateFamilyID:      repeated(0x21, 16),
		ValidFromUnix:         1700000000,
		ValidUntilUnix:        1700003600,
		OriginSPKIHash:        repeated(0x22, 48),
		PublicNameHash:        repeated(0x23, 48),
		CoverOriginCommitment: repeated(0x24, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             1,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      repeated(0x25, 16),
			BodyPolicyID:        2,
			ResponsePolicyID:    3,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{repeated(0x26, 48)},
		OriginPassThroughSlotCommitments: [][]byte{repeated(0x27, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         2048,
			RequestSizeDistributionID:  repeated(0x28, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: repeated(0x29, 16),
			ContentTypeFamilyID:        4,
			ChunkingPolicyID:           5,
			ResponseTimingPolicyID:     6,
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               repeated(0x2a, 16),
			MinCapsuleBodySize:       2048,
			MaxCapsuleBodySize:       4096,
			BodySizeDistributionID:   repeated(0x2b, 16),
			AllowedContentTypeIDs:    []uint64{7, 8},
			ChunkingPolicyID:         9,
			FailureResponseFamilyID:  10,
			ConsumeFailedBodyLocally: true,
		},
		H2Profile: protocol.H2CoverProfile{
			ProfileID:                  11,
			H2SettingsFamilyID:         12,
			PseudoHeaderOrderFamilyID:  13,
			HPACKBehaviorFamilyID:      14,
			MaxConcurrentStreamsBucket: 15,
			InitialWindowBucket:        16,
			RequestGraphFamilyID:       17,
			RecordSizeDistributionID:   repeated(0x2c, 16),
			IdleTimeoutPolicyID:        18,
		},
		H3Profile: protocol.H3CoverProfile{
			ProfileID:                  19,
			H3SettingsFamilyID:         20,
			QPACKBehaviorFamilyID:      21,
			SupportsH3Datagram:         true,
			SupportsWebTransportH3:     true,
			WebTransportProfileID:      22,
			QUICDatagramRequired:       true,
			ResetStreamAtRequired:      true,
			RequestGraphFamilyID:       23,
			DatagramSizeDistributionID: repeated(0x2d, 16),
			DatagramRateDistributionID: repeated(0x2e, 16),
			FallbackMethodID:           registry.MethodWebH2Stream,
		},
		WebSocketProfile: protocol.WebSocketCoverProfile{
			ProfileID:               24,
			UpgradeFamilyID:         25,
			SubprotocolFamilyID:     26,
			FrameSizeDistributionID: repeated(0x2f, 16),
			PingPolicyID:            27,
			CloseBehaviorID:         28,
			StreamLifetimePolicyID:  29,
		},
		CacheCookiePolicy: protocol.CacheCookiePolicy{
			PolicyID:                 30,
			CookieBehaviorFamilyID:   31,
			CacheControlFamilyID:     32,
			ETagBehaviorFamilyID:     33,
			VaryHeaderFamilyID:       34,
			RedirectBehaviorFamilyID: 35,
		},
		TimingEnvelope: protocol.TimingEnvelope{
			TimingPolicyID:       36,
			MinResponseDelayMS:   37,
			MaxResponseDelayMS:   38,
			JitterDistributionID: repeated(0x30, 16),
			TimeoutFamilyID:      39,
			RetryFamilyID:        40,
			CloseTimingFamilyID:  41,
		},
		TemplateFamilySignature:   repeated(0x5d, 8),
		TemplateInstanceSignature: repeated(0x5e, 8),
	}
}

func samplePublicKeyRecord(marker byte) protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       repeated(marker, 65),
	}
}

func sampleMLDSAPublicKeyRecord(marker byte) protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       repeated(marker, 32),
	}
}

func repeated(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
