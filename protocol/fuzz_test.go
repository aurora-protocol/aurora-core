package protocol

import (
	"fmt"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type decodeFuzzTarget struct {
	name string
	seed []byte
	run  func([]byte) error
}

func DecodeFuzzTargetNames() []string {
	targets := decodeFuzzTargets()
	names := make([]string, len(targets))
	for i, target := range targets {
		names[i] = target.name
	}
	return names
}

func FuzzDecodeProtocolStructs(f *testing.F) {
	targets := decodeFuzzTargets()
	for i, target := range targets {
		f.Add(i, target.seed)
		f.Add(i, []byte{})
	}
	f.Fuzz(func(t *testing.T, targetIndex int, data []byte) {
		if len(targets) == 0 {
			t.Fatalf("no decode fuzz targets registered")
		}
		if targetIndex < 0 {
			targetIndex = ^targetIndex
		}
		target := targets[targetIndex%len(targets)]
		_ = target.run(data)
	})
}

func decodeFuzzTargets() []decodeFuzzTarget {
	return []decodeFuzzTarget{
		readerFuzzTarget("PublicKeyRecord", fuzzSamplePublicKeyRecord()),
		readerFuzzTarget("AuthorityKeyRecord", fuzzSampleAuthorityKeyRecord()),
		readerFuzzTarget("ObjectSignature", fuzzSampleObjectSignature()),
		readerFuzzTarget("TokenVerificationKeyRecord", fuzzSampleTokenVerificationKeyRecord()),
		readerFuzzTarget("SignatureEntry", fuzzSampleSignatureEntry()),
		readerFuzzTarget("DirectoryConsensus", fuzzSampleDirectoryConsensus()),
		readerFuzzTarget("RoutingRecord", fuzzSampleRoutingRecord()),
		readerFuzzTarget("RelayDescriptor", fuzzSampleRelayDescriptor()),
		readerFuzzTarget("RequestClass", fuzzSampleRequestClass()),
		readerFuzzTarget("PreludeEnvelope", fuzzSamplePreludeEnvelope()),
		readerFuzzTarget("CapsuleEnvelope", fuzzSampleCapsuleEnvelope()),
		readerFuzzTarget("H2CoverProfile", fuzzSampleH2CoverProfile()),
		readerFuzzTarget("H3CoverProfile", fuzzSampleH3CoverProfile()),
		readerFuzzTarget("WebSocketCoverProfile", fuzzSampleWebSocketCoverProfile()),
		readerFuzzTarget("CacheCookiePolicy", fuzzSampleCacheCookiePolicy()),
		readerFuzzTarget("TimingEnvelope", fuzzSampleTimingEnvelope()),
		readerFuzzTarget("CoverTemplate", fuzzSampleCoverTemplate()),
		readerFuzzTarget("IssuerTokenKeyRecord", fuzzSampleIssuerTokenKeyRecord()),
		readerFuzzTarget("OriginInfoPolicy", fuzzSampleOriginInfoPolicy()),
		readerFuzzTarget("RelayBucketScope", fuzzSampleRelayBucketScope()),
		readerFuzzTarget("AuxiliaryBindingPolicy", fuzzSampleAuxiliaryBindingPolicy()),
		readerFuzzTarget("IssuerVerifierServiceRecord", fuzzSampleIssuerVerifierServiceRecord()),
		readerFuzzTarget("IssuerMetadata", fuzzSampleIssuerMetadata()),
		readerFuzzTarget("IssuerVerifierRequest", fuzzSampleIssuerVerifierRequest()),
		readerFuzzTarget("IssuerVerifierResponse", fuzzSampleIssuerVerifierResponse()),
		readerFuzzTarget("AdmissionProof", fuzzSampleAdmissionProof()),
		readerFuzzTarget("AuroraTokenMetadata", fuzzSampleAuroraTokenMetadata()),
		readerFuzzTarget("ReplayProof", fuzzSampleReplayProof()),
		readerFuzzTarget("ClientTransportHints", fuzzSampleClientTransportHints()),
		readerFuzzTarget("PolicyOffer", fuzzSamplePolicyOffer()),
		readerFuzzTarget("VirtualAddressAssignment", fuzzSampleVirtualAddressAssignment()),
		readerFuzzTarget("PolicyAccept", fuzzSamplePolicyAccept()),
		readerFuzzTarget("CoverPrelude0", fuzzSampleCoverPrelude0()),
		readerFuzzTarget("CoverPrelude1", fuzzSampleCoverPrelude1()),
		readerFuzzTarget("CoverCapsule1Plain", fuzzSampleCoverCapsule1Plain()),
		readerFuzzTarget("CoverCapsule2Plain", fuzzSampleCoverCapsule2Plain()),
		readerFuzzTarget("RouteCapsule1Plain", fuzzSampleRouteCapsule1Plain()),
		readerFuzzTarget("RouteCapsule2Plain", fuzzSampleRouteCapsule2Plain()),
		readerFuzzTarget("RoutePrelude1", fuzzSampleRoutePrelude1()),
		readerFuzzTarget("AuroraFrame", fuzzSampleAuroraFrame()),
		frameBlockFuzzTarget("FrameBlock", fuzzSampleFrameBlock()),
		readerFuzzTarget("KeyUpdate", fuzzSampleKeyUpdate()),
		readerFuzzTarget("KeyUpdateACK", fuzzSampleKeyUpdateACK()),
		readerFuzzTarget("KeyUpdateRequest", fuzzSampleKeyUpdateRequest()),
		readerFuzzTarget("FlowOpen", fuzzSampleFlowOpen()),
		readerFuzzTarget("UDPTargetConfirm", fuzzSampleUDPTargetConfirm()),
		readerFuzzTarget("FlowClose", fuzzSampleFlowClose()),
		readerFuzzTarget("RouteForwardFrame", fuzzSampleRouteForwardFrame()),
		readerFuzzTarget("RoutePreludeEnvelope", fuzzSampleRoutePreludeEnvelope()),
	}
}

func readerFuzzTarget(name string, sample wire.Encodable) decodeFuzzTarget {
	return decodeFuzzTarget{
		name: name,
		seed: mustEncodeFuzzSeed(sample),
		run: func(data []byte) error {
			r := wire.NewReader(data)
			decodeByName(name, r)
			if err := r.Err(); err != nil {
				return err
			}
			if !r.EOF() {
				return fmt.Errorf("protocol: trailing %s bytes", name)
			}
			return nil
		},
	}
}

func frameBlockFuzzTarget(name string, sample FrameBlock) decodeFuzzTarget {
	return decodeFuzzTarget{
		name: name,
		seed: mustEncodeFuzzSeed(sample),
		run: func(data []byte) error {
			_, err := DecodeFrameBlock(data)
			return err
		},
	}
}

func decodeByName(name string, r *wire.Reader) {
	switch name {
	case "PublicKeyRecord":
		_ = DecodePublicKeyRecord(r)
	case "AuthorityKeyRecord":
		_ = DecodeAuthorityKeyRecord(r)
	case "ObjectSignature":
		_ = DecodeObjectSignature(r)
	case "TokenVerificationKeyRecord":
		_ = DecodeTokenVerificationKeyRecord(r)
	case "SignatureEntry":
		_ = DecodeSignatureEntry(r)
	case "DirectoryConsensus":
		_ = DecodeDirectoryConsensus(r)
	case "RoutingRecord":
		_ = DecodeRoutingRecord(r)
	case "RelayDescriptor":
		_ = DecodeRelayDescriptor(r)
	case "RequestClass":
		_ = DecodeRequestClass(r)
	case "PreludeEnvelope":
		_ = DecodePreludeEnvelope(r)
	case "CapsuleEnvelope":
		_ = DecodeCapsuleEnvelope(r)
	case "H2CoverProfile":
		_ = DecodeH2CoverProfile(r)
	case "H3CoverProfile":
		_ = DecodeH3CoverProfile(r)
	case "WebSocketCoverProfile":
		_ = DecodeWebSocketCoverProfile(r)
	case "CacheCookiePolicy":
		_ = DecodeCacheCookiePolicy(r)
	case "TimingEnvelope":
		_ = DecodeTimingEnvelope(r)
	case "CoverTemplate":
		_ = DecodeCoverTemplate(r)
	case "IssuerTokenKeyRecord":
		_ = DecodeIssuerTokenKeyRecord(r)
	case "OriginInfoPolicy":
		_ = DecodeOriginInfoPolicy(r)
	case "RelayBucketScope":
		_ = DecodeRelayBucketScope(r)
	case "AuxiliaryBindingPolicy":
		_ = DecodeAuxiliaryBindingPolicy(r)
	case "IssuerVerifierServiceRecord":
		_ = DecodeIssuerVerifierServiceRecord(r)
	case "IssuerMetadata":
		_ = DecodeIssuerMetadata(r)
	case "IssuerVerifierRequest":
		_ = DecodeIssuerVerifierRequest(r)
	case "IssuerVerifierResponse":
		_ = DecodeIssuerVerifierResponse(r)
	case "AdmissionProof":
		_ = DecodeAdmissionProof(r)
	case "AuroraTokenMetadata":
		_ = DecodeAuroraTokenMetadata(r)
	case "ReplayProof":
		_ = DecodeReplayProof(r)
	case "ClientTransportHints":
		_ = DecodeClientTransportHints(r)
	case "PolicyOffer":
		_ = DecodePolicyOffer(r)
	case "VirtualAddressAssignment":
		_ = DecodeVirtualAddressAssignment(r)
	case "PolicyAccept":
		_ = DecodePolicyAccept(r)
	case "CoverPrelude0":
		_ = DecodeCoverPrelude0(r)
	case "CoverPrelude1":
		_ = DecodeCoverPrelude1(r)
	case "CoverCapsule1Plain":
		_ = DecodeCoverCapsule1Plain(r)
	case "CoverCapsule2Plain":
		_ = DecodeCoverCapsule2Plain(r)
	case "RouteCapsule1Plain":
		_ = DecodeRouteCapsule1Plain(r)
	case "RouteCapsule2Plain":
		_ = DecodeRouteCapsule2Plain(r)
	case "RoutePrelude1":
		_ = DecodeRoutePrelude1(r)
	case "AuroraFrame":
		_ = DecodeAuroraFrame(r)
	case "KeyUpdate":
		_ = DecodeKeyUpdate(r)
	case "KeyUpdateACK":
		_ = DecodeKeyUpdateACK(r)
	case "KeyUpdateRequest":
		_ = DecodeKeyUpdateRequest(r)
	case "FlowOpen":
		_ = DecodeFlowOpen(r)
	case "UDPTargetConfirm":
		_ = DecodeUDPTargetConfirm(r)
	case "FlowClose":
		_ = DecodeFlowClose(r)
	case "RouteForwardFrame":
		_ = DecodeRouteForwardFrame(r)
	case "RoutePreludeEnvelope":
		_ = DecodeRoutePreludeEnvelope(r)
	default:
		panic("unregistered decode fuzz target " + name)
	}
}

func mustEncodeFuzzSeed(v wire.Encodable) []byte {
	encoded, err := Encode(v)
	if err != nil {
		panic(err)
	}
	return encoded
}

func fb(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func fuzzSamplePublicKeyRecord() PublicKeyRecord {
	return PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       append([]byte{0x04}, fb(0x11, 64)...),
	}
}

func fuzzSampleAuthorityKeyRecord() AuthorityKeyRecord {
	return AuthorityKeyRecord{
		AuthorityID:    fb(0x10, 16),
		AuthorityKeyID: fb(0x11, 16),
		AuthorityRole:  0x01,
		PublicKey:      fuzzSamplePublicKeyRecord(),
		ValidFromUnix:  1,
		ValidUntilUnix: 2,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignDirectoryConsensus,
	}
}

func fuzzSampleObjectSignature() ObjectSignature {
	return ObjectSignature{
		SignerKeyID:     fb(0x12, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		Signature:       fb(0x13, 64),
	}
}

func fuzzSampleTokenVerificationKeyRecord() TokenVerificationKeyRecord {
	return TokenVerificationKeyRecord{
		TokenVerificationKeyScheme: registry.TokenKeyBlindRSA2048,
		TokenVerificationKey:       fb(0x14, 32),
	}
}

func fuzzSampleSignatureEntry() SignatureEntry {
	return SignatureEntry{
		AuthorityID:     fb(0x15, 16),
		AuthorityKeyID:  fb(0x16, 16),
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		Signature:       fb(0x17, 64),
	}
}

func fuzzSampleDirectoryConsensus() DirectoryConsensus {
	return DirectoryConsensus{
		Version:                 registry.Version20,
		Epoch:                   7,
		ValidFromUnix:           10,
		ValidUntilUnix:          20,
		PreviousConsensusHash:   fb(0x18, 48),
		RelayDescriptorRoot:     fb(0x19, 48),
		CoverTemplateFamilyRoot: fb(0x1a, 48),
		RevocationRoot:          fb(0x1b, 48),
		PolicyRoot:              fb(0x1c, 48),
		BridgeBucketCommitment:  fb(0x1d, 48),
		IssuerMetadataRoot:      fb(0x1e, 48),
		AuthoritySignatures:     []SignatureEntry{fuzzSampleSignatureEntry()},
	}
}

func fuzzSampleRoutingRecord() RoutingRecord {
	return RoutingRecord{
		RoutingRecordID:   fb(0x1f, 16),
		TransportFamilyID: registry.MethodWebH2Stream,
		LocatorType:       registry.LocatorIPv4Port,
		LocatorBody:       []byte{192, 0, 2, 1, 1, 187},
		Priority:          1,
		NotBeforeUnix:     10,
		NotAfterUnix:      20,
	}
}

func fuzzSampleRelayDescriptor() RelayDescriptor {
	return RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      fb(0x20, 32),
		RoleFlags:                    1,
		ValidFromUnix:                10,
		ValidUntilUnix:               20,
		RelayLongtermClassicalKey:    fuzzSamplePublicKeyRecord(),
		RelayLongtermPQKey:           fuzzSamplePublicKeyRecord(),
		EpochID:                      3,
		EpochAuthClassicalKey:        fuzzSamplePublicKeyRecord(),
		EpochAuthPQKey:               fuzzSamplePublicKeyRecord(),
		EpochValidFromUnix:           10,
		EpochValidUntilUnix:          20,
		ReplayEpochID:                4,
		ReplayEpochValidUntilUnix:    20,
		ReplayWindowID:               fb(0x21, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: fb(0x22, 48),
		SupportedShapeIDsCommitment:  fb(0x23, 48),
		PublicRoutingRecords:         []RoutingRecord{fuzzSampleRoutingRecord()},
		CoverTemplateInstanceHashes:  [][]byte{fb(0x24, 48)},
		ExitPolicyCommitment:         fb(0x25, 48),
		AbusePolicyCommitment:        fb(0x26, 48),
		SignatureByLongtermClassical: fb(0x27, 64),
		SignatureByLongtermPQ:        fb(0x28, 64),
	}
}

func fuzzSampleRequestClass() RequestClass {
	return RequestClass{
		ClassID:             1,
		ClassType:           registry.RequestGatewayOwnedSlot,
		AllowedMethodFamily: registry.MethodWebH2Stream,
		PathTemplateID:      fb(0x29, 16),
		BodyPolicyID:        1,
		ResponsePolicyID:    1,
		MayCarryPrelude:     true,
		MayCarryCapsule:     true,
	}
}

func fuzzSamplePreludeEnvelope() PreludeEnvelope {
	return PreludeEnvelope{
		MinRequestBodySize:         1536,
		MaxRequestBodySize:         4096,
		RequestSizeDistributionID:  fb(0x2a, 16),
		MinResponseBodySize:        6144,
		MaxResponseBodySize:        8192,
		ResponseSizeDistributionID: fb(0x2b, 16),
		ContentTypeFamilyID:        1,
		ChunkingPolicyID:           1,
		ResponseTimingPolicyID:     1,
	}
}

func fuzzSampleCapsuleEnvelope() CapsuleEnvelope {
	return CapsuleEnvelope{
		EnvelopeID:               fb(0x2c, 16),
		MinCapsuleBodySize:       2048,
		MaxCapsuleBodySize:       4096,
		BodySizeDistributionID:   fb(0x2d, 16),
		AllowedContentTypeIDs:    []uint64{1},
		ChunkingPolicyID:         1,
		FailureResponseFamilyID:  1,
		ConsumeFailedBodyLocally: true,
	}
}

func fuzzSampleH2CoverProfile() H2CoverProfile {
	return H2CoverProfile{
		ProfileID:                  1,
		H2SettingsFamilyID:         1,
		PseudoHeaderOrderFamilyID:  1,
		HPACKBehaviorFamilyID:      1,
		MaxConcurrentStreamsBucket: 1,
		InitialWindowBucket:        1,
		RequestGraphFamilyID:       1,
		RecordSizeDistributionID:   fb(0x2e, 16),
		IdleTimeoutPolicyID:        1,
	}
}

func fuzzSampleH3CoverProfile() H3CoverProfile {
	return H3CoverProfile{
		ProfileID:                  1,
		H3SettingsFamilyID:         1,
		QPACKBehaviorFamilyID:      1,
		SupportsH3Datagram:         true,
		SupportsWebTransportH3:     true,
		WebTransportProfileID:      1,
		QUICDatagramRequired:       true,
		ResetStreamAtRequired:      true,
		RequestGraphFamilyID:       1,
		DatagramSizeDistributionID: fb(0x2f, 16),
		DatagramRateDistributionID: fb(0x30, 16),
		FallbackMethodID:           registry.MethodWebH2Stream,
	}
}

func fuzzSampleWebSocketCoverProfile() WebSocketCoverProfile {
	return WebSocketCoverProfile{
		ProfileID:               1,
		UpgradeFamilyID:         1,
		SubprotocolFamilyID:     1,
		FrameSizeDistributionID: fb(0x31, 16),
		PingPolicyID:            1,
		CloseBehaviorID:         1,
		StreamLifetimePolicyID:  1,
	}
}

func fuzzSampleCacheCookiePolicy() CacheCookiePolicy {
	return CacheCookiePolicy{
		PolicyID:                 1,
		CookieBehaviorFamilyID:   1,
		CacheControlFamilyID:     1,
		ETagBehaviorFamilyID:     1,
		VaryHeaderFamilyID:       1,
		RedirectBehaviorFamilyID: 1,
	}
}

func fuzzSampleTimingEnvelope() TimingEnvelope {
	return TimingEnvelope{
		TimingPolicyID:       1,
		MinResponseDelayMS:   10,
		MaxResponseDelayMS:   50,
		JitterDistributionID: fb(0x32, 16),
		TimeoutFamilyID:      1,
		RetryFamilyID:        1,
		CloseTimingFamilyID:  1,
	}
}

func fuzzSampleCoverTemplate() CoverTemplate {
	return CoverTemplate{
		TemplateVersion:                  registry.Version20,
		TemplateID:                       fb(0x33, 16),
		TemplateFamilyID:                 fb(0x34, 16),
		ValidFromUnix:                    10,
		ValidUntilUnix:                   20,
		OriginSPKIHash:                   fb(0x35, 48),
		PublicNameHash:                   fb(0x36, 48),
		CoverOriginCommitment:            fb(0x37, 48),
		RequestClasses:                   []RequestClass{fuzzSampleRequestClass()},
		GatewayOwnedSlotCommitments:      [][]byte{fb(0x38, 48)},
		OriginPassThroughSlotCommitments: [][]byte{fb(0x39, 48)},
		PreludeEnvelope:                  fuzzSamplePreludeEnvelope(),
		CapsuleEnvelope:                  fuzzSampleCapsuleEnvelope(),
		H2Profile:                        fuzzSampleH2CoverProfile(),
		H3Profile:                        fuzzSampleH3CoverProfile(),
		WebSocketProfile:                 fuzzSampleWebSocketCoverProfile(),
		CacheCookiePolicy:                fuzzSampleCacheCookiePolicy(),
		TimingEnvelope:                   fuzzSampleTimingEnvelope(),
		TemplateFamilySignature:          fb(0x3a, 64),
		TemplateInstanceSignature:        fb(0x3b, 64),
	}
}

func fuzzSampleIssuerTokenKeyRecord() IssuerTokenKeyRecord {
	return IssuerTokenKeyRecord{
		ProofType:            registry.ProofBlindRSA2048,
		TokenKeyID:           fb(0x3c, 32),
		TokenVerificationKey: fuzzSampleTokenVerificationKeyRecord(),
		ValidFromUnix:        10,
		ValidUntilUnix:       20,
		KeyStatus:            registry.IssuerStatusActive,
	}
}

func fuzzSampleOriginInfoPolicy() OriginInfoPolicy {
	return OriginInfoPolicy{
		PolicyID:             1,
		OriginInfo:           []byte("origin"),
		AllowEmptyOriginInfo: true,
		ValidFromUnix:        10,
		ValidUntilUnix:       20,
	}
}

func fuzzSampleRelayBucketScope() RelayBucketScope {
	return RelayBucketScope{
		RelayBucketID:         fb(0x3d, 16),
		TokenScopeID:          fb(0x3e, 16),
		AllowedOriginPolicyID: []uint64{1},
		ValidFromUnix:         10,
		ValidUntilUnix:        20,
	}
}

func fuzzSampleAuxiliaryBindingPolicy() AuxiliaryBindingPolicy {
	return AuxiliaryBindingPolicy{
		ProofType:            registry.ProofOpaqueIssuer,
		BindingProofRequired: true,
		MaxBindingProofLen:   256,
		BindingPolicyID:      1,
	}
}

func fuzzSampleIssuerVerifierServiceRecord() IssuerVerifierServiceRecord {
	return IssuerVerifierServiceRecord{
		ServiceID:             fb(0x3f, 16),
		ServiceKind:           registry.VerifierServiceKindVOPRF,
		ServiceProtocolID:     registry.IssuerVerifierVOPRFMTLS13,
		ServiceLocator:        fuzzSampleRoutingRecord(),
		ServiceAuthKey:        fuzzSamplePublicKeyRecord(),
		AllowedProofTypes:     []uint64{registry.ProofVOPRFP384SHA384},
		AllowedRelayBucketIDs: [][]byte{fb(0x40, 16)},
		RequestAuthPolicyID:   1,
		ValidFromUnix:         10,
		ValidUntilUnix:        20,
		ServiceStatus:         registry.IssuerStatusActive,
	}
}

func fuzzSampleIssuerMetadata() IssuerMetadata {
	return IssuerMetadata{
		MetadataVersion:          registry.Version20,
		IssuerID:                 fb(0x41, 16),
		ValidFromUnix:            10,
		ValidUntilUnix:           20,
		IssuerName:               []byte("issuer"),
		SupportedProofTypes:      []uint64{registry.ProofBlindRSA2048},
		TokenKeyMappings:         []IssuerTokenKeyRecord{fuzzSampleIssuerTokenKeyRecord()},
		OriginInfoPolicies:       []OriginInfoPolicy{fuzzSampleOriginInfoPolicy()},
		RelayBucketScopes:        []RelayBucketScope{fuzzSampleRelayBucketScope()},
		AuxiliaryBindingPolicies: []AuxiliaryBindingPolicy{fuzzSampleAuxiliaryBindingPolicy()},
		VerifierServices:         []IssuerVerifierServiceRecord{fuzzSampleIssuerVerifierServiceRecord()},
		MetadataSigningKeyID:     fb(0x42, 16),
		SignatureScheme:          registry.SigECDSAP256SHA384DER,
		KeyEncoding:              registry.KeyP256SEC1Uncompressed,
		MetadataSignature:        fb(0x43, 64),
	}
}

func fuzzSampleIssuerVerifierRequest() IssuerVerifierRequest {
	return IssuerVerifierRequest{
		RequestVersion:            registry.Version20,
		ServiceID:                 fb(0x44, 16),
		IssuerID:                  fb(0x45, 16),
		IssuerMetadataHash:        fb(0x46, 48),
		RelayDescriptorHash:       fb(0x47, 48),
		RelayBucketID:             fb(0x48, 16),
		RouteInstanceID:           7,
		HopIndex:                  1,
		ProofType:                 registry.ProofVOPRFP384SHA384,
		TokenKeyID:                fb(0x49, 32),
		TokenNonce:                fb(0x4a, 32),
		ChallengeDigest:           fb(0x4b, 32),
		AuthenticatorInputHash:    fb(0x4c, 48),
		TokenAuthenticator:        fb(0x4d, 64),
		TokenSpentKey:             fb(0x4e, 48),
		ReplayEpochID:             9,
		ReplayEpochValidUntilUnix: 20,
		RequestNonce:              fb(0x4f, 32),
		RequestTimeUnix:           11,
	}
}

func fuzzSampleIssuerVerifierResponse() IssuerVerifierResponse {
	return IssuerVerifierResponse{
		ResponseVersion:  registry.Version20,
		ServiceID:        fb(0x50, 16),
		RequestHash:      fb(0x51, 48),
		Decision:         1,
		DecisionDetail:   0,
		TokenSpentKey:    fb(0x52, 48),
		ValidUntilUnix:   20,
		ResponseNonce:    fb(0x53, 32),
		ServiceSignature: fb(0x54, 64),
	}
}

func fuzzSampleAdmissionProof() AdmissionProof {
	return AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofOpaqueIssuer,
		IssuerID:              fb(0x55, 16),
		TokenKeyID:            fb(0x56, 32),
		RelayBucketID:         fb(0x57, 16),
		TokenScopeID:          fb(0x58, 16),
		ExpiryUnix:            20,
		TokenNonce:            fb(0x59, 32),
		RedemptionContextHash: fb(0x5a, 48),
		TokenPublicMetadata:   []byte("metadata"),
		TokenAuthenticator:    fb(0x5b, 64),
		BindingProof:          fb(0x5c, 32),
	}
}

func fuzzSampleAuroraTokenMetadata() AuroraTokenMetadata {
	return AuroraTokenMetadata{
		RFC9577TokenType:       uint16(registry.ProofBlindRSA2048),
		RFC9577ChallengeDigest: fb(0x5d, 32),
		RFC9577TokenKeyID:      fb(0x5e, 32),
		IssuerName:             []byte("issuer"),
		OriginInfo:             []byte("origin"),
		IssuerMetadataHash:     fb(0x5f, 48),
	}
}

func fuzzSampleReplayProof() ReplayProof {
	return ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       7,
		TokenRedemptionHash: fb(0x60, 48),
		ClientReplayNonce:   fb(0x61, 32),
		ReplayContextHash:   fb(0x62, 48),
		ReplayWindowID:      fb(0x63, 16),
	}
}

func fuzzSampleClientTransportHints() ClientTransportHints {
	return ClientTransportHints{
		NetworkCohortHint: []byte("cohort"),
		Padding:           fb(0x64, 4),
	}
}

func fuzzSamplePolicyOffer() PolicyOffer {
	return PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         registry.PolicyBalancedWeb,
		RequestedPolicyID:       registry.PolicyBalancedWeb,
		RequestedRouteModeID:    registry.RouteFast1,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		FlowCapabilities:        1,
		MaxPaddingOverheadPct:   20,
	}
}

func fuzzSampleVirtualAddressAssignment() VirtualAddressAssignment {
	return VirtualAddressAssignment{
		LeaseID:         fb(0x65, 16),
		AddressFamily:   4,
		ClientAddress:   []byte{10, 0, 0, 2},
		PrefixLength:    24,
		DNSServerHint:   []byte{10, 0, 0, 1},
		LeaseExpiryUnix: 20,
	}
}

func fuzzSamplePolicyAccept() PolicyAccept {
	return PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyBalancedWeb,
		SelectedRouteModeID:       registry.RouteFast1,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
		FallbackMethods:           []uint64{registry.MethodWebH1WS},
		RetryPolicyID:             1,
		PathValidationPolicyID:    1,
	}
}

func fuzzSampleCoverPrelude0() CoverPrelude0 {
	return CoverPrelude0{
		MsgType:                     1,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{registry.SuiteHybrid768AESGCM},
		ClientNonce:                 fb(0x66, 32),
		ClientClassicalEphPub:       fb(0x67, 32),
		ClientMLKEMEncapsulationKey: fb(0x68, 1184),
		RelayDescriptorHash:         fb(0x69, 48),
		CoverTemplateHash:           fb(0x6a, 48),
		RequestClassID:              1,
		HintIssuerID:                fb(0x6b, 16),
		RelayBucketID:               fb(0x6c, 16),
		HintEpochID:                 3,
		HintSelector:                fb(0x6d, 16),
		AccessHint:                  fb(0x6e, 16),
		ClientCoverRandom:           fb(0x6f, 32),
		Padding:                     fb(0x70, 8),
	}
}

func fuzzSampleCoverPrelude1() CoverPrelude1 {
	return CoverPrelude1{
		MsgType:                         2,
		Version:                         registry.Version20,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		RelayDescriptorHash:             fb(0x71, 48),
		CoverTemplateHash:               fb(0x72, 48),
		RelayEpochID:                    3,
		ServerNonce:                     fb(0x73, 32),
		ServerClassicalEphPub:           fb(0x74, 32),
		ServerMLKEMCiphertextToClient:   fb(0x75, 1088),
		SelectedCoverProfileID:          fb(0x76, 16),
		SelectedBootstrapEnvelopeID:     fb(0x77, 16),
		ServerPreludeSignatureClassical: fb(0x78, 64),
		ServerPreludeSignaturePQ:        fb(0x79, 3309),
		ResponsePadding:                 fb(0x7a, 8),
	}
}

func fuzzSampleCoverCapsule1Plain() CoverCapsule1Plain {
	return CoverCapsule1Plain{
		MsgType:              3,
		RouteInstanceID:      7,
		AdmissionProof:       fuzzSampleAdmissionProof(),
		ReplayProof:          fuzzSampleReplayProof(),
		PolicyOffer:          fuzzSamplePolicyOffer(),
		ClientTransportHints: fuzzSampleClientTransportHints(),
		ClientFinished:       fb(0x7b, 48),
		Padding:              fb(0x7c, 8),
	}
}

func fuzzSampleCoverCapsule2Plain() CoverCapsule2Plain {
	return CoverCapsule2Plain{
		MsgType:         4,
		RouteInstanceID: 7,
		PolicyAccept:    fuzzSamplePolicyAccept(),
		ServerFinished:  fb(0x7d, 48),
		Padding:         fb(0x7e, 8),
	}
}

func fuzzSampleRouteCapsule1Plain() RouteCapsule1Plain {
	return RouteCapsule1Plain{
		MsgType:         5,
		RouteInstanceID: 7,
		HopIndex:        1,
		AdmissionProof:  fuzzSampleAdmissionProof(),
		ReplayProof:     fuzzSampleReplayProof(),
		PolicyOffer:     fuzzSamplePolicyOffer(),
		ClientFinished:  fb(0x7f, 48),
		Padding:         fb(0x80, 8),
	}
}

func fuzzSampleRouteCapsule2Plain() RouteCapsule2Plain {
	return RouteCapsule2Plain{
		MsgType:         6,
		RouteInstanceID: 7,
		HopIndex:        1,
		PolicyAccept:    fuzzSamplePolicyAccept(),
		ServerFinished:  fb(0x81, 48),
		Padding:         fb(0x82, 8),
	}
}

func fuzzSampleRoutePrelude1() RoutePrelude1 {
	return RoutePrelude1{
		MsgType:                         7,
		Version:                         registry.Version20,
		RouteInstanceID:                 7,
		HopIndex:                        1,
		PreviousHopRelayDescriptorHash:  fb(0x83, 48),
		NextRelayDescriptorHash:         fb(0x84, 48),
		NextRelayEpochID:                3,
		SelectedSuite:                   registry.SuiteHybrid768AESGCM,
		ServerNonce:                     fb(0x85, 32),
		ServerClassicalEphPub:           fb(0x86, 32),
		ServerMLKEMCiphertextToClient:   fb(0x87, 1088),
		SelectedShapeID:                 registry.ShapeNormal,
		ServerPreludeSignatureClassical: fb(0x88, 64),
		ServerPreludeSignaturePQ:        fb(0x89, 3309),
		Padding:                         fb(0x8a, 8),
	}
}

func fuzzSampleAuroraFrame() AuroraFrame {
	payload, err := Encode(fuzzSampleFlowClose())
	if err != nil {
		panic(err)
	}
	return AuroraFrame{
		FrameType: registry.FrameFlowClose,
		FlowID:    7,
		Payload:   payload,
	}
}

func fuzzSampleFrameBlock() FrameBlock {
	return FrameBlock{Frames: []AuroraFrame{fuzzSampleAuroraFrame()}}
}

func fuzzSampleKeyUpdate() KeyUpdate {
	return KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     fb(0x8b, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
}

func fuzzSampleKeyUpdateACK() KeyUpdateACK {
	return KeyUpdateACK{
		RouteInstanceID: 7,
		HopLayer:        1,
		AckedDirection:  0,
		AckedKeyPhase:   1,
		AckNonce:        fb(0x8c, 16),
	}
}

func fuzzSampleKeyUpdateRequest() KeyUpdateRequest {
	return KeyUpdateRequest{
		RouteInstanceID:    7,
		HopLayer:           1,
		RequestedDirection: 0,
		RequestNonce:       fb(0x8d, 16),
		RequestReason:      1,
	}
}

func fuzzSampleFlowOpen() FlowOpen {
	return FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           7,
		FlowKind:         1,
		TargetKind:       1,
		TargetHost:       []byte{203, 0, 113, 1},
		TargetPort:       443,
		UDPFQDNMode:      0,
		NameBindingID:    fb(0x8e, 16),
		DNSAnswerSetHash: fb(0x8f, 48),
		LocalBindingMode: 1,
		PriorityClass:    1,
	}
}

func fuzzSampleUDPTargetConfirm() UDPTargetConfirm {
	return UDPTargetConfirm{
		FlowID:           7,
		TargetKind:       1,
		SelectedIP:       []byte{203, 0, 113, 1},
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0x90, 48),
		TTLSeconds:       60,
		ResolutionSource: UDPResolutionClientSuppliedIP,
	}
}

func fuzzSampleFlowClose() FlowClose {
	return FlowClose{
		FlowID:                   7,
		CloseCode:                CloseNormal,
		FinalSequenceHintPresent: true,
		FinalSequenceHint:        12,
		Reason:                   []byte("done"),
	}
}

func fuzzSampleRouteForwardFrame() RouteForwardFrame {
	return RouteForwardFrame{
		RouteInstanceID:                7,
		HopIndex:                       1,
		NextRelayDescriptorHash:        fb(0x91, 48),
		PreviousHopRelayDescriptorHash: fb(0x92, 48),
		NextRelayRoutingRecordID:       fb(0x93, 16),
		NextRelayLocatorType:           registry.LocatorIPv4Port,
		NextRelayLocator:               []byte{192, 0, 2, 1, 1, 187},
		OpaqueNextHopPrelude:           fb(0x94, 64),
	}
}

func fuzzSampleRoutePreludeEnvelope() RoutePreludeEnvelope {
	return RoutePreludeEnvelope{
		RouteInstanceID:                7,
		HopIndex:                       1,
		PreviousHopRelayDescriptorHash: fb(0x95, 48),
		NextRelayDescriptorHash:        fb(0x96, 48),
		HintIssuerID:                   fb(0x97, 16),
		RelayBucketID:                  fb(0x98, 16),
		HintEpochID:                    3,
		HintSelector:                   fb(0x99, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      fb(0x9a, 16),
		SealedRoutePrelude0:            fb(0x9b, 64),
	}
}
