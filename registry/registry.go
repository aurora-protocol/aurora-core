package registry

const Version20 uint64 = 0x000200

const (
	SuiteHybrid768AESGCM       uint64 = 0x0001
	SuiteHybrid768P256AESGCM   uint64 = 0x0002
	SuiteHybrid1024AESGCM      uint64 = 0x0003
	SuiteHybrid768ChaCha20     uint64 = 0x0004
	SuiteHybrid768P256ChaCha20 uint64 = 0x0005
	SuiteHybrid1024ChaCha20    uint64 = 0x0006
	SuiteLabClassical          uint64 = 0x00ff
)

const (
	PolicyFastWeb           uint64 = 0x01
	PolicyBalancedWeb       uint64 = 0x02
	PolicyAdversarialDPI    uint64 = 0x03
	PolicyAdversarialStrict uint64 = 0x04
	PolicyEmergencyWeb      uint64 = 0x05
	PolicyLab               uint64 = 0x7f
)

const (
	RouteFast1       uint64 = 0x01
	RouteSplit2      uint64 = 0x02
	RouteSafe3       uint64 = 0x03
	RouteBridgeSplit uint64 = 0x04
	RouteAuto        uint64 = 0x05
)

const (
	PersonalityProxyFlow uint64 = 0x01
	PersonalityIPLite    uint64 = 0x02
	PersonalityFullIP    uint64 = 0x03
)

const (
	ShapeLight     uint64 = 0x01
	ShapeNormal    uint64 = 0x02
	ShapeStrict    uint64 = 0x03
	ShapeEmergency uint64 = 0x04
)

const (
	LocatorIPv4Port  uint64 = 0x01
	LocatorIPv6Port  uint64 = 0x02
	LocatorAuthority uint64 = 0x03
	LocatorOpaque    uint64 = 0x04
)

const (
	RequestOriginPassThrough uint64 = 0x01
	RequestGatewayOwnedSlot  uint64 = 0x02
	RequestSidecarOriginSlot uint64 = 0x03
)

const (
	MethodWebH2Stream      uint64 = 0x1001
	MethodWebH1WS          uint64 = 0x1002
	MethodShadowOrigin     uint64 = 0x1003
	MethodWebH3Stream      uint64 = 0x1004
	MethodWebH3ExtDgram    uint64 = 0x1005
	MethodMasqueConnectIP  uint64 = 0x2001
	MethodMasqueConnectUDP uint64 = 0x2002
	MethodDirectQUICLab    uint64 = 0x7f01
)

const (
	ProofVOPRFP384SHA384 uint64 = 0x0001
	ProofBlindRSA2048    uint64 = 0x0002
	ProofOpaqueIssuer    uint64 = 0x0003
	ProofLabStaticToken  uint64 = 0x7fff
)

const WrapSuiteRouteV1 uint64 = 0x9001

const (
	SigECDSAP256SHA256DER uint64 = 0x0101
	SigECDSAP256SHA384DER uint64 = 0x0102
	SigECDSAP384SHA384DER uint64 = 0x0103
	SigMLDSA65            uint64 = 0x0201
	SigMLDSA87            uint64 = 0x0202
	SigEd25519Lab         uint64 = 0x7f01
)

const (
	KeyP256SEC1Uncompressed uint64 = 0x0001
	KeyP256SPKI             uint64 = 0x0002
	KeyP384SEC1Uncompressed uint64 = 0x0003
	KeyP384SPKI             uint64 = 0x0004
	KeyMLDSA65RawPublic     uint64 = 0x0005
	KeyMLDSA87RawPublic     uint64 = 0x0006
	KeyEd25519RawPublic     uint64 = 0x7f01
)

const (
	TokenKeyVOPRFP384SHA384 uint64 = 0x0001
	TokenKeyBlindRSA2048    uint64 = 0x0002
	TokenKeyLabStaticNoKey  uint64 = 0x7f01
)

const IssuerVerifierVOPRFMTLS13 uint64 = 0x0001

const (
	FrameStreamData       uint64 = 0x01
	FrameDatagramData     uint64 = 0x02
	FrameIPPacket         uint64 = 0x03
	FrameDNSMessage       uint64 = 0x04
	FrameControl          uint64 = 0x05
	FramePathProbe        uint64 = 0x06
	FrameKeyUpdate        uint64 = 0x07
	FramePadding          uint64 = 0x08
	FrameClose            uint64 = 0x09
	FrameRouteForward     uint64 = 0x0a
	FramePriorityUpdate   uint64 = 0x0b
	FrameAckHint          uint64 = 0x0c
	FrameKeyUpdateAck     uint64 = 0x0d
	FrameKeyUpdateRequest uint64 = 0x0e
	FrameFlowOpen         uint64 = 0x0f
	FrameUDPTargetConfirm uint64 = 0x10
	FrameFlowClose        uint64 = 0x11
)

const (
	AuthorityActive             uint8 = 0x00
	AuthorityRetiringVerifyOnly uint8 = 0x01
	AuthorityRevoked            uint8 = 0x02
)

const (
	UsageMaySignDirectoryConsensus   uint32 = 0x00000001
	UsageMaySignBridgeBundle         uint32 = 0x00000002
	UsageMaySignSignedSeedRecord     uint32 = 0x00000004
	UsageMaySignIssuerMetadata       uint32 = 0x00000008
	UsageMayDelegatePrivateBridge    uint32 = 0x00000010
	UsageMayRotateDirectoryAuthority uint32 = 0x00000020
	UsageAllKnownAuthority           uint32 = 0x0000003f
)

const (
	MsgCoverPrelude0 uint64 = 0x0101
	MsgCoverPrelude1 uint64 = 0x0102
	MsgCoverCapsule1 uint64 = 0x0103
	MsgCoverCapsule2 uint64 = 0x0104
	MsgRoutePrelude0 uint64 = 0x0201
	MsgRoutePrelude1 uint64 = 0x0202
	MsgRouteCapsule1 uint64 = 0x0203
	MsgRouteCapsule2 uint64 = 0x0204
)
