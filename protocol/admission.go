package protocol

import (
	"bytes"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type AdmissionProof struct {
	ProofVersion          uint64
	ProofType             uint64
	IssuerID              []byte
	TokenKeyID            []byte
	RelayBucketID         []byte
	TokenScopeID          []byte
	ExpiryUnix            uint64
	TokenNonce            []byte
	RedemptionContextHash []byte
	TokenPublicMetadata   []byte
	TokenAuthenticator    []byte
	BindingProof          []byte
	Extensions            []Extension
}

type ProofValidationOptions struct {
	AllowLabProofs         bool
	AllowPrivateProofTypes bool
}

func (p AdmissionProof) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.ProofVersion)
	e.WriteVarint(p.ProofType)
	e.WriteOpaqueFixed(p.IssuerID, 16)
	e.WriteOpaqueFixed(p.TokenKeyID, 32)
	e.WriteOpaqueFixed(p.RelayBucketID, 16)
	e.WriteOpaqueFixed(p.TokenScopeID, 16)
	e.WriteUint64(p.ExpiryUnix)
	e.WriteOpaqueFixed(p.TokenNonce, 32)
	e.WritePreHash(p.RedemptionContextHash)
	e.WriteOpaque16(p.TokenPublicMetadata)
	e.WriteOpaque16(p.TokenAuthenticator)
	e.WriteOpaque16(p.BindingProof)
	EncodeExtensions(e, p.Extensions)
}

func DecodeAdmissionProof(r *wire.Reader) AdmissionProof {
	return AdmissionProof{
		ProofVersion:          r.ReadVarint(),
		ProofType:             r.ReadVarint(),
		IssuerID:              r.ReadOpaqueFixed(16),
		TokenKeyID:            r.ReadOpaqueFixed(32),
		RelayBucketID:         r.ReadOpaqueFixed(16),
		TokenScopeID:          r.ReadOpaqueFixed(16),
		ExpiryUnix:            r.ReadUint64(),
		TokenNonce:            r.ReadOpaqueFixed(32),
		RedemptionContextHash: r.ReadPreHash(),
		TokenPublicMetadata:   r.ReadOpaque16(),
		TokenAuthenticator:    r.ReadOpaque16(),
		BindingProof:          r.ReadOpaque16(),
		Extensions:            DecodeExtensions(r),
	}
}

func (p AdmissionProof) ValidateStructural(now uint64, allowLab bool) error {
	return p.ValidateStructuralWithOptions(now, ProofValidationOptions{AllowLabProofs: allowLab})
}

func (p AdmissionProof) ValidateStructuralWithOptions(now uint64, opts ProofValidationOptions) error {
	if p.ProofVersion != registry.Version20 {
		return fmt.Errorf("protocol: unsupported admission proof version 0x%x", p.ProofVersion)
	}
	if now >= p.ExpiryUnix {
		return fmt.Errorf("protocol: admission proof expired")
	}
	switch p.ProofType {
	case registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048:
	case registry.ProofOpaqueIssuer:
		if !opts.AllowPrivateProofTypes {
			return fmt.Errorf("protocol: private admission proof type 0x%x disabled", p.ProofType)
		}
	case registry.ProofLabStaticToken:
		if !opts.AllowLabProofs {
			return fmt.Errorf("protocol: lab admission proof disabled")
		}
	default:
		return fmt.Errorf("protocol: unknown admission proof type 0x%x", p.ProofType)
	}
	if len(p.IssuerID) != 16 {
		return fmt.Errorf("protocol: issuer id must be 16 bytes")
	}
	if len(p.TokenKeyID) != 32 {
		return fmt.Errorf("protocol: token key id must be 32 bytes")
	}
	if len(p.RelayBucketID) != 16 {
		return fmt.Errorf("protocol: relay bucket id must be 16 bytes")
	}
	if len(p.TokenScopeID) != 16 {
		return fmt.Errorf("protocol: token scope id must be 16 bytes")
	}
	if len(p.TokenNonce) != 32 {
		return fmt.Errorf("protocol: token nonce must be 32 bytes")
	}
	if len(p.RedemptionContextHash) != 48 {
		return fmt.Errorf("protocol: redemption context hash must be 48 bytes")
	}
	switch p.ProofType {
	case registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048, registry.ProofLabStaticToken:
		if len(p.BindingProof) != 0 {
			return fmt.Errorf("protocol: proof type 0x%x requires zero-length binding proof without issuer profile", p.ProofType)
		}
	}
	switch p.ProofType {
	case registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048:
		metadata, err := DecodeAuroraTokenMetadataBytes(p.TokenPublicMetadata)
		if err != nil {
			return fmt.Errorf("protocol: invalid production token metadata: %w", err)
		}
		if err := metadata.ValidateForProof(p, metadata.IssuerMetadataHash); err != nil {
			return err
		}
	}
	if p.ProofType == registry.ProofOpaqueIssuer && len(p.BindingProof) > 4096 {
		return fmt.Errorf("protocol: opaque issuer binding proof length %d exceeds 4096", len(p.BindingProof))
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type AuroraTokenMetadata struct {
	RFC9577TokenType       uint16
	RFC9577ChallengeDigest []byte
	RFC9577TokenKeyID      []byte
	IssuerName             []byte
	OriginInfo             []byte
	IssuerMetadataHash     []byte
}

func (m AuroraTokenMetadata) EncodeTo(e *wire.Encoder) {
	e.WriteUint16(m.RFC9577TokenType)
	e.WriteOpaqueFixed(m.RFC9577ChallengeDigest, 32)
	e.WriteOpaqueFixed(m.RFC9577TokenKeyID, 32)
	e.WriteOpaque16(m.IssuerName)
	e.WriteOpaque16(m.OriginInfo)
	e.WritePreHash(m.IssuerMetadataHash)
}

func DecodeAuroraTokenMetadata(r *wire.Reader) AuroraTokenMetadata {
	return AuroraTokenMetadata{
		RFC9577TokenType:       r.ReadUint16(),
		RFC9577ChallengeDigest: r.ReadOpaqueFixed(32),
		RFC9577TokenKeyID:      r.ReadOpaqueFixed(32),
		IssuerName:             r.ReadOpaque16(),
		OriginInfo:             r.ReadOpaque16(),
		IssuerMetadataHash:     r.ReadPreHash(),
	}
}

func DecodeAuroraTokenMetadataBytes(encoded []byte) (AuroraTokenMetadata, error) {
	r := wire.NewReader(encoded)
	out := DecodeAuroraTokenMetadata(r)
	if err := r.Err(); err != nil {
		return AuroraTokenMetadata{}, err
	}
	if !r.EOF() {
		return AuroraTokenMetadata{}, fmt.Errorf("protocol: trailing token metadata bytes")
	}
	return out, nil
}

func (m AuroraTokenMetadata) ValidateForProof(proof AdmissionProof, issuerMetadataHash []byte) error {
	if proof.ProofType > 0xffff {
		return fmt.Errorf("protocol: proof type 0x%x does not fit RFC token type", proof.ProofType)
	}
	if uint64(m.RFC9577TokenType) != proof.ProofType {
		return fmt.Errorf("protocol: token metadata proof type mismatch")
	}
	if len(m.RFC9577ChallengeDigest) != 32 {
		return fmt.Errorf("protocol: token metadata challenge digest must be 32 bytes")
	}
	if !bytes.Equal(m.RFC9577TokenKeyID, proof.TokenKeyID) {
		return fmt.Errorf("protocol: token metadata token key id mismatch")
	}
	if len(m.IssuerName) == 0 {
		return fmt.Errorf("protocol: token metadata issuer name is empty")
	}
	if !bytes.Equal(m.IssuerMetadataHash, issuerMetadataHash) {
		return fmt.Errorf("protocol: token metadata issuer metadata hash mismatch")
	}
	return nil
}

type ReplayProof struct {
	ProofVersion        uint64
	ReplayEpochID       uint64
	TokenRedemptionHash []byte
	ClientReplayNonce   []byte
	ReplayContextHash   []byte
	ReplayWindowID      []byte
	Extensions          []Extension
}

func (p ReplayProof) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.ProofVersion)
	e.WriteUint64(p.ReplayEpochID)
	e.WritePreHash(p.TokenRedemptionHash)
	e.WriteOpaqueFixed(p.ClientReplayNonce, 32)
	e.WritePreHash(p.ReplayContextHash)
	e.WriteOpaqueFixed(p.ReplayWindowID, 16)
	EncodeExtensions(e, p.Extensions)
}

func DecodeReplayProof(r *wire.Reader) ReplayProof {
	return ReplayProof{
		ProofVersion:        r.ReadVarint(),
		ReplayEpochID:       r.ReadUint64(),
		TokenRedemptionHash: r.ReadPreHash(),
		ClientReplayNonce:   r.ReadOpaqueFixed(32),
		ReplayContextHash:   r.ReadPreHash(),
		ReplayWindowID:      r.ReadOpaqueFixed(16),
		Extensions:          DecodeExtensions(r),
	}
}

func (p ReplayProof) ValidateStructural() error {
	if p.ProofVersion != registry.Version20 {
		return fmt.Errorf("protocol: unsupported replay proof version 0x%x", p.ProofVersion)
	}
	if len(p.TokenRedemptionHash) != 48 {
		return fmt.Errorf("protocol: replay token redemption hash must be 48 bytes")
	}
	if len(p.ClientReplayNonce) != 32 {
		return fmt.Errorf("protocol: client replay nonce must be 32 bytes")
	}
	if len(p.ReplayContextHash) != 48 {
		return fmt.Errorf("protocol: replay context hash must be 48 bytes")
	}
	if len(p.ReplayWindowID) != 16 {
		return fmt.Errorf("protocol: replay window id must be 16 bytes")
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type ClientTransportHints struct {
	HintFlags              uint16
	ObservedPathMTUBucket  uint8
	RecentQUICResult       uint8
	RecentH2Result         uint8
	CongestionClass        uint8
	MaxDatagramPayloadHint uint16
	NetworkCohortHint      []byte
	Padding                []byte
	Extensions             []Extension
}

func EmptyClientTransportHints() ClientTransportHints {
	return ClientTransportHints{}
}

func (h ClientTransportHints) EncodeTo(e *wire.Encoder) {
	e.WriteUint16(h.HintFlags)
	e.WriteUint8(h.ObservedPathMTUBucket)
	e.WriteUint8(h.RecentQUICResult)
	e.WriteUint8(h.RecentH2Result)
	e.WriteUint8(h.CongestionClass)
	e.WriteUint16(h.MaxDatagramPayloadHint)
	e.WriteOpaque8(h.NetworkCohortHint)
	e.WriteOpaque16(h.Padding)
	EncodeExtensions(e, h.Extensions)
}

func DecodeClientTransportHints(r *wire.Reader) ClientTransportHints {
	return ClientTransportHints{
		HintFlags:              r.ReadUint16(),
		ObservedPathMTUBucket:  r.ReadUint8(),
		RecentQUICResult:       r.ReadUint8(),
		RecentH2Result:         r.ReadUint8(),
		CongestionClass:        r.ReadUint8(),
		MaxDatagramPayloadHint: r.ReadUint16(),
		NetworkCohortHint:      r.ReadOpaque8(),
		Padding:                r.ReadOpaque16(),
		Extensions:             DecodeExtensions(r),
	}
}

func (h ClientTransportHints) ValidatePrototype() error {
	if h.HintFlags != 0 {
		return fmt.Errorf("protocol: client transport hint_flags must be zero")
	}
	if len(h.NetworkCohortHint) > 16 {
		return fmt.Errorf("protocol: network_cohort_hint length %d exceeds 16", len(h.NetworkCohortHint))
	}
	if err := ValidateExtensions(h.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func (h ClientTransportHints) NormalizePrototype() ClientTransportHints {
	if h.RecentQUICResult > 0x05 {
		h.RecentQUICResult = 0x00
	}
	if h.RecentH2Result > 0x05 {
		h.RecentH2Result = 0x00
	}
	return h
}

type PolicyOffer struct {
	OfferedVersions         []uint64
	OfferedSuites           []uint64
	OfferedMethods          []uint64
	MinimumPolicyID         uint64
	RequestedPolicyID       uint64
	RequestedRouteModeID    uint64
	RequestedShapeID        uint64
	TunnelPersonalityOffers []uint64
	FlowCapabilities        uint64
	MaxPaddingOverheadPct   uint8
	Extensions              []Extension
}

func (p PolicyOffer) EncodeTo(e *wire.Encoder) {
	e.WriteVarintVector(p.OfferedVersions)
	e.WriteVarintVector(p.OfferedSuites)
	e.WriteVarintVector(p.OfferedMethods)
	e.WriteVarint(p.MinimumPolicyID)
	e.WriteVarint(p.RequestedPolicyID)
	e.WriteVarint(p.RequestedRouteModeID)
	e.WriteVarint(p.RequestedShapeID)
	e.WriteVarintVector(p.TunnelPersonalityOffers)
	e.WriteUint64(p.FlowCapabilities)
	e.WriteUint8(p.MaxPaddingOverheadPct)
	EncodeExtensions(e, p.Extensions)
}

func DecodePolicyOffer(r *wire.Reader) PolicyOffer {
	return PolicyOffer{
		OfferedVersions:         r.ReadVarintVector(),
		OfferedSuites:           r.ReadVarintVector(),
		OfferedMethods:          r.ReadVarintVector(),
		MinimumPolicyID:         r.ReadVarint(),
		RequestedPolicyID:       r.ReadVarint(),
		RequestedRouteModeID:    r.ReadVarint(),
		RequestedShapeID:        r.ReadVarint(),
		TunnelPersonalityOffers: r.ReadVarintVector(),
		FlowCapabilities:        r.ReadUint64(),
		MaxPaddingOverheadPct:   r.ReadUint8(),
		Extensions:              DecodeExtensions(r),
	}
}

func (p PolicyOffer) ValidateStructural() error {
	for _, version := range p.OfferedVersions {
		if err := validateVersionKnown(version); err != nil {
			return err
		}
	}
	for _, suite := range p.OfferedSuites {
		if err := validateSuiteKnown(suite); err != nil {
			return err
		}
	}
	for _, method := range p.OfferedMethods {
		if err := validateMethodKnown(method); err != nil {
			return err
		}
	}
	if err := validatePolicyKnown(p.MinimumPolicyID); err != nil {
		return err
	}
	if err := validatePolicyKnown(p.RequestedPolicyID); err != nil {
		return err
	}
	if err := validateRouteModeKnown(p.RequestedRouteModeID); err != nil {
		return err
	}
	if err := validateShapeKnown(p.RequestedShapeID); err != nil {
		return err
	}
	for _, personality := range p.TunnelPersonalityOffers {
		if err := validateTunnelPersonalityKnown(personality); err != nil {
			return err
		}
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type VirtualAddressAssignment struct {
	LeaseID         []byte
	AddressFamily   uint64
	ClientAddress   []byte
	PrefixLength    uint8
	DNSServerHint   []byte
	LeaseExpiryUnix uint64
}

func (v VirtualAddressAssignment) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(v.LeaseID, 16)
	e.WriteVarint(v.AddressFamily)
	e.WriteOpaque8(v.ClientAddress)
	e.WriteUint8(v.PrefixLength)
	if v.DNSServerHint == nil {
		e.WriteBool(false)
	} else {
		e.WriteBool(true)
		e.WriteOpaque8(v.DNSServerHint)
	}
	e.WriteUint64(v.LeaseExpiryUnix)
}

func DecodeVirtualAddressAssignment(r *wire.Reader) VirtualAddressAssignment {
	out := VirtualAddressAssignment{
		LeaseID:       r.ReadOpaqueFixed(16),
		AddressFamily: r.ReadVarint(),
		ClientAddress: r.ReadOpaque8(),
		PrefixLength:  r.ReadUint8(),
	}
	if r.ReadBool() {
		out.DNSServerHint = r.ReadOpaque8()
	}
	out.LeaseExpiryUnix = r.ReadUint64()
	return out
}

type PolicyAccept struct {
	SelectedVersion           uint64
	SelectedSuite             uint64
	SelectedMethod            uint64
	SelectedPolicy            uint64
	SelectedRouteModeID       uint64
	SelectedShape             uint64
	SelectedTunnelPersonality uint64
	FallbackMethods           []uint64
	RetryPolicyID             uint64
	PathValidationPolicyID    uint64
	VirtualAddressAssignment  *VirtualAddressAssignment
	Extensions                []Extension
}

func (p PolicyAccept) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.SelectedVersion)
	e.WriteVarint(p.SelectedSuite)
	e.WriteVarint(p.SelectedMethod)
	e.WriteVarint(p.SelectedPolicy)
	e.WriteVarint(p.SelectedRouteModeID)
	e.WriteVarint(p.SelectedShape)
	e.WriteVarint(p.SelectedTunnelPersonality)
	e.WriteVarintVector(p.FallbackMethods)
	e.WriteVarint(p.RetryPolicyID)
	e.WriteVarint(p.PathValidationPolicyID)
	if p.VirtualAddressAssignment == nil {
		e.WriteUint8(0)
	} else {
		e.WriteUint8(1)
		p.VirtualAddressAssignment.EncodeTo(e)
	}
	EncodeExtensions(e, p.Extensions)
}

func DecodePolicyAccept(r *wire.Reader) PolicyAccept {
	out := PolicyAccept{
		SelectedVersion:           r.ReadVarint(),
		SelectedSuite:             r.ReadVarint(),
		SelectedMethod:            r.ReadVarint(),
		SelectedPolicy:            r.ReadVarint(),
		SelectedRouteModeID:       r.ReadVarint(),
		SelectedShape:             r.ReadVarint(),
		SelectedTunnelPersonality: r.ReadVarint(),
		FallbackMethods:           r.ReadVarintVector(),
		RetryPolicyID:             r.ReadVarint(),
		PathValidationPolicyID:    r.ReadVarint(),
	}
	if r.ReadBool() {
		assignment := DecodeVirtualAddressAssignment(r)
		out.VirtualAddressAssignment = &assignment
	}
	out.Extensions = DecodeExtensions(r)
	return out
}

func (p PolicyAccept) ValidateStructural() error {
	if err := validateVersionKnown(p.SelectedVersion); err != nil {
		return err
	}
	if err := validateSuiteKnown(p.SelectedSuite); err != nil {
		return err
	}
	if err := validateMethodKnown(p.SelectedMethod); err != nil {
		return err
	}
	if err := validatePolicyKnown(p.SelectedPolicy); err != nil {
		return err
	}
	if err := validateRouteModeKnown(p.SelectedRouteModeID); err != nil {
		return err
	}
	if err := validateShapeKnown(p.SelectedShape); err != nil {
		return err
	}
	switch p.SelectedTunnelPersonality {
	case registry.PersonalityProxyFlow:
		if p.VirtualAddressAssignment != nil {
			return fmt.Errorf("protocol: proxy-flow policy accept must not carry virtual address assignment")
		}
	case registry.PersonalityIPLite, registry.PersonalityFullIP:
		if p.VirtualAddressAssignment == nil {
			return fmt.Errorf("protocol: IP policy accept requires virtual address assignment")
		}
	default:
		return fmt.Errorf("protocol: reserved tunnel personality 0x%x", p.SelectedTunnelPersonality)
	}
	for _, method := range p.FallbackMethods {
		if err := validateMethodKnown(method); err != nil {
			return err
		}
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func (p PolicyAccept) ValidateForOffer(offer PolicyOffer) error {
	if err := offer.ValidateStructural(); err != nil {
		return err
	}
	if err := p.ValidateStructural(); err != nil {
		return err
	}
	if !containsUint64(offer.OfferedVersions, p.SelectedVersion) {
		return fmt.Errorf("protocol: selected version 0x%x was not offered", p.SelectedVersion)
	}
	if !containsUint64(offer.OfferedSuites, p.SelectedSuite) {
		return fmt.Errorf("protocol: selected suite 0x%x was not offered", p.SelectedSuite)
	}
	if !containsUint64(offer.OfferedMethods, p.SelectedMethod) {
		return fmt.Errorf("protocol: selected method 0x%x was not offered", p.SelectedMethod)
	}
	if p.SelectedPolicy < offer.MinimumPolicyID {
		return fmt.Errorf("protocol: selected policy 0x%x is weaker than minimum 0x%x", p.SelectedPolicy, offer.MinimumPolicyID)
	}
	if !containsUint64(offer.TunnelPersonalityOffers, p.SelectedTunnelPersonality) {
		return fmt.Errorf("protocol: selected tunnel personality 0x%x was not offered", p.SelectedTunnelPersonality)
	}
	return nil
}

func containsUint64(xs []uint64, want uint64) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func validateVersionKnown(version uint64) error {
	if version == registry.Version20 {
		return nil
	}
	return fmt.Errorf("protocol: reserved version 0x%x", version)
}

func validateSuiteKnown(suite uint64) error {
	switch suite {
	case registry.SuiteHybrid768AESGCM,
		registry.SuiteHybrid768P256AESGCM,
		registry.SuiteHybrid1024AESGCM,
		registry.SuiteHybrid768ChaCha20,
		registry.SuiteHybrid768P256ChaCha20,
		registry.SuiteHybrid1024ChaCha20,
		registry.SuiteLabClassical:
		return nil
	default:
		return fmt.Errorf("protocol: reserved suite 0x%x", suite)
	}
}

func validatePolicyKnown(policy uint64) error {
	switch policy {
	case registry.PolicyFastWeb,
		registry.PolicyBalancedWeb,
		registry.PolicyAdversarialDPI,
		registry.PolicyAdversarialStrict,
		registry.PolicyEmergencyWeb,
		registry.PolicyLab:
		return nil
	default:
		return fmt.Errorf("protocol: reserved policy 0x%x", policy)
	}
}

func validateRouteModeKnown(route uint64) error {
	switch route {
	case registry.RouteFast1,
		registry.RouteSplit2,
		registry.RouteSafe3,
		registry.RouteBridgeSplit,
		registry.RouteAuto:
		return nil
	default:
		return fmt.Errorf("protocol: reserved route mode 0x%x", route)
	}
}

func validateShapeKnown(shape uint64) error {
	switch shape {
	case registry.ShapeLight,
		registry.ShapeNormal,
		registry.ShapeStrict,
		registry.ShapeEmergency:
		return nil
	default:
		return fmt.Errorf("protocol: reserved shape 0x%x", shape)
	}
}

func validateTunnelPersonalityKnown(personality uint64) error {
	switch personality {
	case registry.PersonalityProxyFlow,
		registry.PersonalityIPLite,
		registry.PersonalityFullIP:
		return nil
	default:
		return fmt.Errorf("protocol: reserved tunnel personality 0x%x", personality)
	}
}

func validateMethodKnown(method uint64) error {
	switch method {
	case registry.MethodWebH2Stream,
		registry.MethodWebH1WS,
		registry.MethodShadowOrigin,
		registry.MethodWebH3Stream,
		registry.MethodWebH3ExtDgram,
		registry.MethodMasqueConnectIP,
		registry.MethodMasqueConnectUDP,
		registry.MethodDirectQUICLab:
		return nil
	default:
		return fmt.Errorf("protocol: reserved method 0x%x", method)
	}
}
