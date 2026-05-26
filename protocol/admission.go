package protocol

import (
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
	if p.ProofVersion != registry.Version20 {
		return fmt.Errorf("protocol: unsupported admission proof version 0x%x", p.ProofVersion)
	}
	if now >= p.ExpiryUnix {
		return fmt.Errorf("protocol: admission proof expired")
	}
	switch p.ProofType {
	case registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048, registry.ProofOpaqueIssuer:
	case registry.ProofLabStaticToken:
		if !allowLab {
			return fmt.Errorf("protocol: lab admission proof disabled")
		}
	default:
		return fmt.Errorf("protocol: unknown admission proof type 0x%x", p.ProofType)
	}
	if len(p.RedemptionContextHash) != 48 {
		return fmt.Errorf("protocol: redemption context hash must be 48 bytes")
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
	return nil
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

type VirtualAddressAssignment struct {
	AddressFamily uint8
	Address       []byte
	PrefixLength  uint8
	DNSResolvers  [][]byte
}

func (v VirtualAddressAssignment) EncodeTo(e *wire.Encoder) {
	e.WriteUint8(v.AddressFamily)
	e.WriteOpaque16(v.Address)
	e.WriteUint8(v.PrefixLength)
	e.WriteVarint(uint64(len(v.DNSResolvers)))
	for _, resolver := range v.DNSResolvers {
		e.WriteOpaque16(resolver)
	}
}

func DecodeVirtualAddressAssignment(r *wire.Reader) VirtualAddressAssignment {
	out := VirtualAddressAssignment{
		AddressFamily: r.ReadUint8(),
		Address:       r.ReadOpaque16(),
		PrefixLength:  r.ReadUint8(),
	}
	count := r.ReadVarint()
	out.DNSResolvers = make([][]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		out.DNSResolvers = append(out.DNSResolvers, r.ReadOpaque16())
	}
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
