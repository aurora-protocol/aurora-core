package protocol

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type CoverPrelude0 struct {
	MsgType                     uint64
	Version                     uint64
	SuiteOffers                 []uint64
	ClientNonce                 []byte
	ClientClassicalEphPub       []byte
	ClientMLKEMEncapsulationKey []byte
	RelayDescriptorHash         []byte
	CoverTemplateHash           []byte
	RequestClassID              uint64
	HintIssuerID                []byte
	RelayBucketID               []byte
	HintEpochID                 uint64
	HintSelector                []byte
	AccessHint                  []byte
	ClientCoverRandom           []byte
	Padding                     []byte
	Extensions                  []Extension
}

func (p CoverPrelude0) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.MsgType)
	e.WriteVarint(p.Version)
	e.WriteVarintVector(p.SuiteOffers)
	e.WriteOpaqueFixed(p.ClientNonce, 32)
	e.WriteOpaque16(p.ClientClassicalEphPub)
	e.WriteOpaque16(p.ClientMLKEMEncapsulationKey)
	e.WritePreHash(p.RelayDescriptorHash)
	e.WritePreHash(p.CoverTemplateHash)
	e.WriteVarint(p.RequestClassID)
	e.WriteOpaqueFixed(p.HintIssuerID, 16)
	e.WriteOpaqueFixed(p.RelayBucketID, 16)
	e.WriteUint64(p.HintEpochID)
	e.WriteOpaqueFixed(p.HintSelector, 16)
	e.WriteOpaqueFixed(p.AccessHint, 16)
	e.WriteOpaqueFixed(p.ClientCoverRandom, 32)
	e.WriteOpaque16(p.Padding)
	EncodeExtensions(e, p.Extensions)
}

func DecodeCoverPrelude0(r *wire.Reader) CoverPrelude0 {
	return CoverPrelude0{
		MsgType:                     r.ReadVarint(),
		Version:                     r.ReadVarint(),
		SuiteOffers:                 r.ReadVarintVector(),
		ClientNonce:                 r.ReadOpaqueFixed(32),
		ClientClassicalEphPub:       r.ReadOpaque16(),
		ClientMLKEMEncapsulationKey: r.ReadOpaque16(),
		RelayDescriptorHash:         r.ReadPreHash(),
		CoverTemplateHash:           r.ReadPreHash(),
		RequestClassID:              r.ReadVarint(),
		HintIssuerID:                r.ReadOpaqueFixed(16),
		RelayBucketID:               r.ReadOpaqueFixed(16),
		HintEpochID:                 r.ReadUint64(),
		HintSelector:                r.ReadOpaqueFixed(16),
		AccessHint:                  r.ReadOpaqueFixed(16),
		ClientCoverRandom:           r.ReadOpaqueFixed(32),
		Padding:                     r.ReadOpaque16(),
		Extensions:                  DecodeExtensions(r),
	}
}

func (p CoverPrelude0) ValidateStructural() error {
	if p.MsgType != registry.MsgCoverPrelude0 {
		return fmt.Errorf("protocol: malformed CoverPrelude0 message type 0x%x", p.MsgType)
	}
	if err := validateVersionKnown(p.Version); err != nil {
		return err
	}
	for _, suite := range p.SuiteOffers {
		if err := validateSuiteKnown(suite); err != nil {
			return err
		}
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type CoverPrelude1 struct {
	MsgType                         uint64
	Version                         uint64
	SelectedSuite                   uint64
	RelayDescriptorHash             []byte
	CoverTemplateHash               []byte
	RelayEpochID                    uint64
	ServerNonce                     []byte
	ServerClassicalEphPub           []byte
	ServerMLKEMCiphertextToClient   []byte
	SelectedCoverProfileID          []byte
	SelectedBootstrapEnvelopeID     []byte
	ServerPreludeSignatureClassical []byte
	ServerPreludeSignaturePQ        []byte
	ResponsePadding                 []byte
	Extensions                      []Extension
}

func (p CoverPrelude1) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.MsgType)
	e.WriteVarint(p.Version)
	e.WriteVarint(p.SelectedSuite)
	e.WritePreHash(p.RelayDescriptorHash)
	e.WritePreHash(p.CoverTemplateHash)
	e.WriteUint64(p.RelayEpochID)
	e.WriteOpaqueFixed(p.ServerNonce, 32)
	e.WriteOpaque16(p.ServerClassicalEphPub)
	e.WriteOpaque16(p.ServerMLKEMCiphertextToClient)
	e.WriteOpaqueFixed(p.SelectedCoverProfileID, 16)
	e.WriteOpaqueFixed(p.SelectedBootstrapEnvelopeID, 16)
	e.WriteOpaque16(p.ServerPreludeSignatureClassical)
	e.WriteOpaque16(p.ServerPreludeSignaturePQ)
	e.WriteOpaque16(p.ResponsePadding)
	EncodeExtensions(e, p.Extensions)
}

func DecodeCoverPrelude1(r *wire.Reader) CoverPrelude1 {
	return CoverPrelude1{
		MsgType:                         r.ReadVarint(),
		Version:                         r.ReadVarint(),
		SelectedSuite:                   r.ReadVarint(),
		RelayDescriptorHash:             r.ReadPreHash(),
		CoverTemplateHash:               r.ReadPreHash(),
		RelayEpochID:                    r.ReadUint64(),
		ServerNonce:                     r.ReadOpaqueFixed(32),
		ServerClassicalEphPub:           r.ReadOpaque16(),
		ServerMLKEMCiphertextToClient:   r.ReadOpaque16(),
		SelectedCoverProfileID:          r.ReadOpaqueFixed(16),
		SelectedBootstrapEnvelopeID:     r.ReadOpaqueFixed(16),
		ServerPreludeSignatureClassical: r.ReadOpaque16(),
		ServerPreludeSignaturePQ:        r.ReadOpaque16(),
		ResponsePadding:                 r.ReadOpaque16(),
		Extensions:                      DecodeExtensions(r),
	}
}

func (p CoverPrelude1) ValidateStructural() error {
	if p.MsgType != registry.MsgCoverPrelude1 {
		return fmt.Errorf("protocol: malformed CoverPrelude1 message type 0x%x", p.MsgType)
	}
	if err := validateVersionKnown(p.Version); err != nil {
		return err
	}
	if err := validateSuiteKnown(p.SelectedSuite); err != nil {
		return err
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func (p CoverPrelude1) Unsigned() CoverPrelude1 {
	p.ServerPreludeSignatureClassical = nil
	p.ServerPreludeSignaturePQ = nil
	return p
}

type CoverCapsule1Plain struct {
	MsgType              uint64
	RouteInstanceID      uint64
	AdmissionProof       AdmissionProof
	ReplayProof          ReplayProof
	PolicyOffer          PolicyOffer
	ClientTransportHints ClientTransportHints
	ClientFinished       []byte
	Padding              []byte
	Extensions           []Extension
}

func (c CoverCapsule1Plain) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.MsgType)
	e.WriteVarint(c.RouteInstanceID)
	c.AdmissionProof.EncodeTo(e)
	c.ReplayProof.EncodeTo(e)
	c.PolicyOffer.EncodeTo(e)
	c.ClientTransportHints.EncodeTo(e)
	e.WriteOpaque16(c.ClientFinished)
	e.WriteOpaque16(c.Padding)
	EncodeExtensions(e, c.Extensions)
}

func DecodeCoverCapsule1Plain(r *wire.Reader) CoverCapsule1Plain {
	return CoverCapsule1Plain{
		MsgType:              r.ReadVarint(),
		RouteInstanceID:      r.ReadVarint(),
		AdmissionProof:       DecodeAdmissionProof(r),
		ReplayProof:          DecodeReplayProof(r),
		PolicyOffer:          DecodePolicyOffer(r),
		ClientTransportHints: DecodeClientTransportHints(r),
		ClientFinished:       r.ReadOpaque16(),
		Padding:              r.ReadOpaque16(),
		Extensions:           DecodeExtensions(r),
	}
}

func (c CoverCapsule1Plain) ValidateStructural(now uint64, allowLab bool) error {
	if c.MsgType != registry.MsgCoverCapsule1 {
		return fmt.Errorf("protocol: malformed CoverCapsule1 message type 0x%x", c.MsgType)
	}
	if err := c.AdmissionProof.ValidateStructural(now, allowLab); err != nil {
		return err
	}
	if err := c.ReplayProof.ValidateStructural(); err != nil {
		return err
	}
	if err := c.PolicyOffer.ValidateStructural(); err != nil {
		return err
	}
	if err := c.ClientTransportHints.ValidatePrototype(); err != nil {
		return err
	}
	if err := ValidateExtensions(c.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func (c CoverCapsule1Plain) UnsignedClientFinished() CoverCapsule1Plain {
	c.ClientFinished = nil
	return c
}

type CoverCapsule2Plain struct {
	MsgType         uint64
	RouteInstanceID uint64
	PolicyAccept    PolicyAccept
	ServerFinished  []byte
	Padding         []byte
	Extensions      []Extension
}

func (c CoverCapsule2Plain) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.MsgType)
	e.WriteVarint(c.RouteInstanceID)
	c.PolicyAccept.EncodeTo(e)
	e.WriteOpaque16(c.ServerFinished)
	e.WriteOpaque16(c.Padding)
	EncodeExtensions(e, c.Extensions)
}

func DecodeCoverCapsule2Plain(r *wire.Reader) CoverCapsule2Plain {
	return CoverCapsule2Plain{
		MsgType:         r.ReadVarint(),
		RouteInstanceID: r.ReadVarint(),
		PolicyAccept:    DecodePolicyAccept(r),
		ServerFinished:  r.ReadOpaque16(),
		Padding:         r.ReadOpaque16(),
		Extensions:      DecodeExtensions(r),
	}
}

func (c CoverCapsule2Plain) ValidateStructural() error {
	if c.MsgType != registry.MsgCoverCapsule2 {
		return fmt.Errorf("protocol: malformed CoverCapsule2 message type 0x%x", c.MsgType)
	}
	if err := c.PolicyAccept.ValidateStructural(); err != nil {
		return err
	}
	if err := ValidateExtensions(c.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type RouteCapsule1Plain struct {
	MsgType         uint64
	RouteInstanceID uint64
	HopIndex        uint8
	AdmissionProof  AdmissionProof
	ReplayProof     ReplayProof
	PolicyOffer     PolicyOffer
	ClientFinished  []byte
	Padding         []byte
	Extensions      []Extension
}

func (c RouteCapsule1Plain) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.MsgType)
	e.WriteVarint(c.RouteInstanceID)
	e.WriteUint8(c.HopIndex)
	c.AdmissionProof.EncodeTo(e)
	c.ReplayProof.EncodeTo(e)
	c.PolicyOffer.EncodeTo(e)
	e.WriteOpaque16(c.ClientFinished)
	e.WriteOpaque16(c.Padding)
	EncodeExtensions(e, c.Extensions)
}

func DecodeRouteCapsule1Plain(r *wire.Reader) RouteCapsule1Plain {
	return RouteCapsule1Plain{
		MsgType:         r.ReadVarint(),
		RouteInstanceID: r.ReadVarint(),
		HopIndex:        r.ReadUint8(),
		AdmissionProof:  DecodeAdmissionProof(r),
		ReplayProof:     DecodeReplayProof(r),
		PolicyOffer:     DecodePolicyOffer(r),
		ClientFinished:  r.ReadOpaque16(),
		Padding:         r.ReadOpaque16(),
		Extensions:      DecodeExtensions(r),
	}
}

func (c RouteCapsule1Plain) ValidateStructural(now uint64, allowLab bool) error {
	if c.MsgType != registry.MsgRouteCapsule1 {
		return fmt.Errorf("protocol: malformed RouteCapsule1 message type 0x%x", c.MsgType)
	}
	if err := c.AdmissionProof.ValidateStructural(now, allowLab); err != nil {
		return err
	}
	if err := c.ReplayProof.ValidateStructural(); err != nil {
		return err
	}
	if err := c.PolicyOffer.ValidateStructural(); err != nil {
		return err
	}
	if err := ValidateExtensions(c.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func (c RouteCapsule1Plain) UnsignedClientFinished() RouteCapsule1Plain {
	c.ClientFinished = nil
	return c
}

type RouteCapsule2Plain struct {
	MsgType         uint64
	RouteInstanceID uint64
	HopIndex        uint8
	PolicyAccept    PolicyAccept
	ServerFinished  []byte
	Padding         []byte
	Extensions      []Extension
}

func (c RouteCapsule2Plain) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.MsgType)
	e.WriteVarint(c.RouteInstanceID)
	e.WriteUint8(c.HopIndex)
	c.PolicyAccept.EncodeTo(e)
	e.WriteOpaque16(c.ServerFinished)
	e.WriteOpaque16(c.Padding)
	EncodeExtensions(e, c.Extensions)
}

func DecodeRouteCapsule2Plain(r *wire.Reader) RouteCapsule2Plain {
	return RouteCapsule2Plain{
		MsgType:         r.ReadVarint(),
		RouteInstanceID: r.ReadVarint(),
		HopIndex:        r.ReadUint8(),
		PolicyAccept:    DecodePolicyAccept(r),
		ServerFinished:  r.ReadOpaque16(),
		Padding:         r.ReadOpaque16(),
		Extensions:      DecodeExtensions(r),
	}
}

func (c RouteCapsule2Plain) ValidateStructural() error {
	if c.MsgType != registry.MsgRouteCapsule2 {
		return fmt.Errorf("protocol: malformed RouteCapsule2 message type 0x%x", c.MsgType)
	}
	if err := c.PolicyAccept.ValidateStructural(); err != nil {
		return err
	}
	if err := ValidateExtensions(c.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type RoutePrelude1 struct {
	MsgType                         uint64
	Version                         uint64
	RouteInstanceID                 uint64
	HopIndex                        uint8
	PreviousHopRelayDescriptorHash  []byte
	NextRelayDescriptorHash         []byte
	NextRelayEpochID                uint64
	SelectedSuite                   uint64
	ServerNonce                     []byte
	ServerClassicalEphPub           []byte
	ServerMLKEMCiphertextToClient   []byte
	SelectedShapeID                 uint64
	ServerPreludeSignatureClassical []byte
	ServerPreludeSignaturePQ        []byte
	Padding                         []byte
	Extensions                      []Extension
}

func (p RoutePrelude1) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.MsgType)
	e.WriteVarint(p.Version)
	e.WriteVarint(p.RouteInstanceID)
	e.WriteUint8(p.HopIndex)
	e.WritePreHash(p.PreviousHopRelayDescriptorHash)
	e.WritePreHash(p.NextRelayDescriptorHash)
	e.WriteUint64(p.NextRelayEpochID)
	e.WriteVarint(p.SelectedSuite)
	e.WriteOpaqueFixed(p.ServerNonce, 32)
	e.WriteOpaque16(p.ServerClassicalEphPub)
	e.WriteOpaque16(p.ServerMLKEMCiphertextToClient)
	e.WriteVarint(p.SelectedShapeID)
	e.WriteOpaque16(p.ServerPreludeSignatureClassical)
	e.WriteOpaque16(p.ServerPreludeSignaturePQ)
	e.WriteOpaque16(p.Padding)
	EncodeExtensions(e, p.Extensions)
}

func DecodeRoutePrelude1(r *wire.Reader) RoutePrelude1 {
	return RoutePrelude1{
		MsgType:                         r.ReadVarint(),
		Version:                         r.ReadVarint(),
		RouteInstanceID:                 r.ReadVarint(),
		HopIndex:                        r.ReadUint8(),
		PreviousHopRelayDescriptorHash:  r.ReadPreHash(),
		NextRelayDescriptorHash:         r.ReadPreHash(),
		NextRelayEpochID:                r.ReadUint64(),
		SelectedSuite:                   r.ReadVarint(),
		ServerNonce:                     r.ReadOpaqueFixed(32),
		ServerClassicalEphPub:           r.ReadOpaque16(),
		ServerMLKEMCiphertextToClient:   r.ReadOpaque16(),
		SelectedShapeID:                 r.ReadVarint(),
		ServerPreludeSignatureClassical: r.ReadOpaque16(),
		ServerPreludeSignaturePQ:        r.ReadOpaque16(),
		Padding:                         r.ReadOpaque16(),
		Extensions:                      DecodeExtensions(r),
	}
}

func (p RoutePrelude1) ValidateStructural() error {
	if p.MsgType != registry.MsgRoutePrelude1 {
		return fmt.Errorf("protocol: malformed RoutePrelude1 message type 0x%x", p.MsgType)
	}
	if err := validateVersionKnown(p.Version); err != nil {
		return err
	}
	if err := validateSuiteKnown(p.SelectedSuite); err != nil {
		return err
	}
	if err := validateShapeKnown(p.SelectedShapeID); err != nil {
		return err
	}
	if err := ValidateExtensions(p.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func (p RoutePrelude1) Unsigned() RoutePrelude1 {
	p.ServerPreludeSignatureClassical = nil
	p.ServerPreludeSignaturePQ = nil
	return p
}
