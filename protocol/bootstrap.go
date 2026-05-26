package protocol

import "github.com/aurora-protocol/aurora-core/wire"

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
