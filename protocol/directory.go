package protocol

import "github.com/aurora-protocol/aurora-core/wire"

type SignatureEntry struct {
	AuthorityID     []byte
	AuthorityKeyID  []byte
	SignatureScheme uint64
	KeyEncoding     uint64
	Signature       []byte
}

func (s SignatureEntry) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(s.AuthorityID, 16)
	e.WriteOpaqueFixed(s.AuthorityKeyID, 16)
	e.WriteVarint(s.SignatureScheme)
	e.WriteVarint(s.KeyEncoding)
	e.WriteOpaque16(s.Signature)
}

type DirectoryConsensus struct {
	Version                 uint64
	Epoch                   uint64
	ValidFromUnix           uint64
	ValidUntilUnix          uint64
	PreviousConsensusHash   []byte
	RelayDescriptorRoot     []byte
	CoverTemplateFamilyRoot []byte
	RevocationRoot          []byte
	PolicyRoot              []byte
	BridgeBucketCommitment  []byte
	IssuerMetadataRoot      []byte
	AuthoritySignatures     []SignatureEntry
}

func (d DirectoryConsensus) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(d.Version)
	e.WriteUint64(d.Epoch)
	e.WriteUint64(d.ValidFromUnix)
	e.WriteUint64(d.ValidUntilUnix)
	e.WritePreHash(d.PreviousConsensusHash)
	e.WritePreHash(d.RelayDescriptorRoot)
	e.WritePreHash(d.CoverTemplateFamilyRoot)
	e.WritePreHash(d.RevocationRoot)
	e.WritePreHash(d.PolicyRoot)
	e.WritePreHash(d.BridgeBucketCommitment)
	e.WritePreHash(d.IssuerMetadataRoot)
	e.WriteVarint(uint64(len(d.AuthoritySignatures)))
	for _, sig := range d.AuthoritySignatures {
		sig.EncodeTo(e)
	}
}

func (d DirectoryConsensus) Unsigned() DirectoryConsensus {
	d.AuthoritySignatures = nil
	return d
}

type RoutingRecord struct {
	RoutingRecordID   []byte
	TransportFamilyID uint64
	LocatorType       uint64
	LocatorBody       []byte
	Priority          uint64
	NotBeforeUnix     uint64
	NotAfterUnix      uint64
}

func (r RoutingRecord) EncodeTo(e *wire.Encoder) {
	e.WriteOpaque16(r.RoutingRecordID)
	e.WriteVarint(r.TransportFamilyID)
	e.WriteVarint(r.LocatorType)
	e.WriteOpaque16(r.LocatorBody)
	e.WriteVarint(r.Priority)
	e.WriteUint64(r.NotBeforeUnix)
	e.WriteUint64(r.NotAfterUnix)
}

type RelayDescriptor struct {
	DescriptorVersion            uint64
	RelayID                      []byte
	RoleFlags                    uint32
	ValidFromUnix                uint64
	ValidUntilUnix               uint64
	RelayLongtermClassicalKey    PublicKeyRecord
	RelayLongtermPQKey           PublicKeyRecord
	EpochID                      uint64
	EpochAuthClassicalKey        PublicKeyRecord
	EpochAuthPQKey               PublicKeyRecord
	EpochValidFromUnix           uint64
	EpochValidUntilUnix          uint64
	ReplayEpochID                uint64
	ReplayEpochValidUntilUnix    uint64
	ReplayWindowID               []byte
	SupportedSuiteIDs            []uint64
	SupportedMethodIDs           []uint64
	SupportedPolicyIDsCommitment []byte
	SupportedShapeIDsCommitment  []byte
	PublicRoutingRecords         []RoutingRecord
	CoverTemplateInstanceHashes  [][]byte
	ExitPolicyCommitment         []byte
	AbusePolicyCommitment        []byte
	SignatureByLongtermClassical []byte
	SignatureByLongtermPQ        []byte
}

func (r RelayDescriptor) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.DescriptorVersion)
	e.WriteOpaqueFixed(r.RelayID, 32)
	e.WriteUint32(r.RoleFlags)
	e.WriteUint64(r.ValidFromUnix)
	e.WriteUint64(r.ValidUntilUnix)
	r.RelayLongtermClassicalKey.EncodeTo(e)
	r.RelayLongtermPQKey.EncodeTo(e)
	e.WriteUint64(r.EpochID)
	r.EpochAuthClassicalKey.EncodeTo(e)
	r.EpochAuthPQKey.EncodeTo(e)
	e.WriteUint64(r.EpochValidFromUnix)
	e.WriteUint64(r.EpochValidUntilUnix)
	e.WriteUint64(r.ReplayEpochID)
	e.WriteUint64(r.ReplayEpochValidUntilUnix)
	e.WriteOpaqueFixed(r.ReplayWindowID, 16)
	e.WriteVarintVector(r.SupportedSuiteIDs)
	e.WriteVarintVector(r.SupportedMethodIDs)
	e.WritePreHash(r.SupportedPolicyIDsCommitment)
	e.WritePreHash(r.SupportedShapeIDsCommitment)
	e.WriteVarint(uint64(len(r.PublicRoutingRecords)))
	for _, record := range r.PublicRoutingRecords {
		record.EncodeTo(e)
	}
	e.WriteVarint(uint64(len(r.CoverTemplateInstanceHashes)))
	for _, h := range r.CoverTemplateInstanceHashes {
		e.WritePreHash(h)
	}
	e.WritePreHash(r.ExitPolicyCommitment)
	e.WritePreHash(r.AbusePolicyCommitment)
	e.WriteOpaque16(r.SignatureByLongtermClassical)
	e.WriteOpaque16(r.SignatureByLongtermPQ)
}

func (r RelayDescriptor) Unsigned() RelayDescriptor {
	r.SignatureByLongtermClassical = nil
	r.SignatureByLongtermPQ = nil
	return r
}

type RequestClass struct {
	ClassID             uint64
	ClassType           uint64
	AllowedMethodFamily uint64
	PathTemplateID      []byte
	BodyPolicyID        uint64
	ResponsePolicyID    uint64
	MayCarryPrelude     bool
	MayCarryCapsule     bool
}

func (r RequestClass) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.ClassID)
	e.WriteVarint(r.ClassType)
	e.WriteVarint(r.AllowedMethodFamily)
	e.WriteOpaqueFixed(r.PathTemplateID, 16)
	e.WriteVarint(r.BodyPolicyID)
	e.WriteVarint(r.ResponsePolicyID)
	e.WriteBool(r.MayCarryPrelude)
	e.WriteBool(r.MayCarryCapsule)
}

type PreludeEnvelope struct {
	MinRequestBodySize         uint64
	MaxRequestBodySize         uint64
	RequestSizeDistributionID  []byte
	MinResponseBodySize        uint64
	MaxResponseBodySize        uint64
	ResponseSizeDistributionID []byte
	ContentTypeFamilyID        uint64
	ChunkingPolicyID           uint64
	ResponseTimingPolicyID     uint64
}

func (p PreludeEnvelope) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.MinRequestBodySize)
	e.WriteVarint(p.MaxRequestBodySize)
	e.WriteOpaqueFixed(p.RequestSizeDistributionID, 16)
	e.WriteVarint(p.MinResponseBodySize)
	e.WriteVarint(p.MaxResponseBodySize)
	e.WriteOpaqueFixed(p.ResponseSizeDistributionID, 16)
	e.WriteVarint(p.ContentTypeFamilyID)
	e.WriteVarint(p.ChunkingPolicyID)
	e.WriteVarint(p.ResponseTimingPolicyID)
}

type CapsuleEnvelope struct {
	EnvelopeID               []byte
	MinCapsuleBodySize       uint64
	MaxCapsuleBodySize       uint64
	BodySizeDistributionID   []byte
	AllowedContentTypeIDs    []uint64
	ChunkingPolicyID         uint64
	FailureResponseFamilyID  uint64
	ConsumeFailedBodyLocally bool
}

func (c CapsuleEnvelope) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(c.EnvelopeID, 16)
	e.WriteVarint(c.MinCapsuleBodySize)
	e.WriteVarint(c.MaxCapsuleBodySize)
	e.WriteOpaqueFixed(c.BodySizeDistributionID, 16)
	e.WriteVarintVector(c.AllowedContentTypeIDs)
	e.WriteVarint(c.ChunkingPolicyID)
	e.WriteVarint(c.FailureResponseFamilyID)
	e.WriteBool(c.ConsumeFailedBodyLocally)
}

type H2CoverProfile struct {
	ProfileID                  uint64
	H2SettingsFamilyID         uint64
	PseudoHeaderOrderFamilyID  uint64
	HPACKBehaviorFamilyID      uint64
	MaxConcurrentStreamsBucket uint64
	InitialWindowBucket        uint64
	RequestGraphFamilyID       uint64
	RecordSizeDistributionID   []byte
	IdleTimeoutPolicyID        uint64
}

func (h H2CoverProfile) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(h.ProfileID)
	e.WriteVarint(h.H2SettingsFamilyID)
	e.WriteVarint(h.PseudoHeaderOrderFamilyID)
	e.WriteVarint(h.HPACKBehaviorFamilyID)
	e.WriteVarint(h.MaxConcurrentStreamsBucket)
	e.WriteVarint(h.InitialWindowBucket)
	e.WriteVarint(h.RequestGraphFamilyID)
	e.WriteOpaqueFixed(h.RecordSizeDistributionID, 16)
	e.WriteVarint(h.IdleTimeoutPolicyID)
}

type H3CoverProfile struct {
	ProfileID                  uint64
	H3SettingsFamilyID         uint64
	QPACKBehaviorFamilyID      uint64
	SupportsH3Datagram         bool
	SupportsWebTransportH3     bool
	WebTransportProfileID      uint64
	QUICDatagramRequired       bool
	ResetStreamAtRequired      bool
	RequestGraphFamilyID       uint64
	DatagramSizeDistributionID []byte
	DatagramRateDistributionID []byte
	FallbackMethodID           uint64
}

func (h H3CoverProfile) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(h.ProfileID)
	e.WriteVarint(h.H3SettingsFamilyID)
	e.WriteVarint(h.QPACKBehaviorFamilyID)
	e.WriteBool(h.SupportsH3Datagram)
	e.WriteBool(h.SupportsWebTransportH3)
	e.WriteVarint(h.WebTransportProfileID)
	e.WriteBool(h.QUICDatagramRequired)
	e.WriteBool(h.ResetStreamAtRequired)
	e.WriteVarint(h.RequestGraphFamilyID)
	e.WriteOpaqueFixed(h.DatagramSizeDistributionID, 16)
	e.WriteOpaqueFixed(h.DatagramRateDistributionID, 16)
	e.WriteVarint(h.FallbackMethodID)
}

type WebSocketCoverProfile struct {
	ProfileID               uint64
	UpgradeFamilyID         uint64
	SubprotocolFamilyID     uint64
	FrameSizeDistributionID []byte
	PingPolicyID            uint64
	CloseBehaviorID         uint64
	StreamLifetimePolicyID  uint64
}

func (w WebSocketCoverProfile) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(w.ProfileID)
	e.WriteVarint(w.UpgradeFamilyID)
	e.WriteVarint(w.SubprotocolFamilyID)
	e.WriteOpaqueFixed(w.FrameSizeDistributionID, 16)
	e.WriteVarint(w.PingPolicyID)
	e.WriteVarint(w.CloseBehaviorID)
	e.WriteVarint(w.StreamLifetimePolicyID)
}

type CacheCookiePolicy struct {
	PolicyID                 uint64
	CookieBehaviorFamilyID   uint64
	CacheControlFamilyID     uint64
	ETagBehaviorFamilyID     uint64
	VaryHeaderFamilyID       uint64
	RedirectBehaviorFamilyID uint64
}

func (c CacheCookiePolicy) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.PolicyID)
	e.WriteVarint(c.CookieBehaviorFamilyID)
	e.WriteVarint(c.CacheControlFamilyID)
	e.WriteVarint(c.ETagBehaviorFamilyID)
	e.WriteVarint(c.VaryHeaderFamilyID)
	e.WriteVarint(c.RedirectBehaviorFamilyID)
}

type TimingEnvelope struct {
	TimingPolicyID       uint64
	MinResponseDelayMS   uint64
	MaxResponseDelayMS   uint64
	JitterDistributionID []byte
	TimeoutFamilyID      uint64
	RetryFamilyID        uint64
	CloseTimingFamilyID  uint64
}

func (t TimingEnvelope) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(t.TimingPolicyID)
	e.WriteVarint(t.MinResponseDelayMS)
	e.WriteVarint(t.MaxResponseDelayMS)
	e.WriteOpaqueFixed(t.JitterDistributionID, 16)
	e.WriteVarint(t.TimeoutFamilyID)
	e.WriteVarint(t.RetryFamilyID)
	e.WriteVarint(t.CloseTimingFamilyID)
}

type CoverTemplate struct {
	TemplateVersion                  uint64
	TemplateID                       []byte
	TemplateFamilyID                 []byte
	ValidFromUnix                    uint64
	ValidUntilUnix                   uint64
	OriginSPKIHash                   []byte
	PublicNameHash                   []byte
	CoverOriginCommitment            []byte
	RequestClasses                   []RequestClass
	GatewayOwnedSlotCommitments      [][]byte
	OriginPassThroughSlotCommitments [][]byte
	PreludeEnvelope                  PreludeEnvelope
	CapsuleEnvelope                  CapsuleEnvelope
	H2Profile                        H2CoverProfile
	H3Profile                        H3CoverProfile
	WebSocketProfile                 WebSocketCoverProfile
	CacheCookiePolicy                CacheCookiePolicy
	TimingEnvelope                   TimingEnvelope
	TemplateFamilySignature          []byte
	TemplateInstanceSignature        []byte
}

func (c CoverTemplate) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.TemplateVersion)
	e.WriteOpaque16(c.TemplateID)
	e.WriteOpaque16(c.TemplateFamilyID)
	e.WriteUint64(c.ValidFromUnix)
	e.WriteUint64(c.ValidUntilUnix)
	e.WritePreHash(c.OriginSPKIHash)
	e.WritePreHash(c.PublicNameHash)
	e.WritePreHash(c.CoverOriginCommitment)
	e.WriteVarint(uint64(len(c.RequestClasses)))
	for _, class := range c.RequestClasses {
		class.EncodeTo(e)
	}
	e.WriteVarint(uint64(len(c.GatewayOwnedSlotCommitments)))
	for _, h := range c.GatewayOwnedSlotCommitments {
		e.WritePreHash(h)
	}
	e.WriteVarint(uint64(len(c.OriginPassThroughSlotCommitments)))
	for _, h := range c.OriginPassThroughSlotCommitments {
		e.WritePreHash(h)
	}
	c.PreludeEnvelope.EncodeTo(e)
	c.CapsuleEnvelope.EncodeTo(e)
	c.H2Profile.EncodeTo(e)
	c.H3Profile.EncodeTo(e)
	c.WebSocketProfile.EncodeTo(e)
	c.CacheCookiePolicy.EncodeTo(e)
	c.TimingEnvelope.EncodeTo(e)
	e.WriteOpaque16(c.TemplateFamilySignature)
	e.WriteOpaque16(c.TemplateInstanceSignature)
}

func (c CoverTemplate) Unsigned() CoverTemplate {
	c.TemplateFamilySignature = nil
	c.TemplateInstanceSignature = nil
	return c
}
