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

func DecodeSignatureEntry(r *wire.Reader) SignatureEntry {
	return SignatureEntry{
		AuthorityID:     r.ReadOpaqueFixed(16),
		AuthorityKeyID:  r.ReadOpaqueFixed(16),
		SignatureScheme: r.ReadVarint(),
		KeyEncoding:     r.ReadVarint(),
		Signature:       r.ReadOpaque16(),
	}
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

func DecodeDirectoryConsensus(r *wire.Reader) DirectoryConsensus {
	out := DirectoryConsensus{
		Version:                 r.ReadVarint(),
		Epoch:                   r.ReadUint64(),
		ValidFromUnix:           r.ReadUint64(),
		ValidUntilUnix:          r.ReadUint64(),
		PreviousConsensusHash:   r.ReadPreHash(),
		RelayDescriptorRoot:     r.ReadPreHash(),
		CoverTemplateFamilyRoot: r.ReadPreHash(),
		RevocationRoot:          r.ReadPreHash(),
		PolicyRoot:              r.ReadPreHash(),
		BridgeBucketCommitment:  r.ReadPreHash(),
		IssuerMetadataRoot:      r.ReadPreHash(),
	}
	count := r.ReadVarint()
	out.AuthoritySignatures = make([]SignatureEntry, 0, count)
	for i := uint64(0); i < count; i++ {
		out.AuthoritySignatures = append(out.AuthoritySignatures, DecodeSignatureEntry(r))
	}
	return out
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

func DecodeRoutingRecord(r *wire.Reader) RoutingRecord {
	return RoutingRecord{
		RoutingRecordID:   r.ReadOpaque16(),
		TransportFamilyID: r.ReadVarint(),
		LocatorType:       r.ReadVarint(),
		LocatorBody:       r.ReadOpaque16(),
		Priority:          r.ReadVarint(),
		NotBeforeUnix:     r.ReadUint64(),
		NotAfterUnix:      r.ReadUint64(),
	}
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

func DecodeRelayDescriptor(r *wire.Reader) RelayDescriptor {
	out := RelayDescriptor{
		DescriptorVersion:            r.ReadVarint(),
		RelayID:                      r.ReadOpaqueFixed(32),
		RoleFlags:                    r.ReadUint32(),
		ValidFromUnix:                r.ReadUint64(),
		ValidUntilUnix:               r.ReadUint64(),
		RelayLongtermClassicalKey:    DecodePublicKeyRecord(r),
		RelayLongtermPQKey:           DecodePublicKeyRecord(r),
		EpochID:                      r.ReadUint64(),
		EpochAuthClassicalKey:        DecodePublicKeyRecord(r),
		EpochAuthPQKey:               DecodePublicKeyRecord(r),
		EpochValidFromUnix:           r.ReadUint64(),
		EpochValidUntilUnix:          r.ReadUint64(),
		ReplayEpochID:                r.ReadUint64(),
		ReplayEpochValidUntilUnix:    r.ReadUint64(),
		ReplayWindowID:               r.ReadOpaqueFixed(16),
		SupportedSuiteIDs:            r.ReadVarintVector(),
		SupportedMethodIDs:           r.ReadVarintVector(),
		SupportedPolicyIDsCommitment: r.ReadPreHash(),
		SupportedShapeIDsCommitment:  r.ReadPreHash(),
	}
	records := r.ReadVarint()
	out.PublicRoutingRecords = make([]RoutingRecord, 0, records)
	for i := uint64(0); i < records; i++ {
		out.PublicRoutingRecords = append(out.PublicRoutingRecords, DecodeRoutingRecord(r))
	}
	hashes := r.ReadVarint()
	out.CoverTemplateInstanceHashes = make([][]byte, 0, hashes)
	for i := uint64(0); i < hashes; i++ {
		out.CoverTemplateInstanceHashes = append(out.CoverTemplateInstanceHashes, r.ReadPreHash())
	}
	out.ExitPolicyCommitment = r.ReadPreHash()
	out.AbusePolicyCommitment = r.ReadPreHash()
	out.SignatureByLongtermClassical = r.ReadOpaque16()
	out.SignatureByLongtermPQ = r.ReadOpaque16()
	return out
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

func DecodeRequestClass(r *wire.Reader) RequestClass {
	return RequestClass{
		ClassID:             r.ReadVarint(),
		ClassType:           r.ReadVarint(),
		AllowedMethodFamily: r.ReadVarint(),
		PathTemplateID:      r.ReadOpaqueFixed(16),
		BodyPolicyID:        r.ReadVarint(),
		ResponsePolicyID:    r.ReadVarint(),
		MayCarryPrelude:     r.ReadBool(),
		MayCarryCapsule:     r.ReadBool(),
	}
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

func DecodePreludeEnvelope(r *wire.Reader) PreludeEnvelope {
	return PreludeEnvelope{
		MinRequestBodySize:         r.ReadVarint(),
		MaxRequestBodySize:         r.ReadVarint(),
		RequestSizeDistributionID:  r.ReadOpaqueFixed(16),
		MinResponseBodySize:        r.ReadVarint(),
		MaxResponseBodySize:        r.ReadVarint(),
		ResponseSizeDistributionID: r.ReadOpaqueFixed(16),
		ContentTypeFamilyID:        r.ReadVarint(),
		ChunkingPolicyID:           r.ReadVarint(),
		ResponseTimingPolicyID:     r.ReadVarint(),
	}
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

func DecodeCapsuleEnvelope(r *wire.Reader) CapsuleEnvelope {
	return CapsuleEnvelope{
		EnvelopeID:               r.ReadOpaqueFixed(16),
		MinCapsuleBodySize:       r.ReadVarint(),
		MaxCapsuleBodySize:       r.ReadVarint(),
		BodySizeDistributionID:   r.ReadOpaqueFixed(16),
		AllowedContentTypeIDs:    r.ReadVarintVector(),
		ChunkingPolicyID:         r.ReadVarint(),
		FailureResponseFamilyID:  r.ReadVarint(),
		ConsumeFailedBodyLocally: r.ReadBool(),
	}
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

func DecodeH2CoverProfile(r *wire.Reader) H2CoverProfile {
	return H2CoverProfile{
		ProfileID:                  r.ReadVarint(),
		H2SettingsFamilyID:         r.ReadVarint(),
		PseudoHeaderOrderFamilyID:  r.ReadVarint(),
		HPACKBehaviorFamilyID:      r.ReadVarint(),
		MaxConcurrentStreamsBucket: r.ReadVarint(),
		InitialWindowBucket:        r.ReadVarint(),
		RequestGraphFamilyID:       r.ReadVarint(),
		RecordSizeDistributionID:   r.ReadOpaqueFixed(16),
		IdleTimeoutPolicyID:        r.ReadVarint(),
	}
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

func DecodeH3CoverProfile(r *wire.Reader) H3CoverProfile {
	return H3CoverProfile{
		ProfileID:                  r.ReadVarint(),
		H3SettingsFamilyID:         r.ReadVarint(),
		QPACKBehaviorFamilyID:      r.ReadVarint(),
		SupportsH3Datagram:         r.ReadBool(),
		SupportsWebTransportH3:     r.ReadBool(),
		WebTransportProfileID:      r.ReadVarint(),
		QUICDatagramRequired:       r.ReadBool(),
		ResetStreamAtRequired:      r.ReadBool(),
		RequestGraphFamilyID:       r.ReadVarint(),
		DatagramSizeDistributionID: r.ReadOpaqueFixed(16),
		DatagramRateDistributionID: r.ReadOpaqueFixed(16),
		FallbackMethodID:           r.ReadVarint(),
	}
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

func DecodeWebSocketCoverProfile(r *wire.Reader) WebSocketCoverProfile {
	return WebSocketCoverProfile{
		ProfileID:               r.ReadVarint(),
		UpgradeFamilyID:         r.ReadVarint(),
		SubprotocolFamilyID:     r.ReadVarint(),
		FrameSizeDistributionID: r.ReadOpaqueFixed(16),
		PingPolicyID:            r.ReadVarint(),
		CloseBehaviorID:         r.ReadVarint(),
		StreamLifetimePolicyID:  r.ReadVarint(),
	}
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

func DecodeCacheCookiePolicy(r *wire.Reader) CacheCookiePolicy {
	return CacheCookiePolicy{
		PolicyID:                 r.ReadVarint(),
		CookieBehaviorFamilyID:   r.ReadVarint(),
		CacheControlFamilyID:     r.ReadVarint(),
		ETagBehaviorFamilyID:     r.ReadVarint(),
		VaryHeaderFamilyID:       r.ReadVarint(),
		RedirectBehaviorFamilyID: r.ReadVarint(),
	}
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

func DecodeTimingEnvelope(r *wire.Reader) TimingEnvelope {
	return TimingEnvelope{
		TimingPolicyID:       r.ReadVarint(),
		MinResponseDelayMS:   r.ReadVarint(),
		MaxResponseDelayMS:   r.ReadVarint(),
		JitterDistributionID: r.ReadOpaqueFixed(16),
		TimeoutFamilyID:      r.ReadVarint(),
		RetryFamilyID:        r.ReadVarint(),
		CloseTimingFamilyID:  r.ReadVarint(),
	}
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

func DecodeCoverTemplate(r *wire.Reader) CoverTemplate {
	out := CoverTemplate{
		TemplateVersion:       r.ReadVarint(),
		TemplateID:            r.ReadOpaque16(),
		TemplateFamilyID:      r.ReadOpaque16(),
		ValidFromUnix:         r.ReadUint64(),
		ValidUntilUnix:        r.ReadUint64(),
		OriginSPKIHash:        r.ReadPreHash(),
		PublicNameHash:        r.ReadPreHash(),
		CoverOriginCommitment: r.ReadPreHash(),
	}
	classes := r.ReadVarint()
	out.RequestClasses = make([]RequestClass, 0, classes)
	for i := uint64(0); i < classes; i++ {
		out.RequestClasses = append(out.RequestClasses, DecodeRequestClass(r))
	}
	gatewayCommitments := r.ReadVarint()
	out.GatewayOwnedSlotCommitments = make([][]byte, 0, gatewayCommitments)
	for i := uint64(0); i < gatewayCommitments; i++ {
		out.GatewayOwnedSlotCommitments = append(out.GatewayOwnedSlotCommitments, r.ReadPreHash())
	}
	passThroughCommitments := r.ReadVarint()
	out.OriginPassThroughSlotCommitments = make([][]byte, 0, passThroughCommitments)
	for i := uint64(0); i < passThroughCommitments; i++ {
		out.OriginPassThroughSlotCommitments = append(out.OriginPassThroughSlotCommitments, r.ReadPreHash())
	}
	out.PreludeEnvelope = DecodePreludeEnvelope(r)
	out.CapsuleEnvelope = DecodeCapsuleEnvelope(r)
	out.H2Profile = DecodeH2CoverProfile(r)
	out.H3Profile = DecodeH3CoverProfile(r)
	out.WebSocketProfile = DecodeWebSocketCoverProfile(r)
	out.CacheCookiePolicy = DecodeCacheCookiePolicy(r)
	out.TimingEnvelope = DecodeTimingEnvelope(r)
	out.TemplateFamilySignature = r.ReadOpaque16()
	out.TemplateInstanceSignature = r.ReadOpaque16()
	return out
}

func (c CoverTemplate) Unsigned() CoverTemplate {
	c.TemplateFamilySignature = nil
	c.TemplateInstanceSignature = nil
	return c
}
