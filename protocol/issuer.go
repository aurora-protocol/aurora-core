package protocol

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type IssuerTokenKeyRecord struct {
	ProofType            uint64
	TokenKeyID           []byte
	TokenVerificationKey TokenVerificationKeyRecord
	ValidFromUnix        uint64
	ValidUntilUnix       uint64
	KeyStatus            uint8
}

func (r IssuerTokenKeyRecord) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.ProofType)
	e.WriteOpaqueFixed(r.TokenKeyID, 32)
	r.TokenVerificationKey.EncodeTo(e)
	e.WriteUint64(r.ValidFromUnix)
	e.WriteUint64(r.ValidUntilUnix)
	e.WriteUint8(r.KeyStatus)
}

func DecodeIssuerTokenKeyRecord(r *wire.Reader) IssuerTokenKeyRecord {
	return IssuerTokenKeyRecord{
		ProofType:            r.ReadVarint(),
		TokenKeyID:           r.ReadOpaqueFixed(32),
		TokenVerificationKey: DecodeTokenVerificationKeyRecord(r),
		ValidFromUnix:        r.ReadUint64(),
		ValidUntilUnix:       r.ReadUint64(),
		KeyStatus:            r.ReadUint8(),
	}
}

func (r IssuerTokenKeyRecord) Validate(now uint64) error {
	if len(r.TokenKeyID) != 32 {
		return fmt.Errorf("protocol: issuer token key id must be 32 bytes")
	}
	if now < r.ValidFromUnix || now >= r.ValidUntilUnix {
		return fmt.Errorf("protocol: issuer token key outside validity interval")
	}
	if r.KeyStatus != registry.IssuerStatusActive && r.KeyStatus != registry.IssuerStatusRetiring {
		return fmt.Errorf("protocol: issuer token key status not usable")
	}
	switch r.ProofType {
	case registry.ProofVOPRFP384SHA384:
		if r.TokenVerificationKey.TokenVerificationKeyScheme != registry.TokenKeyVOPRFP384SHA384 {
			return fmt.Errorf("protocol: VOPRF proof requires VOPRF token key scheme")
		}
		if err := r.validateProductionTokenKeyID(); err != nil {
			return err
		}
	case registry.ProofBlindRSA2048:
		if r.TokenVerificationKey.TokenVerificationKeyScheme != registry.TokenKeyBlindRSA2048 {
			return fmt.Errorf("protocol: Blind RSA proof requires Blind RSA token key scheme")
		}
		if err := r.validateProductionTokenKeyID(); err != nil {
			return err
		}
	case registry.ProofOpaqueIssuer:
		if r.TokenVerificationKey.TokenVerificationKeyScheme < 0x7000 || r.TokenVerificationKey.TokenVerificationKeyScheme > 0x7eff {
			return fmt.Errorf("protocol: opaque issuer proof requires private token key scheme")
		}
	case registry.ProofLabStaticToken:
		if r.TokenVerificationKey.TokenVerificationKeyScheme != registry.TokenKeyLabStaticNoKey {
			return fmt.Errorf("protocol: lab static proof requires lab token key scheme")
		}
		if len(r.TokenVerificationKey.TokenVerificationKey) != 0 {
			return fmt.Errorf("protocol: lab static token key must be empty")
		}
	default:
		return fmt.Errorf("protocol: unknown issuer proof type 0x%x", r.ProofType)
	}
	return nil
}

func (r IssuerTokenKeyRecord) validateStructural(allowLab bool) error {
	if len(r.TokenKeyID) != 32 {
		return fmt.Errorf("protocol: issuer token key id must be 32 bytes")
	}
	if r.ValidUntilUnix <= r.ValidFromUnix {
		return fmt.Errorf("protocol: issuer token key validity interval is empty")
	}
	if err := validateIssuerStatusKnown(r.KeyStatus, "issuer token key"); err != nil {
		return err
	}
	switch r.ProofType {
	case registry.ProofVOPRFP384SHA384:
		if r.TokenVerificationKey.TokenVerificationKeyScheme != registry.TokenKeyVOPRFP384SHA384 {
			return fmt.Errorf("protocol: VOPRF proof requires VOPRF token key scheme")
		}
		return r.validateProductionTokenKeyID()
	case registry.ProofBlindRSA2048:
		if r.TokenVerificationKey.TokenVerificationKeyScheme != registry.TokenKeyBlindRSA2048 {
			return fmt.Errorf("protocol: Blind RSA proof requires Blind RSA token key scheme")
		}
		return r.validateProductionTokenKeyID()
	case registry.ProofOpaqueIssuer:
		if r.TokenVerificationKey.TokenVerificationKeyScheme < 0x7000 || r.TokenVerificationKey.TokenVerificationKeyScheme > 0x7eff {
			return fmt.Errorf("protocol: opaque issuer proof requires private token key scheme")
		}
	case registry.ProofLabStaticToken:
		if !allowLab {
			return fmt.Errorf("protocol: lab issuer token key disabled")
		}
		if r.TokenVerificationKey.TokenVerificationKeyScheme != registry.TokenKeyLabStaticNoKey {
			return fmt.Errorf("protocol: lab static proof requires lab token key scheme")
		}
		if len(r.TokenVerificationKey.TokenVerificationKey) != 0 {
			return fmt.Errorf("protocol: lab static token key must be empty")
		}
	default:
		return fmt.Errorf("protocol: unknown issuer proof type 0x%x", r.ProofType)
	}
	return nil
}

func (r IssuerTokenKeyRecord) validateProductionTokenKeyID() error {
	sum := sha256.Sum256(r.TokenVerificationKey.TokenVerificationKey)
	if !bytes.Equal(r.TokenKeyID, sum[:]) {
		return fmt.Errorf("protocol: token key id does not match token verification key")
	}
	return nil
}

type OriginInfoPolicy struct {
	PolicyID             uint64
	OriginInfo           []byte
	AllowEmptyOriginInfo bool
	ValidFromUnix        uint64
	ValidUntilUnix       uint64
}

func (p OriginInfoPolicy) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.PolicyID)
	e.WriteOpaque16(p.OriginInfo)
	e.WriteBool(p.AllowEmptyOriginInfo)
	e.WriteUint64(p.ValidFromUnix)
	e.WriteUint64(p.ValidUntilUnix)
}

func DecodeOriginInfoPolicy(r *wire.Reader) OriginInfoPolicy {
	return OriginInfoPolicy{
		PolicyID:             r.ReadVarint(),
		OriginInfo:           r.ReadOpaque16(),
		AllowEmptyOriginInfo: r.ReadBool(),
		ValidFromUnix:        r.ReadUint64(),
		ValidUntilUnix:       r.ReadUint64(),
	}
}

type RelayBucketScope struct {
	RelayBucketID         []byte
	TokenScopeID          []byte
	AllowedOriginPolicyID []uint64
	ValidFromUnix         uint64
	ValidUntilUnix        uint64
}

func (s RelayBucketScope) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(s.RelayBucketID, 16)
	e.WriteOpaqueFixed(s.TokenScopeID, 16)
	e.WriteVarintVector(s.AllowedOriginPolicyID)
	e.WriteUint64(s.ValidFromUnix)
	e.WriteUint64(s.ValidUntilUnix)
}

func DecodeRelayBucketScope(r *wire.Reader) RelayBucketScope {
	return RelayBucketScope{
		RelayBucketID:         r.ReadOpaqueFixed(16),
		TokenScopeID:          r.ReadOpaqueFixed(16),
		AllowedOriginPolicyID: r.ReadVarintVector(),
		ValidFromUnix:         r.ReadUint64(),
		ValidUntilUnix:        r.ReadUint64(),
	}
}

type AuxiliaryBindingPolicy struct {
	ProofType            uint64
	BindingProofRequired bool
	MaxBindingProofLen   uint16
	BindingPolicyID      uint64
}

func (p AuxiliaryBindingPolicy) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(p.ProofType)
	e.WriteBool(p.BindingProofRequired)
	e.WriteUint16(p.MaxBindingProofLen)
	e.WriteVarint(p.BindingPolicyID)
}

func DecodeAuxiliaryBindingPolicy(r *wire.Reader) AuxiliaryBindingPolicy {
	return AuxiliaryBindingPolicy{
		ProofType:            r.ReadVarint(),
		BindingProofRequired: r.ReadBool(),
		MaxBindingProofLen:   r.ReadUint16(),
		BindingPolicyID:      r.ReadVarint(),
	}
}

type IssuerVerifierServiceRecord struct {
	ServiceID             []byte
	ServiceKind           uint64
	ServiceProtocolID     uint64
	ServiceLocator        RoutingRecord
	ServiceAuthKey        PublicKeyRecord
	AllowedProofTypes     []uint64
	AllowedRelayBucketIDs [][]byte
	RequestAuthPolicyID   uint64
	ValidFromUnix         uint64
	ValidUntilUnix        uint64
	ServiceStatus         uint8
}

func (s IssuerVerifierServiceRecord) EncodeTo(e *wire.Encoder) {
	e.WriteOpaqueFixed(s.ServiceID, 16)
	e.WriteVarint(s.ServiceKind)
	e.WriteVarint(s.ServiceProtocolID)
	s.ServiceLocator.EncodeTo(e)
	s.ServiceAuthKey.EncodeTo(e)
	e.WriteVarintVector(s.AllowedProofTypes)
	e.WriteVarint(uint64(len(s.AllowedRelayBucketIDs)))
	for _, id := range s.AllowedRelayBucketIDs {
		e.WriteOpaqueFixed(id, 16)
	}
	e.WriteVarint(s.RequestAuthPolicyID)
	e.WriteUint64(s.ValidFromUnix)
	e.WriteUint64(s.ValidUntilUnix)
	e.WriteUint8(s.ServiceStatus)
}

func DecodeIssuerVerifierServiceRecord(r *wire.Reader) IssuerVerifierServiceRecord {
	out := IssuerVerifierServiceRecord{
		ServiceID:         r.ReadOpaqueFixed(16),
		ServiceKind:       r.ReadVarint(),
		ServiceProtocolID: r.ReadVarint(),
		ServiceLocator:    DecodeRoutingRecord(r),
		ServiceAuthKey:    DecodePublicKeyRecord(r),
		AllowedProofTypes: r.ReadVarintVector(),
	}
	n := r.ReadVectorCount("allowed relay bucket")
	for i := uint64(0); i < n; i++ {
		out.AllowedRelayBucketIDs = append(out.AllowedRelayBucketIDs, r.ReadOpaqueFixed(16))
	}
	out.RequestAuthPolicyID = r.ReadVarint()
	out.ValidFromUnix = r.ReadUint64()
	out.ValidUntilUnix = r.ReadUint64()
	out.ServiceStatus = r.ReadUint8()
	return out
}

func (s IssuerVerifierServiceRecord) Allows(proofType uint64, relayBucketID []byte, now uint64, requestAuthPolicySupported bool) error {
	if s.ServiceKind != registry.VerifierServiceKindVOPRF {
		return fmt.Errorf("protocol: verifier service kind is not VOPRF")
	}
	if s.ServiceProtocolID != registry.IssuerVerifierVOPRFMTLS13 {
		return fmt.Errorf("protocol: verifier service protocol unsupported")
	}
	if proofType != registry.ProofVOPRFP384SHA384 {
		return fmt.Errorf("protocol: VOPRF verifier service cannot verify proof type 0x%x", proofType)
	}
	if now < s.ValidFromUnix || now >= s.ValidUntilUnix {
		return fmt.Errorf("protocol: verifier service outside validity interval")
	}
	if s.ServiceStatus != registry.IssuerStatusActive && s.ServiceStatus != registry.IssuerStatusRetiring {
		return fmt.Errorf("protocol: verifier service status not usable")
	}
	if !requestAuthPolicySupported {
		return fmt.Errorf("protocol: verifier service request auth policy unsupported")
	}
	if len(s.AllowedProofTypes) == 0 || len(s.AllowedRelayBucketIDs) == 0 {
		return fmt.Errorf("protocol: verifier service allowlists are empty")
	}
	proofOK := false
	for _, allowed := range s.AllowedProofTypes {
		if allowed == proofType {
			proofOK = true
			break
		}
	}
	if !proofOK {
		return fmt.Errorf("protocol: verifier service proof type not allowed")
	}
	for _, allowed := range s.AllowedRelayBucketIDs {
		if bytes.Equal(allowed, relayBucketID) {
			return nil
		}
	}
	return fmt.Errorf("protocol: verifier service relay bucket not allowed")
}

type IssuerMetadata struct {
	MetadataVersion          uint64
	IssuerID                 []byte
	ValidFromUnix            uint64
	ValidUntilUnix           uint64
	IssuerName               []byte
	SupportedProofTypes      []uint64
	TokenKeyMappings         []IssuerTokenKeyRecord
	OriginInfoPolicies       []OriginInfoPolicy
	RelayBucketScopes        []RelayBucketScope
	AuxiliaryBindingPolicies []AuxiliaryBindingPolicy
	VerifierServices         []IssuerVerifierServiceRecord
	MetadataSigningKeyID     []byte
	SignatureScheme          uint64
	KeyEncoding              uint64
	MetadataSignature        []byte
	Extensions               []Extension
}

func (m IssuerMetadata) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(m.MetadataVersion)
	e.WriteOpaqueFixed(m.IssuerID, 16)
	e.WriteUint64(m.ValidFromUnix)
	e.WriteUint64(m.ValidUntilUnix)
	e.WriteOpaque16(m.IssuerName)
	e.WriteVarintVector(m.SupportedProofTypes)
	e.WriteVarint(uint64(len(m.TokenKeyMappings)))
	for _, mapping := range m.TokenKeyMappings {
		mapping.EncodeTo(e)
	}
	e.WriteVarint(uint64(len(m.OriginInfoPolicies)))
	for _, policy := range m.OriginInfoPolicies {
		policy.EncodeTo(e)
	}
	e.WriteVarint(uint64(len(m.RelayBucketScopes)))
	for _, scope := range m.RelayBucketScopes {
		scope.EncodeTo(e)
	}
	e.WriteVarint(uint64(len(m.AuxiliaryBindingPolicies)))
	for _, policy := range m.AuxiliaryBindingPolicies {
		policy.EncodeTo(e)
	}
	e.WriteVarint(uint64(len(m.VerifierServices)))
	for _, service := range m.VerifierServices {
		service.EncodeTo(e)
	}
	e.WriteOpaqueFixed(m.MetadataSigningKeyID, 16)
	e.WriteVarint(m.SignatureScheme)
	e.WriteVarint(m.KeyEncoding)
	e.WriteOpaque16(m.MetadataSignature)
	EncodeExtensions(e, m.Extensions)
}

func DecodeIssuerMetadata(r *wire.Reader) IssuerMetadata {
	out := IssuerMetadata{
		MetadataVersion:     r.ReadVarint(),
		IssuerID:            r.ReadOpaqueFixed(16),
		ValidFromUnix:       r.ReadUint64(),
		ValidUntilUnix:      r.ReadUint64(),
		IssuerName:          r.ReadOpaque16(),
		SupportedProofTypes: r.ReadVarintVector(),
	}
	tokenKeys := r.ReadVectorCount("issuer token key")
	out.TokenKeyMappings = make([]IssuerTokenKeyRecord, 0, tokenKeys)
	for i := uint64(0); i < tokenKeys; i++ {
		out.TokenKeyMappings = append(out.TokenKeyMappings, DecodeIssuerTokenKeyRecord(r))
	}
	originPolicies := r.ReadVectorCount("origin policy")
	out.OriginInfoPolicies = make([]OriginInfoPolicy, 0, originPolicies)
	for i := uint64(0); i < originPolicies; i++ {
		out.OriginInfoPolicies = append(out.OriginInfoPolicies, DecodeOriginInfoPolicy(r))
	}
	relayScopes := r.ReadVectorCount("relay bucket scope")
	out.RelayBucketScopes = make([]RelayBucketScope, 0, relayScopes)
	for i := uint64(0); i < relayScopes; i++ {
		out.RelayBucketScopes = append(out.RelayBucketScopes, DecodeRelayBucketScope(r))
	}
	bindingPolicies := r.ReadVectorCount("auxiliary binding policy")
	out.AuxiliaryBindingPolicies = make([]AuxiliaryBindingPolicy, 0, bindingPolicies)
	for i := uint64(0); i < bindingPolicies; i++ {
		out.AuxiliaryBindingPolicies = append(out.AuxiliaryBindingPolicies, DecodeAuxiliaryBindingPolicy(r))
	}
	services := r.ReadVectorCount("verifier service")
	out.VerifierServices = make([]IssuerVerifierServiceRecord, 0, services)
	for i := uint64(0); i < services; i++ {
		out.VerifierServices = append(out.VerifierServices, DecodeIssuerVerifierServiceRecord(r))
	}
	out.MetadataSigningKeyID = r.ReadOpaqueFixed(16)
	out.SignatureScheme = r.ReadVarint()
	out.KeyEncoding = r.ReadVarint()
	out.MetadataSignature = r.ReadOpaque16()
	out.Extensions = DecodeExtensions(r)
	return out
}

func (m IssuerMetadata) ValidateStructural(now uint64, allowLab bool) error {
	if m.MetadataVersion != registry.Version20 {
		return fmt.Errorf("protocol: unsupported issuer metadata version 0x%x", m.MetadataVersion)
	}
	if len(m.IssuerID) != 16 {
		return fmt.Errorf("protocol: issuer id must be 16 bytes")
	}
	if now < m.ValidFromUnix || now >= m.ValidUntilUnix {
		return fmt.Errorf("protocol: issuer metadata outside validity interval")
	}
	if len(m.MetadataSigningKeyID) != 16 {
		return fmt.Errorf("protocol: metadata signing key id must be 16 bytes")
	}
	if err := validateIssuerPublicKeyCompatibility(PublicKeyRecord{SignatureScheme: m.SignatureScheme, KeyEncoding: m.KeyEncoding}, allowLab); err != nil {
		return err
	}
	for _, proofType := range m.SupportedProofTypes {
		if err := validateIssuerProofTypeKnown(proofType, allowLab); err != nil {
			return err
		}
	}
	for _, key := range m.TokenKeyMappings {
		if err := key.validateStructural(allowLab); err != nil {
			return err
		}
	}
	for _, policy := range m.OriginInfoPolicies {
		if policy.ValidUntilUnix <= policy.ValidFromUnix {
			return fmt.Errorf("protocol: origin info policy validity interval is empty")
		}
	}
	for _, scope := range m.RelayBucketScopes {
		if len(scope.RelayBucketID) != 16 || len(scope.TokenScopeID) != 16 {
			return fmt.Errorf("protocol: relay bucket scope ids must be 16 bytes")
		}
		if scope.ValidUntilUnix <= scope.ValidFromUnix {
			return fmt.Errorf("protocol: relay bucket scope validity interval is empty")
		}
	}
	for _, policy := range m.AuxiliaryBindingPolicies {
		if err := validateIssuerProofTypeKnown(policy.ProofType, allowLab); err != nil {
			return err
		}
	}
	for _, service := range m.VerifierServices {
		if err := service.validateStructural(allowLab); err != nil {
			return err
		}
	}
	if err := ValidateExtensions(m.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func validateIssuerProofTypeKnown(proofType uint64, allowLab bool) error {
	switch proofType {
	case registry.ProofVOPRFP384SHA384, registry.ProofBlindRSA2048, registry.ProofOpaqueIssuer:
		return nil
	case registry.ProofLabStaticToken:
		if allowLab {
			return nil
		}
		return fmt.Errorf("protocol: lab proof type disabled")
	default:
		return fmt.Errorf("protocol: unknown issuer proof type 0x%x", proofType)
	}
}

func (s IssuerVerifierServiceRecord) validateStructural(allowLab bool) error {
	if len(s.ServiceID) != 16 {
		return fmt.Errorf("protocol: verifier service id must be 16 bytes")
	}
	if err := validateVerifierServiceKind(s.ServiceKind, allowLab); err != nil {
		return err
	}
	if err := validateVerifierServiceProtocol(s.ServiceProtocolID); err != nil {
		return err
	}
	if s.ValidUntilUnix <= s.ValidFromUnix {
		return fmt.Errorf("protocol: verifier service validity interval is empty")
	}
	if err := validateIssuerStatusKnown(s.ServiceStatus, "verifier service"); err != nil {
		return err
	}
	if err := validateIssuerPublicKeyCompatibility(s.ServiceAuthKey, allowLab); err != nil {
		return err
	}
	for _, proofType := range s.AllowedProofTypes {
		if err := validateIssuerProofTypeKnown(proofType, allowLab); err != nil {
			return err
		}
	}
	for _, relayBucketID := range s.AllowedRelayBucketIDs {
		if len(relayBucketID) != 16 {
			return fmt.Errorf("protocol: verifier service relay bucket id must be 16 bytes")
		}
	}
	return nil
}

func validateVerifierServiceKind(serviceKind uint64, allowLab bool) error {
	switch serviceKind {
	case registry.VerifierServiceKindVOPRF, registry.VerifierServiceKindOpaqueIssuer:
		return nil
	}
	if serviceKind >= 0x7000 && serviceKind <= 0x7eff {
		return nil
	}
	if allowLab && serviceKind >= 0x7f00 && serviceKind <= 0x7fff {
		return nil
	}
	return fmt.Errorf("protocol: verifier service kind 0x%x is reserved", serviceKind)
}

func validateVerifierServiceProtocol(serviceProtocolID uint64) error {
	if serviceProtocolID == registry.IssuerVerifierVOPRFMTLS13 {
		return nil
	}
	if serviceProtocolID >= 0x7000 && serviceProtocolID <= 0x7eff {
		return nil
	}
	return fmt.Errorf("protocol: verifier service protocol 0x%x is reserved", serviceProtocolID)
}

func validateIssuerStatusKnown(status uint8, label string) error {
	switch status {
	case registry.IssuerStatusActive, registry.IssuerStatusRetiring, registry.IssuerStatusRevoked:
		return nil
	default:
		return fmt.Errorf("protocol: %s status is reserved", label)
	}
}

func validateIssuerPublicKeyCompatibility(key PublicKeyRecord, allowLab bool) error {
	if !allowLab && key.SignatureScheme == registry.SigEd25519Lab {
		return fmt.Errorf("protocol: lab signature scheme disabled")
	}
	return key.ValidateCompatibility()
}

func (m IssuerMetadata) Unsigned() IssuerMetadata {
	m.MetadataSignature = nil
	return m
}

type IssuerVerifierRequest struct {
	RequestVersion            uint64
	ServiceID                 []byte
	IssuerID                  []byte
	IssuerMetadataHash        []byte
	RelayDescriptorHash       []byte
	RelayBucketID             []byte
	RouteInstanceID           uint64
	HopIndex                  uint8
	ProofType                 uint64
	TokenKeyID                []byte
	TokenNonce                []byte
	ChallengeDigest           []byte
	AuthenticatorInputHash    []byte
	TokenAuthenticator        []byte
	TokenSpentKey             []byte
	ReplayEpochID             uint64
	ReplayEpochValidUntilUnix uint64
	RequestNonce              []byte
	RequestTimeUnix           uint64
}

func (r IssuerVerifierRequest) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.RequestVersion)
	e.WriteOpaqueFixed(r.ServiceID, 16)
	e.WriteOpaqueFixed(r.IssuerID, 16)
	e.WritePreHash(r.IssuerMetadataHash)
	e.WritePreHash(r.RelayDescriptorHash)
	e.WriteOpaqueFixed(r.RelayBucketID, 16)
	e.WriteVarint(r.RouteInstanceID)
	e.WriteUint8(r.HopIndex)
	e.WriteVarint(r.ProofType)
	e.WriteOpaqueFixed(r.TokenKeyID, 32)
	e.WriteOpaqueFixed(r.TokenNonce, 32)
	e.WriteOpaqueFixed(r.ChallengeDigest, 32)
	e.WritePreHash(r.AuthenticatorInputHash)
	e.WriteOpaque16(r.TokenAuthenticator)
	e.WritePreHash(r.TokenSpentKey)
	e.WriteUint64(r.ReplayEpochID)
	e.WriteUint64(r.ReplayEpochValidUntilUnix)
	e.WriteOpaqueFixed(r.RequestNonce, 32)
	e.WriteUint64(r.RequestTimeUnix)
}

func DecodeIssuerVerifierRequest(r *wire.Reader) IssuerVerifierRequest {
	return IssuerVerifierRequest{
		RequestVersion:            r.ReadVarint(),
		ServiceID:                 r.ReadOpaqueFixed(16),
		IssuerID:                  r.ReadOpaqueFixed(16),
		IssuerMetadataHash:        r.ReadPreHash(),
		RelayDescriptorHash:       r.ReadPreHash(),
		RelayBucketID:             r.ReadOpaqueFixed(16),
		RouteInstanceID:           r.ReadVarint(),
		HopIndex:                  r.ReadUint8(),
		ProofType:                 r.ReadVarint(),
		TokenKeyID:                r.ReadOpaqueFixed(32),
		TokenNonce:                r.ReadOpaqueFixed(32),
		ChallengeDigest:           r.ReadOpaqueFixed(32),
		AuthenticatorInputHash:    r.ReadPreHash(),
		TokenAuthenticator:        r.ReadOpaque16(),
		TokenSpentKey:             r.ReadPreHash(),
		ReplayEpochID:             r.ReadUint64(),
		ReplayEpochValidUntilUnix: r.ReadUint64(),
		RequestNonce:              r.ReadOpaqueFixed(32),
		RequestTimeUnix:           r.ReadUint64(),
	}
}

type IssuerVerifierResponse struct {
	ResponseVersion  uint64
	ServiceID        []byte
	RequestHash      []byte
	Decision         uint8
	DecisionDetail   uint8
	TokenSpentKey    []byte
	ValidUntilUnix   uint64
	ResponseNonce    []byte
	ServiceSignature []byte
}

func (r IssuerVerifierResponse) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.ResponseVersion)
	e.WriteOpaqueFixed(r.ServiceID, 16)
	e.WritePreHash(r.RequestHash)
	e.WriteUint8(r.Decision)
	e.WriteUint8(r.DecisionDetail)
	e.WritePreHash(r.TokenSpentKey)
	e.WriteUint64(r.ValidUntilUnix)
	e.WriteOpaqueFixed(r.ResponseNonce, 32)
	e.WriteOpaque16(r.ServiceSignature)
}

func DecodeIssuerVerifierResponse(r *wire.Reader) IssuerVerifierResponse {
	return IssuerVerifierResponse{
		ResponseVersion:  r.ReadVarint(),
		ServiceID:        r.ReadOpaqueFixed(16),
		RequestHash:      r.ReadPreHash(),
		Decision:         r.ReadUint8(),
		DecisionDetail:   r.ReadUint8(),
		TokenSpentKey:    r.ReadPreHash(),
		ValidUntilUnix:   r.ReadUint64(),
		ResponseNonce:    r.ReadOpaqueFixed(32),
		ServiceSignature: r.ReadOpaque16(),
	}
}

func (r IssuerVerifierResponse) Unsigned() IssuerVerifierResponse {
	r.ServiceSignature = nil
	return r
}
