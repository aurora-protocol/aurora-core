package trust

import (
	"bytes"
	"fmt"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type RelayDeploymentVerification struct {
	Descriptor               protocol.RelayDescriptor
	TrustedDescriptorHash    []byte
	Template                 protocol.CoverTemplate
	TemplateAuthorityKey     protocol.PublicKeyRecord
	RequestClassID           uint64
	Suite                    uint64
	Method                   uint64
	NowUnix                  uint64
	MaxTemplateFutureSkew    uint64
	RequirePQDescriptorProof bool
}

type VerifiedRelayDeployment struct {
	verified       bool
	suite          uint64
	method         uint64
	descriptor     protocol.RelayDescriptor
	template       protocol.CoverTemplate
	requestClass   protocol.RequestClass
	descriptorHash []byte
	templateHash   []byte
}

// FirstHopDeploymentMetadata contains scalar bootstrap constraints from a verified deployment.
type FirstHopDeploymentMetadata struct {
	DescriptorValidFromUnix     uint64
	DescriptorValidUntilUnix    uint64
	EpochValidFromUnix          uint64
	EpochValidUntilUnix         uint64
	ReplayEpochValidUntilUnix   uint64
	TemplateValidFromUnix       uint64
	TemplateValidUntilUnix      uint64
	PreludeMaxRequestBodySize   uint64
	PreludeMaxResponseBodySize  uint64
	CapsuleMaxBodySize          uint64
	RequestClassType            uint64
	RequestClassAllowedMethod   uint64
	RequestClassMayCarryPrelude bool
	RequestClassMayCarryCapsule bool
	SelectedSuiteIsSupported    bool
}

func VerifyRelayDeployment(in RelayDeploymentVerification) (VerifiedRelayDeployment, error) {
	descriptor, err := cloneRelayDescriptor(in.Descriptor)
	if err != nil {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: invalid relay descriptor encoding: %w", err)
	}
	template, err := cloneCoverTemplate(in.Template)
	if err != nil {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: invalid cover template encoding: %w", err)
	}
	authorityKey := clonePublicKeyRecord(in.TemplateAuthorityKey)

	descriptorHash, err := RelayDescriptorHash(descriptor)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if len(in.TrustedDescriptorHash) != 48 || !bytes.Equal(descriptorHash, in.TrustedDescriptorHash) {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: relay descriptor does not match trusted hash")
	}
	if err := validateDeploymentDescriptor(descriptor, in.NowUnix); err != nil {
		return VerifiedRelayDeployment{}, err
	}
	descriptorInput, err := RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if err := auroracrypto.VerifySignature(
		descriptor.RelayLongtermClassicalKey.SignatureScheme,
		descriptor.RelayLongtermClassicalKey.KeyEncoding,
		descriptor.RelayLongtermClassicalKey.PublicKey,
		descriptorInput,
		descriptor.SignatureByLongtermClassical,
	); err != nil {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: relay descriptor classical signature: %w", err)
	}
	if in.RequirePQDescriptorProof || len(descriptor.SignatureByLongtermPQ) > 0 {
		if len(descriptor.SignatureByLongtermPQ) == 0 {
			return VerifiedRelayDeployment{}, fmt.Errorf("trust: relay descriptor PQ signature is required")
		}
		if err := auroracrypto.VerifySignature(
			descriptor.RelayLongtermPQKey.SignatureScheme,
			descriptor.RelayLongtermPQKey.KeyEncoding,
			descriptor.RelayLongtermPQKey.PublicKey,
			descriptorInput,
			descriptor.SignatureByLongtermPQ,
		); err != nil {
			return VerifiedRelayDeployment{}, fmt.Errorf("trust: relay descriptor PQ signature: %w", err)
		}
	}

	if err := validateDeploymentTemplate(template, in.Suite, in.NowUnix, in.MaxTemplateFutureSkew); err != nil {
		return VerifiedRelayDeployment{}, err
	}
	templateHash, err := CoverTemplateHash(template)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if countEqualHashes(descriptor.CoverTemplateInstanceHashes, templateHash) != 1 {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: cover template commitment must appear exactly once")
	}
	requestClass, err := deploymentRequestClass(template, in.RequestClassID, in.Method)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if err := authorityKey.ValidateCompatibility(); err != nil {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: invalid template authority key: %w", err)
	}
	if isLabSignatureScheme(authorityKey.SignatureScheme) {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: template authority key uses a lab signature scheme")
	}
	templateFamilyInput, err := CoverTemplateFamilySignatureInput(template)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if err := auroracrypto.VerifySignature(
		authorityKey.SignatureScheme,
		authorityKey.KeyEncoding,
		authorityKey.PublicKey,
		templateFamilyInput,
		template.TemplateFamilySignature,
	); err != nil {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: cover template authority signature: %w", err)
	}
	templateInstanceInput, err := CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		return VerifiedRelayDeployment{}, err
	}
	if err := auroracrypto.VerifySignature(
		descriptor.RelayLongtermClassicalKey.SignatureScheme,
		descriptor.RelayLongtermClassicalKey.KeyEncoding,
		descriptor.RelayLongtermClassicalKey.PublicKey,
		templateInstanceInput,
		template.TemplateInstanceSignature,
	); err != nil {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: cover template instance signature: %w", err)
	}
	if !containsDeploymentID(descriptor.SupportedSuiteIDs, in.Suite) {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: relay descriptor does not support selected suite")
	}
	if !isProductionSuite(in.Suite) {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: selected suite is not a production suite")
	}
	if in.Method != registry.MethodWebH2Stream || !containsDeploymentID(descriptor.SupportedMethodIDs, in.Method) {
		return VerifiedRelayDeployment{}, fmt.Errorf("trust: relay descriptor does not support the HTTP/2 method")
	}

	return VerifiedRelayDeployment{
		verified:       true,
		suite:          in.Suite,
		method:         in.Method,
		descriptor:     descriptor,
		template:       template,
		requestClass:   cloneRequestClass(requestClass),
		descriptorHash: append([]byte(nil), descriptorHash...),
		templateHash:   append([]byte(nil), templateHash...),
	}, nil
}

func (d VerifiedRelayDeployment) Valid() bool {
	return d.verified
}

func (d VerifiedRelayDeployment) Suite() uint64 { return d.suite }

func (d VerifiedRelayDeployment) Method() uint64 { return d.method }

// FirstHopMetadata returns scalar constraints without copying verified descriptor or template data.
func (d VerifiedRelayDeployment) FirstHopMetadata(selectedSuite uint64) FirstHopDeploymentMetadata {
	if selectedSuite == 0 {
		selectedSuite = d.suite
	}
	return FirstHopDeploymentMetadata{
		DescriptorValidFromUnix:     d.descriptor.ValidFromUnix,
		DescriptorValidUntilUnix:    d.descriptor.ValidUntilUnix,
		EpochValidFromUnix:          d.descriptor.EpochValidFromUnix,
		EpochValidUntilUnix:         d.descriptor.EpochValidUntilUnix,
		ReplayEpochValidUntilUnix:   d.descriptor.ReplayEpochValidUntilUnix,
		TemplateValidFromUnix:       d.template.ValidFromUnix,
		TemplateValidUntilUnix:      d.template.ValidUntilUnix,
		PreludeMaxRequestBodySize:   d.template.PreludeEnvelope.MaxRequestBodySize,
		PreludeMaxResponseBodySize:  d.template.PreludeEnvelope.MaxResponseBodySize,
		CapsuleMaxBodySize:          d.template.CapsuleEnvelope.MaxCapsuleBodySize,
		RequestClassType:            d.requestClass.ClassType,
		RequestClassAllowedMethod:   d.requestClass.AllowedMethodFamily,
		RequestClassMayCarryPrelude: d.requestClass.MayCarryPrelude,
		RequestClassMayCarryCapsule: d.requestClass.MayCarryCapsule,
		SelectedSuiteIsSupported:    containsDeploymentID(d.descriptor.SupportedSuiteIDs, selectedSuite),
	}
}

func (d VerifiedRelayDeployment) Descriptor() protocol.RelayDescriptor {
	cloned, _ := cloneRelayDescriptor(d.descriptor)
	return cloned
}

func (d VerifiedRelayDeployment) Template() protocol.CoverTemplate {
	cloned, _ := cloneCoverTemplate(d.template)
	return cloned
}

func (d VerifiedRelayDeployment) RequestClass() protocol.RequestClass {
	return cloneRequestClass(d.requestClass)
}

func (d VerifiedRelayDeployment) DescriptorHash() []byte {
	return append([]byte(nil), d.descriptorHash...)
}

func (d VerifiedRelayDeployment) TemplateHash() []byte {
	return append([]byte(nil), d.templateHash...)
}

func validateDeploymentDescriptor(d protocol.RelayDescriptor, now uint64) error {
	if d.DescriptorVersion != registry.Version20 {
		return fmt.Errorf("trust: unsupported relay descriptor version")
	}
	if len(d.RelayID) != 32 || len(d.ReplayWindowID) != 16 {
		return fmt.Errorf("trust: invalid relay descriptor identifier length")
	}
	if d.ValidUntilUnix <= d.ValidFromUnix || now < d.ValidFromUnix || now >= d.ValidUntilUnix {
		return fmt.Errorf("trust: relay descriptor outside validity interval")
	}
	if d.EpochValidUntilUnix <= d.EpochValidFromUnix || now < d.EpochValidFromUnix || now >= d.EpochValidUntilUnix {
		return fmt.Errorf("trust: relay epoch outside validity interval")
	}
	if now >= d.ReplayEpochValidUntilUnix {
		return fmt.Errorf("trust: relay replay epoch expired")
	}
	for label, key := range map[string]protocol.PublicKeyRecord{
		"long-term classical": d.RelayLongtermClassicalKey,
		"long-term PQ":        d.RelayLongtermPQKey,
		"epoch classical":     d.EpochAuthClassicalKey,
		"epoch PQ":            d.EpochAuthPQKey,
	} {
		if err := key.ValidateCompatibility(); err != nil {
			return fmt.Errorf("trust: invalid relay %s key: %w", label, err)
		}
		if isLabSignatureScheme(key.SignatureScheme) {
			return fmt.Errorf("trust: relay %s key uses a lab signature scheme", label)
		}
	}
	if isPQSignatureScheme(d.RelayLongtermClassicalKey.SignatureScheme) || isPQSignatureScheme(d.EpochAuthClassicalKey.SignatureScheme) {
		return fmt.Errorf("trust: relay classical key uses a PQ signature scheme")
	}
	if !isPQSignatureScheme(d.RelayLongtermPQKey.SignatureScheme) || !isPQSignatureScheme(d.EpochAuthPQKey.SignatureScheme) {
		return fmt.Errorf("trust: relay PQ key does not use a PQ signature scheme")
	}
	for label, value := range map[string][]byte{
		"policy commitment": d.SupportedPolicyIDsCommitment,
		"shape commitment":  d.SupportedShapeIDsCommitment,
		"exit commitment":   d.ExitPolicyCommitment,
		"abuse commitment":  d.AbusePolicyCommitment,
	} {
		if len(value) != 48 {
			return fmt.Errorf("trust: invalid relay %s length", label)
		}
	}
	if len(d.SupportedSuiteIDs) == 0 || len(d.SupportedMethodIDs) == 0 || len(d.CoverTemplateInstanceHashes) == 0 {
		return fmt.Errorf("trust: relay descriptor compatibility lists are empty")
	}
	if hasDuplicateDeploymentIDs(d.SupportedSuiteIDs) || hasDuplicateDeploymentIDs(d.SupportedMethodIDs) {
		return fmt.Errorf("trust: relay descriptor compatibility list contains duplicates")
	}
	for _, hash := range d.CoverTemplateInstanceHashes {
		if len(hash) != 48 {
			return fmt.Errorf("trust: invalid cover template commitment length")
		}
	}
	return nil
}

func validateDeploymentTemplate(t protocol.CoverTemplate, suite, now, maxFutureSkew uint64) error {
	if t.TemplateVersion != registry.Version20 {
		return fmt.Errorf("trust: unsupported cover template version")
	}
	if len(t.TemplateID) == 0 || len(t.TemplateFamilyID) == 0 || len(t.OriginSPKIHash) != 48 || len(t.PublicNameHash) != 48 || len(t.CoverOriginCommitment) != 48 {
		return fmt.Errorf("trust: invalid cover template identifier or hash length")
	}
	if err := ValidateCoverTemplateTime(t, now, maxFutureSkew); err != nil {
		return err
	}
	commitment, err := CoverOriginCommitment(t)
	if err != nil {
		return err
	}
	if !bytes.Equal(commitment, t.CoverOriginCommitment) {
		return fmt.Errorf("trust: cover origin commitment mismatch")
	}
	minimumRequest, minimumResponse := uint64(1536), uint64(6144)
	if suite == registry.SuiteHybrid1024AESGCM || suite == registry.SuiteHybrid1024ChaCha20 {
		minimumRequest, minimumResponse = 2048, 8192
	}
	if t.PreludeEnvelope.MaxRequestBodySize < t.PreludeEnvelope.MinRequestBodySize || t.PreludeEnvelope.MaxRequestBodySize < minimumRequest {
		return fmt.Errorf("trust: invalid cover prelude request envelope")
	}
	if t.PreludeEnvelope.MaxResponseBodySize < t.PreludeEnvelope.MinResponseBodySize || t.PreludeEnvelope.MaxResponseBodySize < minimumResponse {
		return fmt.Errorf("trust: invalid cover prelude response envelope")
	}
	if t.CapsuleEnvelope.MaxCapsuleBodySize < t.CapsuleEnvelope.MinCapsuleBodySize {
		return fmt.Errorf("trust: invalid cover capsule envelope")
	}
	seen := make(map[uint64]struct{}, len(t.RequestClasses))
	privateCapsule := false
	for _, class := range t.RequestClasses {
		if _, exists := seen[class.ClassID]; exists {
			return fmt.Errorf("trust: duplicate cover request class")
		}
		seen[class.ClassID] = struct{}{}
		if err := ValidateRequestClass(class); err != nil {
			return err
		}
		if len(class.PathTemplateID) != 16 {
			return fmt.Errorf("trust: invalid request-class path template ID")
		}
		if class.MayCarryPrelude || class.MayCarryCapsule {
			if !isKnownDeploymentMethod(class.AllowedMethodFamily) {
				return fmt.Errorf("trust: request class has unknown method family")
			}
		}
		if class.ClassType == registry.RequestSidecarOriginSlot && class.AllowedMethodFamily != registry.MethodShadowOrigin {
			return fmt.Errorf("trust: sidecar carrier requires shadow-origin method")
		}
		if class.MayCarryCapsule && (class.ClassType == registry.RequestGatewayOwnedSlot || class.ClassType == registry.RequestSidecarOriginSlot) {
			privateCapsule = true
		}
	}
	if privateCapsule && !t.CapsuleEnvelope.ConsumeFailedBodyLocally {
		return fmt.Errorf("trust: failed private capsule bodies must be consumed locally")
	}
	return nil
}

func deploymentRequestClass(t protocol.CoverTemplate, classID, method uint64) (protocol.RequestClass, error) {
	var matches []protocol.RequestClass
	for _, class := range t.RequestClasses {
		if class.ClassID == classID {
			matches = append(matches, class)
		}
	}
	if len(matches) != 1 {
		return protocol.RequestClass{}, fmt.Errorf("trust: request-class lookup returned %d matches", len(matches))
	}
	class := matches[0]
	if class.ClassType != registry.RequestGatewayOwnedSlot || !class.MayCarryPrelude || !class.MayCarryCapsule {
		return protocol.RequestClass{}, fmt.Errorf("trust: request class is not a gateway-owned bootstrap slot")
	}
	if class.AllowedMethodFamily != method || method != registry.MethodWebH2Stream {
		return protocol.RequestClass{}, fmt.Errorf("trust: request class does not match HTTP/2 method")
	}
	return class, nil
}

func cloneRelayDescriptor(in protocol.RelayDescriptor) (protocol.RelayDescriptor, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.RelayDescriptor{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeRelayDescriptor(r)
	if err := r.Err(); err != nil {
		return protocol.RelayDescriptor{}, err
	}
	if !r.EOF() {
		return protocol.RelayDescriptor{}, fmt.Errorf("trailing relay descriptor bytes")
	}
	return out, nil
}

func cloneCoverTemplate(in protocol.CoverTemplate) (protocol.CoverTemplate, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.CoverTemplate{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeCoverTemplate(r)
	if err := r.Err(); err != nil {
		return protocol.CoverTemplate{}, err
	}
	if !r.EOF() {
		return protocol.CoverTemplate{}, fmt.Errorf("trailing cover template bytes")
	}
	return out, nil
}

func clonePublicKeyRecord(in protocol.PublicKeyRecord) protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: in.SignatureScheme,
		KeyEncoding:     in.KeyEncoding,
		PublicKey:       append([]byte(nil), in.PublicKey...),
	}
}

func cloneRequestClass(in protocol.RequestClass) protocol.RequestClass {
	in.PathTemplateID = append([]byte(nil), in.PathTemplateID...)
	return in
}

func countEqualHashes(values [][]byte, want []byte) int {
	count := 0
	for _, value := range values {
		if bytes.Equal(value, want) {
			count++
		}
	}
	return count
}

func containsDeploymentID(values []uint64, want uint64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isProductionSuite(suite uint64) bool {
	switch suite {
	case registry.SuiteHybrid768AESGCM,
		registry.SuiteHybrid768P256AESGCM,
		registry.SuiteHybrid1024AESGCM,
		registry.SuiteHybrid768ChaCha20,
		registry.SuiteHybrid768P256ChaCha20,
		registry.SuiteHybrid1024ChaCha20:
		return true
	default:
		return false
	}
}

func isKnownDeploymentMethod(method uint64) bool {
	switch method {
	case registry.MethodWebH2Stream,
		registry.MethodWebH1WS,
		registry.MethodShadowOrigin,
		registry.MethodWebH3Stream,
		registry.MethodWebH3ExtDgram,
		registry.MethodMasqueConnectIP,
		registry.MethodMasqueConnectUDP,
		registry.MethodDirectQUICLab:
		return true
	default:
		return false
	}
}

func hasDuplicateDeploymentIDs(values []uint64) bool {
	seen := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func isPQSignatureScheme(scheme uint64) bool {
	return scheme == registry.SigMLDSA65 || scheme == registry.SigMLDSA87
}

// isLabSignatureScheme reports whether the scheme is lab-only and therefore
// never acceptable on the production relay-deployment verification path.
func isLabSignatureScheme(scheme uint64) bool {
	return scheme == registry.SigEd25519Lab
}
