package client

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	nativeProvisioningFormat             uint64 = 1
	maximumNativeProvisioningBytes              = 1 << 20
	maximumNativeProvisioningURLBytes           = 2048
	maximumNativeProvisioningObjectBytes        = 256 << 10
	maximumNativeProvisioningPolicyBytes        = 32 << 10
	maximumNativeProvisioningHintsBytes         = 32 << 10
	nativeTemplateFutureSkew                    = 5 * time.Minute
)

// NativeProvisioning is the bounded canonical input for a portable native client session.
type NativeProvisioning struct {
	RelayURL              string
	IssuerURL             string
	IssuerCarrierPath     string
	Descriptor            []byte
	TrustedDescriptorHash []byte
	Template              []byte
	TemplateAuthorityKey  []byte
	RequestClassID        uint64
	Suite                 uint64
	AccessHint            []byte
	PolicyOffer           []byte
	TransportHints        []byte
}

type nativeProvisioningObjects struct {
	descriptor           protocol.RelayDescriptor
	template             protocol.CoverTemplate
	templateAuthorityKey protocol.PublicKeyRecord
	accessHint           admission.AccessHintCredential
	policyOffer          protocol.PolicyOffer
	transportHints       protocol.ClientTransportHints
}

// EncodeNativeProvisioning encodes bounded native provisioning fields for transport or storage.
func EncodeNativeProvisioning(provisioning NativeProvisioning) ([]byte, error) {
	if err := provisioning.validateContainer(); err != nil {
		return nil, err
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(nativeProvisioningFormat)
	encoder.WriteOpaque16([]byte(provisioning.RelayURL))
	encoder.WriteOpaque16([]byte(provisioning.IssuerURL))
	encoder.WriteOpaque16([]byte(provisioning.IssuerCarrierPath))
	encoder.WriteOpaque24(provisioning.Descriptor)
	encoder.WritePreHash(provisioning.TrustedDescriptorHash)
	encoder.WriteOpaque24(provisioning.Template)
	encoder.WriteOpaque16(provisioning.TemplateAuthorityKey)
	encoder.WriteVarint(provisioning.RequestClassID)
	encoder.WriteVarint(provisioning.Suite)
	encoder.WriteOpaque16(provisioning.AccessHint)
	encoder.WriteOpaque24(provisioning.PolicyOffer)
	encoder.WriteOpaque24(provisioning.TransportHints)
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("client: encode native provisioning: %w", err)
	}
	if len(encoded) > maximumNativeProvisioningBytes {
		return nil, fmt.Errorf("client: native provisioning exceeds size limit")
	}
	return encoded, nil
}

// ParseNativeProvisioning validates a complete native provisioning bundle before use.
func ParseNativeProvisioning(encoded []byte, now time.Time) (NativeProvisioning, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeProvisioningBytes {
		return NativeProvisioning{}, fmt.Errorf("client: native provisioning size is invalid")
	}
	reader := wire.NewReader(encoded)
	if format := reader.ReadVarint(); format != nativeProvisioningFormat {
		return NativeProvisioning{}, fmt.Errorf("client: unsupported native provisioning format")
	}
	provisioning := NativeProvisioning{
		RelayURL:              string(readNativeProvisioningOpaque16(reader, maximumNativeProvisioningURLBytes)),
		IssuerURL:             string(readNativeProvisioningOpaque16(reader, maximumNativeProvisioningURLBytes)),
		IssuerCarrierPath:     string(readNativeProvisioningOpaque16(reader, maximumNativeProvisioningURLBytes)),
		Descriptor:            readNativeProvisioningOpaque24(reader, maximumNativeProvisioningObjectBytes),
		TrustedDescriptorHash: reader.ReadPreHash(),
		Template:              readNativeProvisioningOpaque24(reader, maximumNativeProvisioningObjectBytes),
		TemplateAuthorityKey:  readNativeProvisioningOpaque16(reader, maximumNativeProvisioningObjectBytes),
		RequestClassID:        reader.ReadVarint(),
		Suite:                 reader.ReadVarint(),
		AccessHint:            readNativeProvisioningOpaque16(reader, maximumNativeProvisioningObjectBytes),
		PolicyOffer:           readNativeProvisioningOpaque24(reader, maximumNativeProvisioningPolicyBytes),
		TransportHints:        readNativeProvisioningOpaque24(reader, maximumNativeProvisioningHintsBytes),
	}
	if reader.Err() != nil || !reader.EOF() {
		return NativeProvisioning{}, fmt.Errorf("client: malformed native provisioning")
	}
	if err := provisioning.validateAt(now); err != nil {
		return NativeProvisioning{}, err
	}
	return provisioning, nil
}

// VerifiedDeployment returns the deployment authenticated by this provisioning bundle.
func (p NativeProvisioning) VerifiedDeployment(now time.Time) (trust.VerifiedRelayDeployment, error) {
	_, deployment, err := p.validatedObjectsAndDeployment(now)
	return deployment, err
}

// ClientDriverConfig constructs a fully validated portable client configuration.
func (p NativeProvisioning) ClientDriverConfig(now time.Time, provider handshake.ClientProofProvider) (handshake.ClientDriverConfig, error) {
	objects, deployment, err := p.validatedObjectsAndDeployment(now)
	if err != nil {
		return handshake.ClientDriverConfig{}, err
	}
	config := handshake.ClientDriverConfig{
		Deployment:     deployment,
		Suite:          p.Suite,
		AccessHint:     objects.accessHint,
		PolicyOffer:    objects.policyOffer,
		TransportHints: objects.transportHints,
		ProofProvider:  provider,
		RequirePQ:      true,
		SessionLimits: session.Limits{
			MaxQueuedPackets:       64,
			MaxQueuedBytes:         1 << 20,
			ControlReservedPackets: 2,
			ControlReservedBytes:   8 << 10,
			ReplayWindow:           1024,
		},
	}
	if _, err := handshake.NewClientDriver(config); err != nil {
		return handshake.ClientDriverConfig{}, fmt.Errorf("client: native provisioning client configuration: %w", err)
	}
	return config, nil
}

func (p NativeProvisioning) validateAt(now time.Time) error {
	_, _, err := p.validatedObjectsAndDeployment(now)
	return err
}

func (p NativeProvisioning) validatedObjectsAndDeployment(now time.Time) (nativeProvisioningObjects, trust.VerifiedRelayDeployment, error) {
	if err := p.validateContainer(); err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, fmt.Errorf("client: native provisioning requires a valid time")
	}
	objects, err := p.decodeObjects()
	if err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
	}
	if objects.accessHint.ExpiryUnix == 0 || uint64(now.Unix()) >= objects.accessHint.ExpiryUnix {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, fmt.Errorf("client: native provisioning access hint is expired")
	}
	if err := validateNativePolicy(objects.policyOffer, objects.transportHints, p.Suite); err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
	}
	deployment, err := p.verifyDeployment(now, objects)
	if err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, fmt.Errorf("client: native provisioning relay deployment: %w", err)
	}
	return objects, deployment, nil
}

func (p NativeProvisioning) verifyDeployment(now time.Time, objects nativeProvisioningObjects) (trust.VerifiedRelayDeployment, error) {
	return trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor:               objects.descriptor,
		TrustedDescriptorHash:    p.TrustedDescriptorHash,
		Template:                 objects.template,
		TemplateAuthorityKey:     objects.templateAuthorityKey,
		RequestClassID:           p.RequestClassID,
		Suite:                    p.Suite,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  uint64(now.Unix()),
		MaxTemplateFutureSkew:    uint64(nativeTemplateFutureSkew / time.Second),
		RequirePQDescriptorProof: true,
	})
}

func (p NativeProvisioning) validateContainer() error {
	if err := validateNativeHTTPSURL(p.RelayURL, true); err != nil {
		return fmt.Errorf("client: invalid relay URL: %w", err)
	}
	if err := validateNativeHTTPSURL(p.IssuerURL, false); err != nil {
		return fmt.Errorf("client: invalid issuer URL: %w", err)
	}
	if err := validateNativeCarrierPath(p.IssuerCarrierPath); err != nil {
		return fmt.Errorf("client: invalid issuer carrier path: %w", err)
	}
	for _, field := range []struct {
		label   string
		value   []byte
		maximum int
	}{
		{"relay descriptor", p.Descriptor, maximumNativeProvisioningObjectBytes},
		{"trusted descriptor hash", p.TrustedDescriptorHash, 48},
		{"cover template", p.Template, maximumNativeProvisioningObjectBytes},
		{"template authority key", p.TemplateAuthorityKey, maximumNativeProvisioningObjectBytes},
		{"access hint", p.AccessHint, maximumNativeProvisioningObjectBytes},
		{"policy offer", p.PolicyOffer, maximumNativeProvisioningPolicyBytes},
		{"transport hints", p.TransportHints, maximumNativeProvisioningHintsBytes},
	} {
		if len(field.value) == 0 || len(field.value) > field.maximum {
			return fmt.Errorf("client: native provisioning %s size is invalid", field.label)
		}
	}
	if p.RequestClassID == 0 || p.RequestClassID > wire.MaxVarint || p.Suite == 0 || p.Suite > wire.MaxVarint {
		return fmt.Errorf("client: native provisioning identifiers are invalid")
	}
	return nil
}

func (p NativeProvisioning) decodeObjects() (nativeProvisioningObjects, error) {
	descriptor, err := decodeNativeRelayDescriptor(p.Descriptor)
	if err != nil {
		return nativeProvisioningObjects{}, err
	}
	template, err := decodeNativeCoverTemplate(p.Template)
	if err != nil {
		return nativeProvisioningObjects{}, err
	}
	authorityKey, err := decodeNativePublicKeyRecord(p.TemplateAuthorityKey)
	if err != nil {
		return nativeProvisioningObjects{}, err
	}
	accessHint, err := admission.DecodeAccessHintCredential(p.AccessHint)
	if err != nil {
		return nativeProvisioningObjects{}, fmt.Errorf("client: invalid native access hint: %w", err)
	}
	policyOffer, err := decodeNativePolicyOffer(p.PolicyOffer)
	if err != nil {
		return nativeProvisioningObjects{}, err
	}
	transportHints, err := decodeNativeTransportHints(p.TransportHints)
	if err != nil {
		return nativeProvisioningObjects{}, err
	}
	return nativeProvisioningObjects{
		descriptor:           descriptor,
		template:             template,
		templateAuthorityKey: authorityKey,
		accessHint:           accessHint,
		policyOffer:          policyOffer,
		transportHints:       transportHints,
	}, nil
}

func decodeNativeRelayDescriptor(encoded []byte) (protocol.RelayDescriptor, error) {
	reader := wire.NewReader(encoded)
	value := protocol.DecodeRelayDescriptor(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.RelayDescriptor{}, fmt.Errorf("client: malformed native relay descriptor")
	}
	return value, nil
}

func decodeNativeCoverTemplate(encoded []byte) (protocol.CoverTemplate, error) {
	reader := wire.NewReader(encoded)
	value := protocol.DecodeCoverTemplate(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.CoverTemplate{}, fmt.Errorf("client: malformed native cover template")
	}
	return value, nil
}

func decodeNativePublicKeyRecord(encoded []byte) (protocol.PublicKeyRecord, error) {
	reader := wire.NewReader(encoded)
	value := protocol.DecodePublicKeyRecord(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.PublicKeyRecord{}, fmt.Errorf("client: malformed native template authority key")
	}
	return value, nil
}

func decodeNativePolicyOffer(encoded []byte) (protocol.PolicyOffer, error) {
	reader := wire.NewReader(encoded)
	value := protocol.DecodePolicyOffer(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.PolicyOffer{}, fmt.Errorf("client: malformed native policy offer")
	}
	return value, nil
}

func decodeNativeTransportHints(encoded []byte) (protocol.ClientTransportHints, error) {
	reader := wire.NewReader(encoded)
	value := protocol.DecodeClientTransportHints(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.ClientTransportHints{}, fmt.Errorf("client: malformed native transport hints")
	}
	return value, nil
}

func validateNativePolicy(offer protocol.PolicyOffer, hints protocol.ClientTransportHints, suite uint64) error {
	if err := offer.ValidateStructural(); err != nil {
		return fmt.Errorf("client: invalid native policy offer: %w", err)
	}
	if err := hints.ValidatePrototype(); err != nil {
		return fmt.Errorf("client: invalid native transport hints: %w", err)
	}
	if !containsNativeID(offer.OfferedVersions, registry.Version20) ||
		!containsNativeID(offer.OfferedSuites, suite) ||
		!containsNativeID(offer.OfferedMethods, registry.MethodWebH2Stream) {
		return fmt.Errorf("client: native policy offer omits the selected protocol values")
	}
	for _, offeredSuite := range offer.OfferedSuites {
		if !isNativeProductionSuite(offeredSuite) {
			return fmt.Errorf("client: native policy offer contains a non-production suite")
		}
	}
	for _, offeredMethod := range offer.OfferedMethods {
		if !isNativeProductionMethod(offeredMethod) {
			return fmt.Errorf("client: native policy offer contains a non-production method")
		}
	}
	if offer.MinimumPolicyID == registry.PolicyLab || offer.RequestedPolicyID == registry.PolicyLab {
		return fmt.Errorf("client: native policy offer contains a lab policy")
	}
	return nil
}

func validateNativeHTTPSURL(raw string, requirePath bool) error {
	if len(raw) == 0 || len(raw) > maximumNativeProvisioningURLBytes {
		return fmt.Errorf("URL length is invalid")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return fmt.Errorf("URL must be an HTTPS authority without user info, query, or fragment")
	}
	if requirePath {
		if err := validateNativeCarrierPath(parsed.Path); err != nil {
			return fmt.Errorf("URL path: %w", err)
		}
		return nil
	}
	if parsed.Path != "" {
		return fmt.Errorf("issuer URL must not include a path")
	}
	return nil
}

func validateNativeCarrierPath(raw string) error {
	if len(raw) < 2 || len(raw) > maximumNativeProvisioningURLBytes || !strings.HasPrefix(raw, "/") {
		return fmt.Errorf("path length or prefix is invalid")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return err
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != raw || path.Clean(raw) != raw || strings.Contains(raw, "//") {
		return fmt.Errorf("path is not canonical")
	}
	return nil
}

func readNativeProvisioningOpaque16(reader *wire.Reader, maximum int) []byte {
	value := reader.ReadOpaque16()
	if len(value) > maximum {
		reader.SetErr(fmt.Errorf("client: native provisioning field exceeds limit"))
	}
	return value
}

func readNativeProvisioningOpaque24(reader *wire.Reader, maximum int) []byte {
	value := reader.ReadOpaque24()
	if len(value) > maximum {
		reader.SetErr(fmt.Errorf("client: native provisioning field exceeds limit"))
	}
	return value
}

func containsNativeID(values []uint64, want uint64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isNativeProductionSuite(suite uint64) bool {
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

func isNativeProductionMethod(method uint64) bool {
	switch method {
	case registry.MethodWebH2Stream,
		registry.MethodWebH1WS,
		registry.MethodShadowOrigin,
		registry.MethodWebH3Stream,
		registry.MethodWebH3ExtDgram,
		registry.MethodMasqueConnectIP,
		registry.MethodMasqueConnectUDP:
		return true
	default:
		return false
	}
}
