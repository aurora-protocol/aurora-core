package client

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	nativeProvisioningFormat                  uint64 = 5
	maximumNativeProvisioningBytes                   = 1 << 20
	maximumNativeProvisioningURLBytes                = 2048
	maximumNativeProvisioningObjectBytes             = 256 << 10
	maximumNativeProvisioningPolicyBytes             = 32 << 10
	maximumNativeProvisioningHintsBytes              = 32 << 10
	maximumNativeProvisioningHeaderBytes             = 64 << 10
	maximumNativeProvisioningTrustRootBytes          = 64 << 10
	maximumNativeProvisioningTrustRoots              = 16
	maximumNativeProvisioningHeaderEntries           = 64
	maximumNativeProvisioningHeaderNameBytes         = 64
	maximumNativeProvisioningHeaderValueBytes        = 4096
	nativeTemplateFutureSkew                         = 5 * time.Minute
)

// NativeProvisioning is the bounded canonical input for a portable native client session.
type NativeProvisioning struct {
	RelayURL              string
	IssuerURL             string
	IssuerCarrierPath     string
	IssuerMetadata        []byte
	SignedSeed            []byte
	Descriptor            []byte
	TrustedDescriptorHash []byte
	Template              []byte
	TemplateAuthorityKey  []byte
	RequestClassID        uint64
	Suite                 uint64
	AccessHint            []byte
	PolicyOffer           []byte
	TransportHints        []byte
	RelayExpectedStatus   uint64
	RelayRequestHeaders   []byte
	RelayResponseHeaders  []byte
	RelayTrustRoots       []byte
	signedSeedTrust       NativeProvisioningTrust
}

type nativeProvisioningObjects struct {
	descriptor           protocol.RelayDescriptor
	template             protocol.CoverTemplate
	templateAuthorityKey protocol.PublicKeyRecord
	issuerMetadata       protocol.IssuerMetadata
	accessHint           admission.AccessHintCredential
	policyOffer          protocol.PolicyOffer
	transportHints       protocol.ClientTransportHints
	relayRequestHeaders  http.Header
	relayResponseHeaders http.Header
	relayTrustRoots      []*x509.Certificate
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
	encoder.WriteOpaque24(provisioning.IssuerMetadata)
	encoder.WriteOpaque24(provisioning.SignedSeed)
	encoder.WriteOpaque24(provisioning.Descriptor)
	encoder.WritePreHash(provisioning.TrustedDescriptorHash)
	encoder.WriteOpaque24(provisioning.Template)
	encoder.WriteOpaque16(provisioning.TemplateAuthorityKey)
	encoder.WriteVarint(provisioning.RequestClassID)
	encoder.WriteVarint(provisioning.Suite)
	encoder.WriteOpaque16(provisioning.AccessHint)
	encoder.WriteOpaque24(provisioning.PolicyOffer)
	encoder.WriteOpaque24(provisioning.TransportHints)
	encoder.WriteVarint(provisioning.RelayExpectedStatus)
	encoder.WriteOpaque16(provisioning.RelayRequestHeaders)
	encoder.WriteOpaque16(provisioning.RelayResponseHeaders)
	encoder.WriteOpaque24(provisioning.RelayTrustRoots)
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
	return NativeProvisioning{}, ErrNativeProvisioningTrustRequired
}

// ParseNativeProvisioningWithTrust validates a complete native provisioning
// bundle using roots supplied independently from the bundle itself.
func ParseNativeProvisioningWithTrust(encoded []byte, signedSeedTrust NativeProvisioningTrust, now time.Time) (NativeProvisioning, error) {
	if err := signedSeedTrust.validate(); err != nil {
		return NativeProvisioning{}, fmt.Errorf("client: native provisioning trust: %w", err)
	}
	provisioning, err := parseNativeProvisioningContainer(encoded)
	if err != nil {
		return NativeProvisioning{}, err
	}
	provisioning.signedSeedTrust = signedSeedTrust
	if err := provisioning.validateAt(now); err != nil {
		zeroNativeProvisioning(&provisioning)
		return NativeProvisioning{}, err
	}
	return provisioning, nil
}

func parseNativeProvisioningContainer(encoded []byte) (NativeProvisioning, error) {
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
		IssuerMetadata:        readNativeProvisioningOpaque24(reader, maximumNativeProvisioningObjectBytes),
		SignedSeed:            readNativeProvisioningOpaque24(reader, maximumNativeProvisioningObjectBytes),
		Descriptor:            readNativeProvisioningOpaque24(reader, maximumNativeProvisioningObjectBytes),
		TrustedDescriptorHash: reader.ReadPreHash(),
		Template:              readNativeProvisioningOpaque24(reader, maximumNativeProvisioningObjectBytes),
		TemplateAuthorityKey:  readNativeProvisioningOpaque16(reader, maximumNativeProvisioningObjectBytes),
		RequestClassID:        reader.ReadVarint(),
		Suite:                 reader.ReadVarint(),
		AccessHint:            readNativeProvisioningOpaque16(reader, maximumNativeProvisioningObjectBytes),
		PolicyOffer:           readNativeProvisioningOpaque24(reader, maximumNativeProvisioningPolicyBytes),
		TransportHints:        readNativeProvisioningOpaque24(reader, maximumNativeProvisioningHintsBytes),
		RelayExpectedStatus:   reader.ReadVarint(),
		RelayRequestHeaders:   readNativeProvisioningOpaque16(reader, maximumNativeProvisioningHeaderBytes),
		RelayResponseHeaders:  readNativeProvisioningOpaque16(reader, maximumNativeProvisioningHeaderBytes),
		RelayTrustRoots:       readNativeProvisioningOpaque24(reader, maximumNativeProvisioningTrustRootBytes*maximumNativeProvisioningTrustRoots),
	}
	if reader.Err() != nil || !reader.EOF() {
		zeroNativeProvisioning(&provisioning)
		return NativeProvisioning{}, fmt.Errorf("client: malformed native provisioning")
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

// NewHTTP2ClientCarrierOpener creates the pinned first-hop carrier authenticated by this bundle.
func (p NativeProvisioning) NewHTTP2ClientCarrierOpener(now time.Time) (handshake.ClientCarrierOpener, error) {
	objects, deployment, err := p.validatedObjectsAndDeployment(now)
	if err != nil {
		return nil, err
	}
	relayURL, err := url.Parse(p.RelayURL)
	if err != nil {
		return nil, fmt.Errorf("client: parse native relay URL: %w", err)
	}
	template := deployment.Template()
	requestClass := deployment.RequestClass()
	tlsConfig, err := nativeProvisioningTLSConfig(objects.relayTrustRoots, template.OriginSPKIHash)
	if err != nil {
		return nil, err
	}
	built, err := transport.BuildStreamingH2CarrierRequest(transport.CarrierRequestInput{
		Plan: transport.CarrierPlan{
			Carrier: transport.Carrier{MethodID: registry.MethodWebH2Stream},
			UDPMode: transport.UDPOverStreamFallback,
		},
		Template:       template,
		RequestClassID: p.RequestClassID,
		Scheme:         relayURL.Scheme,
		Authority:      relayURL.Host,
		Path:           relayURL.Path,
		Header:         objects.relayRequestHeaders,
	})
	if err != nil {
		return nil, fmt.Errorf("client: build native HTTP/2 carrier request: %w", err)
	}
	opener, err := transport.NewHTTP2ClientCarrierOpener(transport.HTTP2ClientCarrierConfig{
		Request:            built.Request,
		TLSConfig:          tlsConfig,
		BindingMetadata:    nativeHTTP2BindingMetadata(template, requestClass),
		ExpectedStatus:     int(p.RelayExpectedStatus),
		ExpectedHeader:     objects.relayResponseHeaders,
		MaxRecordBodyBytes: transport.DefaultMaxRecordBodyBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("client: create native HTTP/2 carrier opener: %w", err)
	}
	return opener, nil
}

func (p NativeProvisioning) validateAt(now time.Time) error {
	_, _, err := p.validatedObjectsAndDeployment(now)
	return err
}

func (p NativeProvisioning) validatedObjectsAndDeployment(now time.Time) (nativeProvisioningObjects, trust.VerifiedRelayDeployment, error) {
	return p.validatedObjectsAndDeploymentAt(now, true)
}

func (p NativeProvisioning) validatedObjectsAndDeploymentAt(now time.Time, requireUsableAccessHint bool) (nativeProvisioningObjects, trust.VerifiedRelayDeployment, error) {
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
	if requireUsableAccessHint && (objects.accessHint.ExpiryUnix == 0 || uint64(now.Unix()) >= objects.accessHint.ExpiryUnix) {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, fmt.Errorf("client: native provisioning access hint is expired")
	}
	seed, authorityKeys, err := p.verifiedSignedSeedAt(now)
	if err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
	}
	if err := validateNativeSeedIssuerMetadataBinding(seed, objects.issuerMetadata); err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
	}
	if !bytes.Equal(seed.TokenIssuerHint, objects.accessHint.HintIssuerID) {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, fmt.Errorf("client: signed seed issuer does not match access hint")
	}
	if err := validateNativeIssuerMetadata(objects.issuerMetadata, authorityKeys, uint64(now.Unix())); err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
	}
	if err := validateNativeIssuerScope(objects.issuerMetadata, objects.accessHint, uint64(now.Unix())); err != nil {
		return nativeProvisioningObjects{}, trust.VerifiedRelayDeployment{}, err
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
	if len(p.IssuerMetadata) == 0 || len(p.IssuerMetadata) > maximumNativeProvisioningObjectBytes {
		return fmt.Errorf("client: native provisioning issuer metadata size is invalid")
	}
	if len(p.SignedSeed) == 0 || len(p.SignedSeed) > maximumNativeProvisioningObjectBytes {
		return fmt.Errorf("client: native provisioning signed seed size is invalid")
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
		{"relay request headers", p.RelayRequestHeaders, maximumNativeProvisioningHeaderBytes},
		{"relay response headers", p.RelayResponseHeaders, maximumNativeProvisioningHeaderBytes},
		{"relay trust roots", p.RelayTrustRoots, maximumNativeProvisioningTrustRootBytes * maximumNativeProvisioningTrustRoots},
	} {
		if len(field.value) == 0 || len(field.value) > field.maximum {
			return fmt.Errorf("client: native provisioning %s size is invalid", field.label)
		}
	}
	if p.RequestClassID == 0 || p.RequestClassID > wire.MaxVarint || p.Suite == 0 || p.Suite > wire.MaxVarint {
		return fmt.Errorf("client: native provisioning identifiers are invalid")
	}
	if p.RelayExpectedStatus < http.StatusOK || p.RelayExpectedStatus > 599 {
		return fmt.Errorf("client: native provisioning relay response status is invalid")
	}
	if _, err := decodeNativeHeaders(p.RelayRequestHeaders); err != nil {
		return fmt.Errorf("client: invalid native relay request headers: %w", err)
	}
	if _, err := decodeNativeHeaders(p.RelayResponseHeaders); err != nil {
		return fmt.Errorf("client: invalid native relay response headers: %w", err)
	}
	if _, err := decodeNativeTrustRoots(p.RelayTrustRoots); err != nil {
		return fmt.Errorf("client: invalid native relay trust roots: %w", err)
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
	issuerMetadata, err := decodeNativeIssuerMetadata(p.IssuerMetadata)
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
	relayRequestHeaders, err := decodeNativeHeaders(p.RelayRequestHeaders)
	if err != nil {
		return nativeProvisioningObjects{}, fmt.Errorf("client: invalid native relay request headers: %w", err)
	}
	relayResponseHeaders, err := decodeNativeHeaders(p.RelayResponseHeaders)
	if err != nil {
		return nativeProvisioningObjects{}, fmt.Errorf("client: invalid native relay response headers: %w", err)
	}
	relayTrustRoots, err := decodeNativeTrustRoots(p.RelayTrustRoots)
	if err != nil {
		return nativeProvisioningObjects{}, fmt.Errorf("client: invalid native relay trust roots: %w", err)
	}
	return nativeProvisioningObjects{
		descriptor:           descriptor,
		template:             template,
		templateAuthorityKey: authorityKey,
		issuerMetadata:       issuerMetadata,
		accessHint:           accessHint,
		policyOffer:          policyOffer,
		transportHints:       transportHints,
		relayRequestHeaders:  relayRequestHeaders,
		relayResponseHeaders: relayResponseHeaders,
		relayTrustRoots:      relayTrustRoots,
	}, nil
}

func (p NativeProvisioning) verifiedIssuerMetadataAt(now time.Time) (protocol.IssuerMetadata, error) {
	if now.IsZero() || now.Unix() < 0 {
		return protocol.IssuerMetadata{}, fmt.Errorf("client: native issuer metadata requires a valid time")
	}
	if err := validateNativeHTTPSURL(p.IssuerURL, false); err != nil {
		return protocol.IssuerMetadata{}, fmt.Errorf("client: invalid issuer URL: %w", err)
	}
	if err := validateNativeCarrierPath(p.IssuerCarrierPath); err != nil {
		return protocol.IssuerMetadata{}, fmt.Errorf("client: invalid issuer carrier path: %w", err)
	}
	if len(p.IssuerMetadata) == 0 || len(p.IssuerMetadata) > maximumNativeProvisioningObjectBytes || len(p.SignedSeed) == 0 || len(p.SignedSeed) > maximumNativeProvisioningObjectBytes {
		return protocol.IssuerMetadata{}, fmt.Errorf("client: native issuer metadata inputs are invalid")
	}
	metadata, err := decodeNativeIssuerMetadata(p.IssuerMetadata)
	if err != nil {
		return protocol.IssuerMetadata{}, err
	}
	seed, authorityKeys, err := p.verifiedSignedSeedAt(now)
	if err != nil {
		return protocol.IssuerMetadata{}, err
	}
	if err := validateNativeSeedIssuerMetadataBinding(seed, metadata); err != nil {
		return protocol.IssuerMetadata{}, err
	}
	if err := validateNativeIssuerMetadata(metadata, authorityKeys, uint64(now.Unix())); err != nil {
		return protocol.IssuerMetadata{}, err
	}
	return metadata, nil
}

func (p NativeProvisioning) verifiedSignedSeedAt(now time.Time) (protocol.SignedSeedRecord, []protocol.AuthorityKeyRecord, error) {
	if now.IsZero() || now.Unix() < 0 {
		return protocol.SignedSeedRecord{}, nil, fmt.Errorf("client: native signed seed requires a valid time")
	}
	if len(p.SignedSeed) == 0 || len(p.SignedSeed) > maximumNativeProvisioningObjectBytes {
		return protocol.SignedSeedRecord{}, nil, fmt.Errorf("client: native signed seed inputs are invalid")
	}
	seed, err := decodeNativeSignedSeed(p.SignedSeed)
	if err != nil {
		return protocol.SignedSeedRecord{}, nil, err
	}
	store, err := p.signedSeedTrust.newStore()
	if err != nil {
		return protocol.SignedSeedRecord{}, nil, fmt.Errorf("client: native signed seed trust: %w", err)
	}
	if err := store.Accept(seed, uint64(now.Unix())); err != nil {
		return protocol.SignedSeedRecord{}, nil, fmt.Errorf("client: native signed seed verification: %w", err)
	}
	return seed, store.AuthorityKeys(), nil
}

func validateNativeSeedIssuerMetadataBinding(seed protocol.SignedSeedRecord, metadata protocol.IssuerMetadata) error {
	if !hasNativeNonZeroPreHash(seed.IssuerMetadataHash) {
		return fmt.Errorf("client: signed seed does not commit to issuer metadata")
	}
	metadataHash, err := trust.IssuerMetadataHash(metadata)
	if err != nil {
		return err
	}
	if !bytes.Equal(seed.IssuerMetadataHash, metadataHash) {
		return fmt.Errorf("client: signed seed issuer metadata hash mismatch")
	}
	return nil
}

func hasNativeNonZeroPreHash(value []byte) bool {
	if len(value) != 48 {
		return false
	}
	for _, byteValue := range value {
		if byteValue != 0 {
			return true
		}
	}
	return false
}

func validateNativeIssuerMetadata(metadata protocol.IssuerMetadata, authorityKeys []protocol.AuthorityKeyRecord, nowUnix uint64) error {
	if err := trust.VerifyIssuerMetadataSignature(metadata, authorityKeys, nowUnix); err != nil {
		return fmt.Errorf("client: native issuer metadata verification: %w", err)
	}
	if !containsNativeID(metadata.SupportedProofTypes, registry.ProofBlindRSA2048) {
		return fmt.Errorf("client: native issuer metadata does not support Blind RSA")
	}
	for _, key := range metadata.TokenKeyMappings {
		if key.ProofType == registry.ProofBlindRSA2048 && key.Validate(nowUnix) == nil {
			return nil
		}
	}
	return fmt.Errorf("client: native issuer metadata has no active Blind RSA key")
}

func validateNativeIssuerScope(metadata protocol.IssuerMetadata, hint admission.AccessHintCredential, nowUnix uint64) error {
	if !bytes.Equal(metadata.IssuerID, hint.HintIssuerID) {
		return fmt.Errorf("client: native issuer metadata does not match access hint issuer")
	}
	for _, scope := range metadata.RelayBucketScopes {
		if bytes.Equal(scope.RelayBucketID, hint.RelayBucketID) && nowUnix >= scope.ValidFromUnix && nowUnix < scope.ValidUntilUnix {
			return nil
		}
	}
	return fmt.Errorf("client: native issuer metadata does not authorize access hint relay bucket")
}

func decodeNativeIssuerMetadata(encoded []byte) (protocol.IssuerMetadata, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeProvisioningObjectBytes {
		return protocol.IssuerMetadata{}, fmt.Errorf("client: native issuer metadata size is invalid")
	}
	reader := wire.NewReader(encoded)
	metadata := protocol.DecodeIssuerMetadata(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.IssuerMetadata{}, fmt.Errorf("client: malformed native issuer metadata")
	}
	return metadata, nil
}

func decodeNativeSignedSeed(encoded []byte) (protocol.SignedSeedRecord, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeProvisioningObjectBytes {
		return protocol.SignedSeedRecord{}, fmt.Errorf("client: native signed seed size is invalid")
	}
	reader := wire.NewReader(encoded)
	seed := protocol.DecodeSignedSeedRecord(reader)
	if reader.Err() != nil || !reader.EOF() {
		return protocol.SignedSeedRecord{}, fmt.Errorf("client: malformed native signed seed")
	}
	return seed, nil
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

// EncodeNativeHeaders returns the canonical, bounded carrier-header representation.
func EncodeNativeHeaders(header http.Header) ([]byte, error) {
	fields, err := nativeHeaderFields(header)
	if err != nil {
		return nil, err
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(uint64(len(fields)))
	for _, field := range fields {
		encoder.WriteOpaque8([]byte(field.name))
		encoder.WriteOpaque16([]byte(field.value))
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("client: encode native headers: %w", err)
	}
	if len(encoded) > maximumNativeProvisioningHeaderBytes {
		return nil, fmt.Errorf("client: native headers exceed size limit")
	}
	return encoded, nil
}

// EncodeNativeTrustRoots returns the canonical, bounded DER trust-root representation.
func EncodeNativeTrustRoots(roots [][]byte) ([]byte, error) {
	if len(roots) > maximumNativeProvisioningTrustRoots {
		return nil, fmt.Errorf("client: too many native trust roots")
	}
	encodedRoots := make([][]byte, len(roots))
	for index, root := range roots {
		if len(root) == 0 || len(root) > maximumNativeProvisioningTrustRootBytes {
			return nil, fmt.Errorf("client: native trust root size is invalid")
		}
		certificate, err := x509.ParseCertificate(root)
		if err != nil || !bytes.Equal(certificate.Raw, root) {
			return nil, fmt.Errorf("client: native trust root is not canonical DER")
		}
		encodedRoots[index] = append([]byte(nil), root...)
	}
	sort.Slice(encodedRoots, func(i, j int) bool { return bytes.Compare(encodedRoots[i], encodedRoots[j]) < 0 })
	for index := 1; index < len(encodedRoots); index++ {
		if bytes.Equal(encodedRoots[index-1], encodedRoots[index]) {
			return nil, fmt.Errorf("client: duplicate native trust root")
		}
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(uint64(len(encodedRoots)))
	for _, root := range encodedRoots {
		encoder.WriteOpaque16(root)
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("client: encode native trust roots: %w", err)
	}
	return encoded, nil
}

type nativeHeaderField struct {
	name  string
	value string
}

func nativeHeaderFields(header http.Header) ([]nativeHeaderField, error) {
	fields := make([]nativeHeaderField, 0, len(header))
	for name, values := range header {
		if len(values) == 0 {
			return nil, fmt.Errorf("client: native header %q has no values", name)
		}
		for _, value := range values {
			if err := validateNativeHeaderField(name, value); err != nil {
				return nil, err
			}
			fields = append(fields, nativeHeaderField{name: name, value: value})
		}
	}
	if len(fields) > maximumNativeProvisioningHeaderEntries {
		return nil, fmt.Errorf("client: too many native headers")
	}
	sort.Slice(fields, func(i, j int) bool {
		if fields[i].name == fields[j].name {
			return fields[i].value < fields[j].value
		}
		return fields[i].name < fields[j].name
	})
	for index := 1; index < len(fields); index++ {
		if fields[index-1] == fields[index] {
			return nil, fmt.Errorf("client: duplicate native header")
		}
	}
	return fields, nil
}

func decodeNativeHeaders(encoded []byte) (http.Header, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeProvisioningHeaderBytes {
		return nil, fmt.Errorf("client: native headers size is invalid")
	}
	reader := wire.NewReader(encoded)
	count := reader.ReadVarint()
	if count > maximumNativeProvisioningHeaderEntries {
		return nil, fmt.Errorf("client: too many native headers")
	}
	fields := make([]nativeHeaderField, 0, count)
	for index := uint64(0); index < count; index++ {
		name := string(readNativeProvisioningOpaque8(reader, maximumNativeProvisioningHeaderNameBytes))
		value := string(readNativeProvisioningOpaque16(reader, maximumNativeProvisioningHeaderValueBytes))
		if err := validateNativeHeaderField(name, value); err != nil {
			return nil, err
		}
		if len(fields) > 0 && (fields[len(fields)-1].name > name || (fields[len(fields)-1].name == name && fields[len(fields)-1].value >= value)) {
			return nil, fmt.Errorf("client: native headers are not canonical")
		}
		fields = append(fields, nativeHeaderField{name: name, value: value})
	}
	if reader.Err() != nil || !reader.EOF() {
		return nil, fmt.Errorf("client: malformed native headers")
	}
	header := make(http.Header)
	for _, field := range fields {
		header.Add(field.name, field.value)
	}
	return header, nil
}

func validateNativeHeaderField(name, value string) error {
	if len(name) == 0 || len(name) > maximumNativeProvisioningHeaderNameBytes || textproto.CanonicalMIMEHeaderKey(name) != name {
		return fmt.Errorf("client: native header name is invalid")
	}
	for index := 0; index < len(name); index++ {
		if !isNativeHeaderFieldByte(name[index]) {
			return fmt.Errorf("client: native header name is invalid")
		}
	}
	if len(value) == 0 || len(value) > maximumNativeProvisioningHeaderValueBytes {
		return fmt.Errorf("client: native header value length is invalid")
	}
	for index := 0; index < len(value); index++ {
		if value[index] != '\t' && (value[index] < 0x20 || value[index] > 0x7e) {
			return fmt.Errorf("client: native header value is invalid")
		}
	}
	switch strings.ToLower(name) {
	case "connection", "content-length", "host", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return fmt.Errorf("client: native header name is reserved")
	}
	if err := transport.ValidateVisibleHeaders(http.Header{name: {value}}); err != nil {
		return fmt.Errorf("client: native header is not cover-safe: %w", err)
	}
	return nil
}

func isNativeHeaderFieldByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

func decodeNativeTrustRoots(encoded []byte) ([]*x509.Certificate, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeProvisioningTrustRootBytes*maximumNativeProvisioningTrustRoots {
		return nil, fmt.Errorf("client: native trust roots size is invalid")
	}
	reader := wire.NewReader(encoded)
	count := reader.ReadVarint()
	if count > maximumNativeProvisioningTrustRoots {
		return nil, fmt.Errorf("client: too many native trust roots")
	}
	certificates := make([]*x509.Certificate, 0, count)
	var previous []byte
	for index := uint64(0); index < count; index++ {
		root := readNativeProvisioningOpaque16(reader, maximumNativeProvisioningTrustRootBytes)
		certificate, err := x509.ParseCertificate(root)
		if err != nil || !bytes.Equal(certificate.Raw, root) {
			return nil, fmt.Errorf("client: native trust root is not canonical DER")
		}
		if len(previous) != 0 && bytes.Compare(previous, root) >= 0 {
			return nil, fmt.Errorf("client: native trust roots are not canonical")
		}
		previous = root
		certificates = append(certificates, certificate)
	}
	if reader.Err() != nil || !reader.EOF() {
		return nil, fmt.Errorf("client: malformed native trust roots")
	}
	return certificates, nil
}

func nativeProvisioningTLSConfig(roots []*x509.Certificate, originSPKIHash []byte) (*tls.Config, error) {
	if len(originSPKIHash) != 48 {
		return nil, fmt.Errorf("client: native relay SPKI hash length is invalid")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("client: load system root pool: %w", err)
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	for _, root := range roots {
		pool.AddCert(root)
	}
	wantSPKIHash := append([]byte(nil), originSPKIHash...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
		RootCAs:            pool,
		ClientSessionCache: nil,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("client: native relay did not provide a certificate")
			}
			gotSPKIHash := auroracrypto.PreHash(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(gotSPKIHash, wantSPKIHash) != 1 {
				return fmt.Errorf("client: native relay certificate SPKI pin mismatch")
			}
			return nil
		},
	}, nil
}

func nativeHTTP2BindingMetadata(template protocol.CoverTemplate, requestClass protocol.RequestClass) handshake.HTTP2BindingMetadata {
	return handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), template.PublicNameHash...),
		PathTemplateID:          append([]byte(nil), requestClass.PathTemplateID...),
		RequestClassID:          requestClass.ClassID,
		MethodFamilyID:          registry.MethodWebH2Stream,
	}
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
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return fmt.Errorf("URL must be an HTTPS authority without user info, query, or fragment")
	}
	port := parsed.Port()
	if strings.HasSuffix(parsed.Host, ":") || port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return fmt.Errorf("URL port must be between 1 and 65535")
		}
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

func readNativeProvisioningOpaque8(reader *wire.Reader, maximum int) []byte {
	value := reader.ReadOpaque8()
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
