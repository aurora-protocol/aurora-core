package handshake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
)

type BootstrapCarrier interface {
	Binding() FirstHopBinding
	WriteRecord([]byte) error
	ReadRecord() ([]byte, error)
	ApplicationStreams() (io.ReadCloser, io.WriteCloser, error)
	Close() error
}

type ClientCarrierOpener interface {
	Open(context.Context, []byte) (BootstrapCarrier, error)
}

type ClientProofRequest struct {
	AdmissionContextHash    []byte
	HandshakeBindingContext []byte
	RouteInstanceID         uint64
	HopIndex                uint8
	ReplayEpochID           uint64
	ReplayEpochValidUntil   uint64
	ReplayWindowID          []byte
}

type ClientProofProvider interface {
	BuildProofs(context.Context, ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error)
}

type HintCredentialResolver interface {
	ResolveAccessHint(context.Context, []byte, []byte, uint64, []byte) (admission.AccessHintCredential, error)
}

type AdmissionVerifier interface {
	VerifyAdmission(context.Context, protocol.AdmissionProof, uint64) error
}

type TranscriptSigner interface {
	PublicKey() protocol.PublicKeyRecord
	SignTranscript(context.Context, []byte) ([]byte, error)
}

type PolicySelector interface {
	SelectPolicy(context.Context, protocol.PolicyOffer, protocol.ClientTransportHints) (protocol.PolicyAccept, error)
}

type DurableReplayCache interface {
	admission.ReplayCache
	admission.RetentionReplayCache
	Durable() bool
}

type ClientDriverConfig struct {
	Deployment     trust.VerifiedRelayDeployment
	Suite          uint64
	AccessHint     admission.AccessHintCredential
	PolicyOffer    protocol.PolicyOffer
	TransportHints protocol.ClientTransportHints
	ProofProvider  ClientProofProvider
	RequirePQ      bool
	SessionLimits  session.Limits
	Rekey          session.RekeyPolicy
	Entropy        session.EntropySource
}

type RelayDriverConfig struct {
	Deployment        trust.VerifiedRelayDeployment
	HintResolver      HintCredentialResolver
	HintSpentCache    DurableReplayCache
	AdmissionVerifier AdmissionVerifier
	TokenSpentCache   DurableReplayCache
	BootstrapCache    DurableReplayCache
	ClassicalSigner   TranscriptSigner
	PQSigner          TranscriptSigner
	PolicySelector    PolicySelector
	SessionLimits     session.Limits
	Rekey             session.RekeyPolicy
	Entropy           session.EntropySource
}

type ClientDriver struct {
	deployment     trust.VerifiedRelayDeployment
	suite          uint64
	accessHint     admission.AccessHintCredential
	policyOffer    protocol.PolicyOffer
	transportHints protocol.ClientTransportHints
	proofProvider  ClientProofProvider
	requirePQ      bool
	sessionLimits  session.Limits
	rekey          session.RekeyPolicy
	entropy        session.EntropySource
	hintUse        *clientAccessHintUse
}

type clientAccessHintUse struct {
	mu   sync.Mutex
	uses uint16
}

type RelayDriver struct {
	deployment        trust.VerifiedRelayDeployment
	hintResolver      HintCredentialResolver
	hintSpentCache    admission.ReplayCache
	admissionVerifier AdmissionVerifier
	tokenSpentCache   admission.ReplayCache
	bootstrapCache    admission.ReplayCache
	classicalSigner   TranscriptSigner
	pqSigner          TranscriptSigner
	policySelector    PolicySelector
	sessionLimits     session.Limits
	rekey             session.RekeyPolicy
	entropy           session.EntropySource
	newApplication    func(session.Config) (*session.Application, error)
}

type EstablishedSession struct {
	Application     *session.Application
	ReadCarrier     io.ReadCloser
	WriteCarrier    io.WriteCloser
	Policy          protocol.PolicyAccept
	RouteInstanceID uint64

	closeOnce              sync.Once
	closeErr               error
	closeCarrier           func() error
	ownedHandshakeMaterial [][]byte
}

func NewClientDriver(config ClientDriverConfig) (*ClientDriver, error) {
	return newClientDriverAt(config, time.Now())
}

func newClientDriverAt(config ClientDriverConfig, now time.Time) (*ClientDriver, error) {
	if err := validateDriverDeployment(config.Deployment, config.Suite, now); err != nil {
		return nil, err
	}
	if isNilDependency(config.ProofProvider) {
		return nil, fmt.Errorf("handshake: missing client proof provider")
	}
	if _, err := admission.ComputeSpentHintKey(config.AccessHint); err != nil {
		return nil, fmt.Errorf("handshake: invalid access hint credential: %w", err)
	}
	if config.AccessHint.ExpiryUnix == 0 || uint64(now.Unix()) >= config.AccessHint.ExpiryUnix {
		return nil, fmt.Errorf("handshake: access hint credential expired")
	}
	if err := validateClientPolicy(config.PolicyOffer, config.TransportHints, config.Suite); err != nil {
		return nil, err
	}
	if err := validateSessionSettings(config.Suite, config.SessionLimits, config.Rekey, config.Entropy); err != nil {
		return nil, err
	}
	offer, err := clonePolicyOffer(config.PolicyOffer)
	if err != nil {
		return nil, err
	}
	hints, err := cloneTransportHints(config.TransportHints.NormalizePrototype())
	if err != nil {
		return nil, err
	}
	return &ClientDriver{
		deployment:     config.Deployment,
		suite:          config.Suite,
		accessHint:     cloneAccessHint(config.AccessHint),
		policyOffer:    offer,
		transportHints: hints,
		proofProvider:  config.ProofProvider,
		requirePQ:      config.RequirePQ,
		sessionLimits:  config.SessionLimits,
		rekey:          config.Rekey,
		entropy:        config.Entropy,
		hintUse:        &clientAccessHintUse{},
	}, nil
}

func NewRelayDriver(config RelayDriverConfig) (*RelayDriver, error) {
	return newRelayDriver(config, time.Now(), true)
}

// Deployment returns the verified deployment bound to this relay driver.
func (d *RelayDriver) Deployment() trust.VerifiedRelayDeployment {
	if d == nil {
		return trust.VerifiedRelayDeployment{}
	}
	return d.deployment
}

func newRelayDriverForTest(config RelayDriverConfig) (*RelayDriver, error) {
	return newRelayDriver(config, time.Now(), false)
}

func newRelayDriver(config RelayDriverConfig, now time.Time, requireDurable bool) (*RelayDriver, error) {
	if err := validateDriverDeployment(config.Deployment, 0, now); err != nil {
		return nil, err
	}
	for label, dependency := range map[string]any{
		"hint resolver":          config.HintResolver,
		"admission verifier":     config.AdmissionVerifier,
		"classical signer":       config.ClassicalSigner,
		"PQ signer":              config.PQSigner,
		"policy selector":        config.PolicySelector,
		"spent-hint cache":       config.HintSpentCache,
		"spent-token cache":      config.TokenSpentCache,
		"bootstrap replay cache": config.BootstrapCache,
	} {
		if isNilDependency(dependency) {
			return nil, fmt.Errorf("handshake: missing %s", label)
		}
	}
	if requireDurable {
		for label, cache := range map[string]DurableReplayCache{
			"spent-hint":  config.HintSpentCache,
			"spent-token": config.TokenSpentCache,
			"bootstrap":   config.BootstrapCache,
		} {
			if !cache.Durable() {
				return nil, fmt.Errorf("handshake: %s replay cache is not durable", label)
			}
		}
	}
	descriptor := config.Deployment.Descriptor()
	if !publicKeysEqual(config.ClassicalSigner.PublicKey(), descriptor.EpochAuthClassicalKey) {
		return nil, fmt.Errorf("handshake: classical signer does not match relay epoch key")
	}
	if !publicKeysEqual(config.PQSigner.PublicKey(), descriptor.EpochAuthPQKey) {
		return nil, fmt.Errorf("handshake: PQ signer does not match relay epoch key")
	}
	if err := validateSessionSettings(config.Deployment.Suite(), config.SessionLimits, config.Rekey, config.Entropy); err != nil {
		return nil, err
	}
	return &RelayDriver{
		deployment:        config.Deployment,
		hintResolver:      config.HintResolver,
		hintSpentCache:    config.HintSpentCache,
		admissionVerifier: config.AdmissionVerifier,
		tokenSpentCache:   config.TokenSpentCache,
		bootstrapCache:    config.BootstrapCache,
		classicalSigner:   config.ClassicalSigner,
		pqSigner:          config.PQSigner,
		policySelector:    config.PolicySelector,
		sessionLimits:     config.SessionLimits,
		rekey:             config.Rekey,
		entropy:           config.Entropy,
		newApplication:    session.NewApplication,
	}, nil
}

func (s *EstablishedSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var closeErrors []error
		if s.Application != nil {
			closeErrors = appendCloseError(closeErrors, s.Application.Close())
		}
		if s.ReadCarrier != nil {
			closeErrors = appendCloseError(closeErrors, s.ReadCarrier.Close())
		}
		if s.WriteCarrier != nil {
			closeErrors = appendCloseError(closeErrors, s.WriteCarrier.Close())
		}
		if s.closeCarrier != nil {
			closeErrors = appendCloseError(closeErrors, s.closeCarrier())
		}
		for _, material := range s.ownedHandshakeMaterial {
			zeroBindingBytes(material)
		}
		s.ownedHandshakeMaterial = nil
		s.closeErr = errors.Join(closeErrors...)
	})
	return s.closeErr
}

func validateDriverDeployment(deployment trust.VerifiedRelayDeployment, suite uint64, now time.Time) error {
	if !deployment.Valid() {
		return fmt.Errorf("handshake: relay deployment is not verified")
	}
	nowUnix := uint64(now.Unix())
	selectedSuite := suite
	if selectedSuite == 0 {
		selectedSuite = deployment.Suite()
	}
	metadata := deployment.FirstHopMetadata(selectedSuite)
	if nowUnix < metadata.DescriptorValidFromUnix || nowUnix >= metadata.DescriptorValidUntilUnix {
		return fmt.Errorf("handshake: relay descriptor outside validity interval")
	}
	if nowUnix < metadata.EpochValidFromUnix || nowUnix >= metadata.EpochValidUntilUnix {
		return fmt.Errorf("handshake: relay epoch outside validity interval")
	}
	if nowUnix >= metadata.ReplayEpochValidUntilUnix {
		return fmt.Errorf("handshake: relay replay epoch expired")
	}
	if nowUnix < metadata.TemplateValidFromUnix || nowUnix >= metadata.TemplateValidUntilUnix {
		return fmt.Errorf("handshake: cover template outside validity interval")
	}
	if metadata.PreludeMaxRequestBodySize > uint64(wire.DefaultRecordBodyBytes) ||
		metadata.PreludeMaxResponseBodySize > uint64(wire.DefaultRecordBodyBytes) ||
		metadata.CapsuleMaxBodySize > uint64(wire.DefaultRecordBodyBytes) {
		return fmt.Errorf("handshake: bootstrap envelope exceeds record limit")
	}
	if deployment.Method() != registry.MethodWebH2Stream || metadata.RequestClassType != registry.RequestGatewayOwnedSlot || metadata.RequestClassAllowedMethod != deployment.Method() || !metadata.RequestClassMayCarryPrelude || !metadata.RequestClassMayCarryCapsule {
		return fmt.Errorf("handshake: verified request class is not an HTTP/2 bootstrap slot")
	}
	if selectedSuite != deployment.Suite() || !isDriverProductionSuite(selectedSuite) || !metadata.SelectedSuiteIsSupported {
		return fmt.Errorf("handshake: selected suite does not match verified deployment")
	}
	if isDriverHybrid1024Suite(selectedSuite) && (metadata.PreludeMaxRequestBodySize < 2048 || metadata.PreludeMaxResponseBodySize < 8192) {
		return fmt.Errorf("handshake: cover prelude envelope is too small for selected suite")
	}
	return nil
}

func validateClientPolicy(offer protocol.PolicyOffer, hints protocol.ClientTransportHints, suite uint64) error {
	if err := offer.ValidateStructural(); err != nil {
		return fmt.Errorf("handshake: invalid policy offer: %w", err)
	}
	if err := hints.ValidatePrototype(); err != nil {
		return fmt.Errorf("handshake: invalid client transport hints: %w", err)
	}
	if !containsDriverID(offer.OfferedVersions, registry.Version20) || !containsDriverID(offer.OfferedSuites, suite) || !containsDriverID(offer.OfferedMethods, registry.MethodWebH2Stream) {
		return fmt.Errorf("handshake: policy offer omits authenticated version, suite, or method")
	}
	if hasDuplicateDriverIDs(offer.OfferedVersions) || hasDuplicateDriverIDs(offer.OfferedSuites) || hasDuplicateDriverIDs(offer.OfferedMethods) || hasDuplicateDriverIDs(offer.TunnelPersonalityOffers) {
		return fmt.Errorf("handshake: policy offer contains duplicate values")
	}
	for _, offeredSuite := range offer.OfferedSuites {
		if !isDriverProductionSuite(offeredSuite) {
			return fmt.Errorf("handshake: policy offer contains a non-production suite")
		}
	}
	for _, offeredMethod := range offer.OfferedMethods {
		if !isDriverProductionMethod(offeredMethod) {
			return fmt.Errorf("handshake: policy offer contains a non-production method")
		}
	}
	if offer.MinimumPolicyID == registry.PolicyLab || offer.RequestedPolicyID == registry.PolicyLab {
		return fmt.Errorf("handshake: lab policy is forbidden in production")
	}
	if offer.RequestedPolicyID < offer.MinimumPolicyID {
		return fmt.Errorf("handshake: policy offer requests a policy weaker than its own minimum")
	}
	if offer.RequestedRouteModeID == registry.RouteFast1 && (policy.ForbidsFast1Route(offer.MinimumPolicyID) || policy.ForbidsFast1Route(offer.RequestedPolicyID)) {
		return fmt.Errorf("handshake: policy offer requests the fast-1 route under a policy that forbids it")
	}
	if (offer.RequestedPolicyID == registry.PolicyAdversarialStrict || offer.RequestedPolicyID == registry.PolicyEmergencyWeb) && len(hints.NetworkCohortHint) != 0 {
		return fmt.Errorf("handshake: strict policy forbids a network cohort hint")
	}
	return nil
}

func validateSessionSettings(suite uint64, limits session.Limits, rekey session.RekeyPolicy, entropy session.EntropySource) error {
	if limits == (session.Limits{}) {
		return fmt.Errorf("handshake: explicit session limits are required")
	}
	hashLength, err := auroracrypto.SuiteHashLength(suite)
	if err != nil {
		return err
	}
	keyLength, err := auroracrypto.AEADKeyLength(suite)
	if err != nil {
		return err
	}
	application, err := session.NewApplication(session.Config{
		Suite:   suite,
		Write:   session.DirectionConfig{Direction: 0, Secret: make([]byte, hashLength), Key: make([]byte, keyLength), IV: make([]byte, 12)},
		Read:    session.DirectionConfig{Direction: 1, Secret: make([]byte, hashLength), Key: make([]byte, keyLength), IV: make([]byte, 12)},
		Limits:  limits,
		Rekey:   rekey,
		Entropy: entropy,
	})
	if err != nil {
		return fmt.Errorf("handshake: invalid session settings: %w", err)
	}
	return application.Close()
}

func clonePolicyOffer(in protocol.PolicyOffer) (protocol.PolicyOffer, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.PolicyOffer{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodePolicyOffer(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.PolicyOffer{}, fmt.Errorf("handshake: cannot clone policy offer")
	}
	return out, nil
}

func cloneTransportHints(in protocol.ClientTransportHints) (protocol.ClientTransportHints, error) {
	encoded, err := protocol.Encode(in)
	if err != nil {
		return protocol.ClientTransportHints{}, err
	}
	r := wire.NewReader(encoded)
	out := protocol.DecodeClientTransportHints(r)
	if r.Err() != nil || !r.EOF() {
		return protocol.ClientTransportHints{}, fmt.Errorf("handshake: cannot clone client transport hints")
	}
	return out, nil
}

func cloneAccessHint(in admission.AccessHintCredential) admission.AccessHintCredential {
	in.HintIssuerID = append([]byte(nil), in.HintIssuerID...)
	in.RelayBucketID = append([]byte(nil), in.RelayBucketID...)
	in.HintSelector = append([]byte(nil), in.HintSelector...)
	in.HintSecret = append([]byte(nil), in.HintSecret...)
	return in
}

func publicKeysEqual(left, right protocol.PublicKeyRecord) bool {
	return left.SignatureScheme == right.SignatureScheme && left.KeyEncoding == right.KeyEncoding && bytes.Equal(left.PublicKey, right.PublicKey)
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func isDriverProductionSuite(suite uint64) bool {
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

func isDriverHybrid1024Suite(suite uint64) bool {
	return suite == registry.SuiteHybrid1024AESGCM || suite == registry.SuiteHybrid1024ChaCha20
}

func isDriverProductionMethod(method uint64) bool {
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

func containsDriverID(values []uint64, want uint64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasDuplicateDriverIDs(values []uint64) bool {
	seen := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func appendCloseError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}
