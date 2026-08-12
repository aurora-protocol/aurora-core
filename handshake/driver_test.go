package handshake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestNewClientDriverRejectsInvalidDependencies(t *testing.T) {
	valid := validClientDriverConfig(t, time.Now())
	tests := []struct {
		name   string
		mutate func(*ClientDriverConfig)
	}{
		{name: "zero deployment", mutate: func(c *ClientDriverConfig) { c.Deployment = trust.VerifiedRelayDeployment{} }},
		{name: "nil proof provider", mutate: func(c *ClientDriverConfig) { c.ProofProvider = nil }},
		{name: "typed nil proof provider", mutate: func(c *ClientDriverConfig) { var provider *testProofProvider; c.ProofProvider = provider }},
		{name: "lab suite", mutate: func(c *ClientDriverConfig) { c.Suite = registry.SuiteLabClassical }},
		{name: "lab suite alternative", mutate: func(c *ClientDriverConfig) {
			c.PolicyOffer.OfferedSuites = append(c.PolicyOffer.OfferedSuites, registry.SuiteLabClassical)
		}},
		{name: "lab method alternative", mutate: func(c *ClientDriverConfig) {
			c.PolicyOffer.OfferedMethods = append(c.PolicyOffer.OfferedMethods, registry.MethodDirectQUICLab)
		}},
		{name: "suite outside deployment capability", mutate: func(c *ClientDriverConfig) {
			c.Suite = registry.SuiteHybrid768AESGCM
			c.PolicyOffer.OfferedSuites = append(c.PolicyOffer.OfferedSuites, c.Suite)
		}},
		{name: "missing limits", mutate: func(c *ClientDriverConfig) { c.SessionLimits = session.Limits{} }},
		{name: "expired access hint", mutate: func(c *ClientDriverConfig) { c.AccessHint.ExpiryUnix = uint64(time.Now().Add(-time.Second).Unix()) }},
		{name: "missing access hint expiry", mutate: func(c *ClientDriverConfig) { c.AccessHint.ExpiryUnix = 0 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewClientDriver(config); err == nil {
				t.Fatal("invalid client driver configuration accepted")
			}
		})
	}
}

func TestRelayDriverTestConstructorStillRequiresCryptographicDependencies(t *testing.T) {
	valid := validRelayDriverConfig(t, time.Now())
	valid.HintSpentCache = admission.NewMemoryReplayCache()
	valid.TokenSpentCache = admission.NewMemoryReplayCache()
	valid.BootstrapCache = admission.NewMemoryReplayCache()
	tests := []struct {
		name   string
		mutate func(*RelayDriverConfig)
	}{
		{name: "resolver", mutate: func(c *RelayDriverConfig) { c.HintResolver = nil }},
		{name: "verifier", mutate: func(c *RelayDriverConfig) { c.AdmissionVerifier = nil }},
		{name: "classical signer", mutate: func(c *RelayDriverConfig) { c.ClassicalSigner = nil }},
		{name: "pq signer", mutate: func(c *RelayDriverConfig) { c.PQSigner = nil }},
		{name: "selector", mutate: func(c *RelayDriverConfig) { c.PolicySelector = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := newRelayDriverForTest(config); err == nil {
				t.Fatal("test relay constructor accepted a missing cryptographic dependency")
			}
		})
	}
}

func TestNewRelayDriverRejectsInvalidDependencies(t *testing.T) {
	valid := validRelayDriverConfig(t, time.Now())
	tests := []struct {
		name   string
		mutate func(*RelayDriverConfig)
	}{
		{name: "zero deployment", mutate: func(c *RelayDriverConfig) { c.Deployment = trust.VerifiedRelayDeployment{} }},
		{name: "nil hint resolver", mutate: func(c *RelayDriverConfig) { c.HintResolver = nil }},
		{name: "typed nil hint resolver", mutate: func(c *RelayDriverConfig) { var resolver *testHintResolver; c.HintResolver = resolver }},
		{name: "nil admission verifier", mutate: func(c *RelayDriverConfig) { c.AdmissionVerifier = nil }},
		{name: "nil classical signer", mutate: func(c *RelayDriverConfig) { c.ClassicalSigner = nil }},
		{name: "nil pq signer", mutate: func(c *RelayDriverConfig) { c.PQSigner = nil }},
		{name: "nil policy selector", mutate: func(c *RelayDriverConfig) { c.PolicySelector = nil }},
		{name: "missing hint cache", mutate: func(c *RelayDriverConfig) { c.HintSpentCache = nil }},
		{name: "missing token cache", mutate: func(c *RelayDriverConfig) { c.TokenSpentCache = nil }},
		{name: "missing bootstrap cache", mutate: func(c *RelayDriverConfig) { c.BootstrapCache = nil }},
		{name: "memory hint cache", mutate: func(c *RelayDriverConfig) { c.HintSpentCache = admission.NewMemoryReplayCache() }},
		{name: "memory token cache", mutate: func(c *RelayDriverConfig) { c.TokenSpentCache = admission.NewMemoryReplayCache() }},
		{name: "memory bootstrap cache", mutate: func(c *RelayDriverConfig) { c.BootstrapCache = admission.NewMemoryReplayCache() }},
		{name: "classical signer mismatch", mutate: func(c *RelayDriverConfig) {
			c.ClassicalSigner = testSigner{key: c.Deployment.Descriptor().RelayLongtermClassicalKey}
		}},
		{name: "pq signer mismatch", mutate: func(c *RelayDriverConfig) { c.PQSigner = testSigner{key: c.Deployment.Descriptor().RelayLongtermPQKey} }},
		{name: "missing limits", mutate: func(c *RelayDriverConfig) { c.SessionLimits = session.Limits{} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewRelayDriver(config); err == nil {
				t.Fatal("invalid relay driver configuration accepted")
			}
		})
	}
}

func TestRelayDriverProductionRequiresDurableReplayCaches(t *testing.T) {
	config := validRelayDriverConfig(t, time.Now())
	if _, err := NewRelayDriver(config); err != nil {
		t.Fatalf("valid production relay configuration rejected: %v", err)
	}

	config.HintSpentCache = admission.NewMemoryReplayCache()
	config.TokenSpentCache = admission.NewMemoryReplayCache()
	config.BootstrapCache = admission.NewMemoryReplayCache()
	if _, err := newRelayDriverForTest(config); err != nil {
		t.Fatalf("explicit test relay configuration rejected memory caches: %v", err)
	}
}

func TestRelayDriverDeploymentReturnsBoundVerifiedDeployment(t *testing.T) {
	config := validRelayDriverConfig(t, time.Now())
	driver, err := NewRelayDriver(config)
	if err != nil {
		t.Fatal(err)
	}
	deployment := driver.Deployment()
	if !deployment.Valid() || deployment.Suite() != config.Deployment.Suite() || deployment.Method() != config.Deployment.Method() ||
		!bytes.Equal(deployment.DescriptorHash(), config.Deployment.DescriptorHash()) || !bytes.Equal(deployment.TemplateHash(), config.Deployment.TemplateHash()) {
		t.Fatalf("relay driver returned unexpected deployment: %+v", deployment)
	}
	if (*RelayDriver)(nil).Deployment().Valid() {
		t.Fatal("nil relay driver returned a verified deployment")
	}
}

func TestStaticAccessHintResolverOwnsAndMatchesCredentials(t *testing.T) {
	credential := validClientDriverConfig(t, time.Now()).AccessHint
	issuerID := append([]byte(nil), credential.HintIssuerID...)
	relayBucketID := append([]byte(nil), credential.RelayBucketID...)
	hintSelector := append([]byte(nil), credential.HintSelector...)
	wantSecret := append([]byte(nil), credential.HintSecret...)
	resolver, err := NewStaticAccessHintResolver([]admission.AccessHintCredential{credential})
	if err != nil {
		t.Fatal(err)
	}
	credential.HintSecret[0] ^= 0xff
	resolved, err := resolver.ResolveAccessHint(context.Background(), issuerID, relayBucketID, credential.HintEpochID, hintSelector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resolved.HintSecret, wantSecret) {
		t.Fatal("resolver retained caller access hint secret")
	}
	resolved.HintSecret[0] ^= 0xff
	again, err := resolver.ResolveAccessHint(context.Background(), issuerID, relayBucketID, credential.HintEpochID, hintSelector)
	if err != nil || !bytes.Equal(again.HintSecret, wantSecret) {
		t.Fatal("resolver returned aliased access hint credential")
	}
	if _, err := resolver.ResolveAccessHint(context.Background(), issuerID, relayBucketID, credential.HintEpochID+1, hintSelector); err == nil {
		t.Fatal("resolver accepted unrelated access hint lookup")
	}
}

func TestDriverConstructorsOwnMutableInputs(t *testing.T) {
	config := validClientDriverConfig(t, time.Now())
	wantSecret := append([]byte(nil), config.AccessHint.HintSecret...)
	wantSuites := append([]uint64(nil), config.PolicyOffer.OfferedSuites...)
	wantPadding := append([]byte(nil), config.TransportHints.Padding...)

	driver, err := NewClientDriver(config)
	if err != nil {
		t.Fatal(err)
	}
	config.AccessHint.HintSecret[0] ^= 0xff
	config.PolicyOffer.OfferedSuites[0] ^= 0xff
	config.TransportHints.Padding[0] ^= 0xff

	if string(driver.accessHint.HintSecret) != string(wantSecret) {
		t.Fatal("client driver access hint aliases caller input")
	}
	if driver.policyOffer.OfferedSuites[0] != wantSuites[0] {
		t.Fatal("client driver policy offer aliases caller input")
	}
	if string(driver.transportHints.Padding) != string(wantPadding) {
		t.Fatal("client driver transport hints alias caller input")
	}
}

func TestNewRelayDriverRejectsDeploymentWithExpiredReplayEpoch(t *testing.T) {
	verifiedAt := time.Now().Add(-2 * time.Second)
	config := validRelayDriverConfigWithDeployment(t, testVerifiedDeploymentUntil(t, verifiedAt, verifiedAt.Add(time.Second)))
	if _, err := NewRelayDriver(config); err == nil {
		t.Fatal("relay driver accepted an expired replay epoch")
	}
}

func TestEstablishedSessionCloseIsConcurrentAndDestroysOwnedMaterial(t *testing.T) {
	readCloser := &countingDriverCloser{}
	writeCloser := &countingDriverCloser{err: errors.New("write close failed")}
	var carrierCloses atomic.Int32
	material := hx(0x71, 48)
	s := &EstablishedSession{
		ReadCarrier:            readCloser,
		WriteCarrier:           writeCloser,
		closeCarrier:           func() error { carrierCloses.Add(1); return nil },
		ownedHandshakeMaterial: [][]byte{material},
	}

	const callers = 32
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsSeen <- s.Close()
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, writeCloser.err) {
			t.Fatalf("Close lost stable stream error: %v", err)
		}
	}
	if readCloser.calls.Load() != 1 || writeCloser.calls.Load() != 1 || carrierCloses.Load() != 1 {
		t.Fatalf("close counts read=%d write=%d carrier=%d", readCloser.calls.Load(), writeCloser.calls.Load(), carrierCloses.Load())
	}
	if !bytesAllZero(material) {
		t.Fatal("Close did not zero owned handshake material")
	}
}

type testProofProvider struct{}

type countingDriverCloser struct {
	calls atomic.Int32
	err   error
}

func (c *countingDriverCloser) Close() error {
	c.calls.Add(1)
	return c.err
}

func (*countingDriverCloser) Read([]byte) (int, error) { return 0, io.EOF }

func (*countingDriverCloser) Write(p []byte) (int, error) { return len(p), nil }

func bytesAllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func (*testProofProvider) BuildProofs(context.Context, ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	return protocol.AdmissionProof{}, protocol.ReplayProof{}, nil
}

type testHintResolver struct{}

func (*testHintResolver) ResolveAccessHint(context.Context, []byte, []byte, uint64, []byte) (admission.AccessHintCredential, error) {
	return admission.AccessHintCredential{}, nil
}

type testAdmissionVerifier struct{}

func (testAdmissionVerifier) VerifyAdmission(context.Context, protocol.AdmissionProof, uint64) error {
	return nil
}

type testSigner struct {
	key protocol.PublicKeyRecord
}

func (s testSigner) PublicKey() protocol.PublicKeyRecord { return s.key }
func (testSigner) SignTranscript(context.Context, []byte) ([]byte, error) {
	return []byte{1}, nil
}

type testPolicySelector struct{}

func (testPolicySelector) SelectPolicy(context.Context, protocol.PolicyOffer, protocol.ClientTransportHints) (protocol.PolicyAccept, error) {
	return protocol.PolicyAccept{}, nil
}

type testDurableReplayCache struct {
	*admission.MemoryReplayCache
}

func (testDurableReplayCache) Durable() bool { return true }

type testVerifiedDeploymentFixture struct {
	deployment     trust.VerifiedRelayDeployment
	epochClassical *ecdsa.PrivateKey
	epochPQ        *mldsa65.PrivateKey
}

func validClientDriverConfig(t *testing.T, verifiedAt time.Time) ClientDriverConfig {
	t.Helper()
	return ClientDriverConfig{
		Deployment: testVerifiedDeployment(t, verifiedAt),
		Suite:      registry.SuiteHybrid768P256AESGCM,
		AccessHint: admission.AccessHintCredential{
			HintIssuerID:  hx(0x21, 16),
			RelayBucketID: hx(0x22, 16),
			HintEpochID:   3,
			HintSelector:  hx(0x23, 16),
			HintSecret:    hx(0x24, 32),
			ExpiryUnix:    uint64(time.Now().Add(time.Hour).Unix()),
			MaxUses:       1,
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768P256AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyFastWeb,
			RequestedPolicyID:       registry.PolicyBalancedWeb,
			RequestedRouteModeID:    registry.RouteFast1,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
		TransportHints: protocol.ClientTransportHints{Padding: hx(0x25, 8)},
		ProofProvider:  &testProofProvider{},
		RequirePQ:      true,
		SessionLimits:  testSessionLimits(),
	}
}

func validRelayDriverConfig(t *testing.T, verifiedAt time.Time) RelayDriverConfig {
	t.Helper()
	return validRelayDriverConfigWithDeployment(t, testVerifiedDeployment(t, verifiedAt))
}

func validRelayDriverConfigWithDeployment(t *testing.T, deployment trust.VerifiedRelayDeployment) RelayDriverConfig {
	t.Helper()
	descriptor := deployment.Descriptor()
	return RelayDriverConfig{
		Deployment:        deployment,
		HintResolver:      &testHintResolver{},
		HintSpentCache:    testDurableReplayCache{admission.NewMemoryReplayCache()},
		AdmissionVerifier: testAdmissionVerifier{},
		TokenSpentCache:   testDurableReplayCache{admission.NewMemoryReplayCache()},
		BootstrapCache:    testDurableReplayCache{admission.NewMemoryReplayCache()},
		ClassicalSigner:   testSigner{key: descriptor.EpochAuthClassicalKey},
		PQSigner:          testSigner{key: descriptor.EpochAuthPQKey},
		PolicySelector:    testPolicySelector{},
		RequirePQ:         true,
		SessionLimits:     testSessionLimits(),
	}
}

func testSessionLimits() session.Limits {
	return session.Limits{
		MaxQueuedPackets:       32,
		MaxQueuedBytes:         256 << 10,
		ControlReservedPackets: 2,
		ControlReservedBytes:   8 << 10,
		ReplayWindow:           1024,
	}
}

func testVerifiedDeployment(t *testing.T, verifiedAt time.Time) trust.VerifiedRelayDeployment {
	t.Helper()
	return testVerifiedDeploymentFixtureUntil(t, verifiedAt, verifiedAt.Add(time.Hour)).deployment
}

func testVerifiedDeploymentUntil(t *testing.T, verifiedAt, replayValidUntil time.Time) trust.VerifiedRelayDeployment {
	t.Helper()
	return testVerifiedDeploymentFixtureUntil(t, verifiedAt, replayValidUntil).deployment
}

func newTestVerifiedDeploymentFixture(t *testing.T, verifiedAt time.Time) testVerifiedDeploymentFixture {
	t.Helper()
	return testVerifiedDeploymentFixtureUntil(t, verifiedAt, verifiedAt.Add(time.Hour))
}

func testVerifiedDeploymentFixtureUntil(t *testing.T, verifiedAt, replayValidUntil time.Time) testVerifiedDeploymentFixture {
	t.Helper()
	now := uint64(verifiedAt.Unix())
	longtermClassical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochClassical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	templateAuthority, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	longtermPQPublic, longtermPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPQPublic, epochPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       hx(0x31, 16),
		TemplateFamilyID: hx(0x32, 16),
		ValidFromUnix:    now - 60,
		ValidUntilUnix:   now + 3600,
		OriginSPKIHash:   hx(0x33, 48),
		PublicNameHash:   hx(0x34, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      hx(0x35, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{hx(0x36, 48)},
		OriginPassThroughSlotCommitments: [][]byte{hx(0x37, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  hx(0x38, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: hx(0x39, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               hx(0x3a, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   hx(0x3b, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile:         protocol.H2CoverProfile{ProfileID: 1, RecordSizeDistributionID: hx(0x3c, 16)},
		H3Profile:         protocol.H3CoverProfile{ProfileID: 2, DatagramSizeDistributionID: hx(0x3d, 16), DatagramRateDistributionID: hx(0x3e, 16)},
		WebSocketProfile:  protocol.WebSocketCoverProfile{ProfileID: 3, FrameSizeDistributionID: hx(0x3f, 16)},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: hx(0x40, 16)},
	}
	commitment, err := trust.CoverOriginCommitment(template)
	if err != nil {
		t.Fatal(err)
	}
	template.CoverOriginCommitment = commitment
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:         registry.Version20,
		RelayID:                   hx(0x41, 32),
		RoleFlags:                 1,
		ValidFromUnix:             now - 60,
		ValidUntilUnix:            now + 3600,
		RelayLongtermClassicalKey: testECDSAPublicRecord(t, longtermClassical),
		RelayLongtermPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       longtermPQPublic.Bytes(),
		},
		EpochID:               9,
		EpochAuthClassicalKey: testECDSAPublicRecord(t, epochClassical),
		EpochAuthPQKey: protocol.PublicKeyRecord{
			SignatureScheme: registry.SigMLDSA65,
			KeyEncoding:     registry.KeyMLDSA65RawPublic,
			PublicKey:       epochPQPublic.Bytes(),
		},
		EpochValidFromUnix:           now - 60,
		EpochValidUntilUnix:          now + 3600,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    uint64(replayValidUntil.Unix()),
		ReplayWindowID:               hx(0x42, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: hx(0x43, 48),
		SupportedShapeIDsCommitment:  hx(0x44, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         hx(0x45, 48),
		AbusePolicyCommitment:        hx(0x46, 48),
	}
	descriptorInput, err := trust.RelayDescriptorSignatureInput(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermClassical, err = ecdsa.SignASN1(rand.Reader, longtermClassical, descriptorInput)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.SignatureByLongtermPQ = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(longtermPQPrivate, descriptorInput, nil, false, descriptor.SignatureByLongtermPQ); err != nil {
		t.Fatal(err)
	}
	descriptorHash, err := trust.RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	templateFamilyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, templateFamilyInput)
	if err != nil {
		t.Fatal(err)
	}
	templateInstanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, templateInstanceInput)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     testECDSAPublicRecord(t, templateAuthority),
		RequestClassID:           7,
		Suite:                    registry.SuiteHybrid768P256AESGCM,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  now,
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testVerifiedDeploymentFixture{
		deployment:     verified,
		epochClassical: epochClassical,
		epochPQ:        epochPQPrivate,
	}
}

func testECDSAPublicRecord(t *testing.T, key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	t.Helper()
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       publicKey,
	}
}
