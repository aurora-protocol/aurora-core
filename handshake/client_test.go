package handshake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestClientDriverCompletesAuthenticatedHandshakeAndApplicationInterop(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config := validClientDriverConfig(t, now)
	config.Deployment = fixture.deployment
	provider := &productionClientProofProvider{
		issuerID:      append([]byte(nil), config.AccessHint.HintIssuerID...),
		relayBucketID: append([]byte(nil), config.AccessHint.RelayBucketID...),
	}
	config.ProofProvider = provider
	driver, err := NewClientDriver(config)
	if err != nil {
		t.Fatal(err)
	}
	opener := &scriptedClientOpener{
		fixture: fixture,
		config:  config,
	}

	established, err := driver.Connect(context.Background(), opener)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	t.Cleanup(func() { _ = established.Close() })
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client opener did not retain carrier")
	}
	if len(carrier.writes) != 2 {
		t.Fatalf("client wrote %d bootstrap records, want 2", len(carrier.writes))
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("proof provider calls = %d, want 1", provider.calls.Load())
	}
	if carrier.streamRequests.Load() != 1 {
		t.Fatalf("application stream requests = %d, want 1", carrier.streamRequests.Load())
	}
	if established.RouteInstanceID != carrier.routeInstanceID || established.Application == nil || carrier.relayApplication == nil {
		t.Fatal("authenticated application state was not created on both peers")
	}

	p0, err := decodeClientTestPrelude0(carrier.writes[0])
	if err != nil {
		t.Fatal(err)
	}
	template := fixture.deployment.Template()
	class := fixture.deployment.RequestClass()
	if !bytes.Equal(p0.RelayDescriptorHash, fixture.deployment.DescriptorHash()) ||
		!bytes.Equal(p0.CoverTemplateHash, fixture.deployment.TemplateHash()) ||
		p0.RequestClassID != class.ClassID || len(p0.SuiteOffers) != 1 || p0.SuiteOffers[0] != fixture.deployment.Suite() {
		t.Fatal("Prelude0 did not carry the verified deployment choices")
	}
	wantHint, err := admission.ComputeAccessHint(config.AccessHint, carrier.binding.HandshakeBindingContext, p0.ClientNonce)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(wantHint, p0.AccessHint) != 1 {
		t.Fatal("Prelude0 access hint was not bound to the live carrier")
	}
	if !bytes.Equal(p0.ClientCoverRandom, opener.coverRandom) || !bytes.Equal(template.PublicNameHash, opener.authorityHash) || !bytes.Equal(class.PathTemplateID, opener.pathTemplateID) {
		t.Fatal("client carrier binding metadata mismatch")
	}

	assertApplicationsInteroperate(t, established.Application, carrier.relayApplication)
}

func TestClientDriverRandomizesPublicHandshakeValues(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config := validClientDriverConfig(t, now)
	config.Deployment = fixture.deployment

	seen := map[string]map[string]struct{}{
		"cover random": {},
		"client nonce": {},
		"replay nonce": {},
		"ecdh public":  {},
		"mlkem public": {},
	}
	for range 32 {
		runConfig := config
		runConfig.AccessHint = cloneAccessHint(config.AccessHint)
		if _, err := rand.Read(runConfig.AccessHint.HintSelector); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(runConfig.AccessHint.HintSecret); err != nil {
			t.Fatal(err)
		}
		provider := &productionClientProofProvider{
			issuerID:      append([]byte(nil), runConfig.AccessHint.HintIssuerID...),
			relayBucketID: append([]byte(nil), runConfig.AccessHint.RelayBucketID...),
		}
		runConfig.ProofProvider = provider
		driver, err := NewClientDriver(runConfig)
		if err != nil {
			t.Fatal(err)
		}
		opener := &scriptedClientOpener{fixture: fixture, config: runConfig}
		established, err := driver.Connect(context.Background(), opener)
		if err != nil {
			t.Fatal(err)
		}
		carrier := opener.lastCarrier()
		p0, err := decodeClientTestPrelude0(carrier.writes[0])
		if err != nil {
			t.Fatal(err)
		}
		request := provider.lastRequest()
		seen["cover random"][string(p0.ClientCoverRandom)] = struct{}{}
		seen["client nonce"][string(p0.ClientNonce)] = struct{}{}
		seen["replay nonce"][string(request.replayNonce)] = struct{}{}
		seen["ecdh public"][string(p0.ClientClassicalEphPub)] = struct{}{}
		seen["mlkem public"][string(p0.ClientMLKEMEncapsulationKey)] = struct{}{}
		if err := established.Close(); err != nil {
			t.Fatal(err)
		}
		if carrier.relayApplication != nil {
			_ = carrier.relayApplication.Close()
		}
	}
	for label, values := range seen {
		if len(values) != 32 {
			t.Fatalf("%s produced %d distinct values across 32 runs", label, len(values))
		}
	}
}

func TestClientDriverEnforcesAccessHintUsageLimit(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	firstOpener := &scriptedClientOpener{fixture: fixture, config: config}
	first, err := driver.Connect(context.Background(), firstOpener)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	secondOpener := &scriptedClientOpener{fixture: fixture, config: config}
	if second, err := driver.Connect(context.Background(), secondOpener); err == nil || second != nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("client reused an exhausted access hint credential")
	}
	if secondOpener.lastCarrier() != nil {
		t.Fatal("client opened a carrier after exhausting access hint uses")
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("proof provider calls = %d, want 1", provider.calls.Load())
	}
}

func TestClientDriverReleasesAccessHintReservationBeforePreludeAttempt(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	badOpener := &scriptedClientOpener{
		fixture: fixture,
		config:  config,
		mutateBinding: func(binding *FirstHopBinding) {
			binding.CoverStreamBinding[0] ^= 0xff
		},
	}
	if failed, err := driver.Connect(context.Background(), badOpener); err == nil || failed != nil {
		t.Fatal("client accepted invalid binding")
	}

	validOpener := &scriptedClientOpener{fixture: fixture, config: config}
	established, err := driver.Connect(context.Background(), validOpener)
	if err != nil {
		t.Fatalf("pre-Prelude failure consumed access hint reservation: %v", err)
	}
	if err := established.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("proof provider calls = %d, want 1", provider.calls.Load())
	}
}

func TestClientDriverDoesNotDiscloseProofsBeforeAuthenticatedPrelude(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	cases := []struct {
		name                string
		mutatePrelude       func(*protocol.CoverPrelude1)
		mutateSignedPrelude func(*protocol.CoverPrelude1)
		mutateRecord        func([]byte)
	}{
		{
			name: "malformed prelude",
			mutateRecord: func(record []byte) {
				record[0] = 0xff
			},
		},
		{
			name: "selected suite mismatch",
			mutatePrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.SelectedSuite = registry.SuiteHybrid768AESGCM
			},
		},
		{
			name: "descriptor mismatch",
			mutatePrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.RelayDescriptorHash[0] ^= 0xff
			},
		},
		{
			name: "template mismatch",
			mutatePrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.CoverTemplateHash[0] ^= 0xff
			},
		},
		{
			name: "malformed hybrid share",
			mutatePrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.ServerClassicalEphPub = []byte{1}
			},
		},
		{
			name: "bad classical signature",
			mutateSignedPrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.ServerPreludeSignatureClassical[0] ^= 0xff
			},
		},
		{
			name: "missing required PQ signature",
			mutateSignedPrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.ServerPreludeSignaturePQ = nil
			},
		},
		{
			name: "bad PQ signature",
			mutateSignedPrelude: func(prelude *protocol.CoverPrelude1) {
				prelude.ServerPreludeSignaturePQ[0] ^= 0xff
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
			opener := &scriptedClientOpener{
				fixture:              fixture,
				config:               config,
				mutatePrelude:        tc.mutatePrelude,
				mutateSignedPrelude:  tc.mutateSignedPrelude,
				mutatePreludeRecord:  tc.mutateRecord,
				skipRelayApplication: true,
			}

			established, err := driver.Connect(context.Background(), opener)
			if established != nil {
				_ = established.Close()
			}
			if err == nil {
				t.Fatal("client accepted unauthenticated Prelude1")
			}
			carrier := opener.lastCarrier()
			if carrier == nil {
				t.Fatal("client did not open carrier")
			}
			if provider.calls.Load() != 0 {
				t.Fatalf("proof provider calls = %d, want 0", provider.calls.Load())
			}
			if len(carrier.writes) != 1 {
				t.Fatalf("client wrote %d records before Prelude1 authentication", len(carrier.writes))
			}
			if carrier.streamRequests.Load() != 0 {
				t.Fatal("application streams released before Prelude1 authentication")
			}
			if carrier.closes.Load() != 1 {
				t.Fatalf("carrier closes = %d, want 1", carrier.closes.Load())
			}
		})
	}
}

func TestClientDriverDoesNotReleaseApplicationAfterCapsuleFailure(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	cases := []struct {
		name               string
		mutateConfig       func(*ClientDriverConfig)
		mutateAccept       func(*protocol.PolicyAccept)
		mutateCapsule      func(*protocol.CoverCapsule2Plain)
		mutateRecord       func([]byte)
		routeOverride      func(uint64) uint64
		allowInvalidPolicy bool
	}{
		{
			name: "bad capsule tag",
			mutateRecord: func(record []byte) {
				record[len(record)-1] ^= 0xff
			},
		},
		{
			name:          "wrong route instance",
			routeOverride: func(route uint64) uint64 { return route ^ 1 },
		},
		{
			name: "wrong server finished",
			mutateCapsule: func(capsule *protocol.CoverCapsule2Plain) {
				capsule.ServerFinished[0] ^= 0xff
			},
		},
		{
			name: "unoffered version",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedVersion = 0x55
			},
			allowInvalidPolicy: true,
		},
		{
			name: "unoffered suite",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedSuite = registry.SuiteHybrid768AESGCM
			},
			allowInvalidPolicy: true,
		},
		{
			name: "unoffered method",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedMethod = registry.MethodWebH1WS
			},
			allowInvalidPolicy: true,
		},
		{
			name: "weaker policy",
			mutateConfig: func(config *ClientDriverConfig) {
				config.PolicyOffer.MinimumPolicyID = registry.PolicyBalancedWeb
				config.PolicyOffer.RequestedPolicyID = registry.PolicyAdversarialDPI
			},
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedPolicy = registry.PolicyFastWeb
			},
			allowInvalidPolicy: true,
		},
		{
			name: "lab policy",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedPolicy = registry.PolicyLab
			},
		},
		{
			name: "changed route",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedRouteModeID = registry.RouteSplit2
			},
		},
		{
			name: "changed shape",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedShape = registry.ShapeLight
			},
		},
		{
			name: "unoffered personality",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedTunnelPersonality = registry.PersonalityIPLite
				accept.VirtualAddressAssignment = validClientVirtualAddress(now)
			},
			allowInvalidPolicy: true,
		},
		{
			name: "unoffered fallback",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.FallbackMethods = []uint64{registry.MethodWebH1WS}
			},
		},
		{
			name: "duplicate fallback",
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.FallbackMethods = []uint64{registry.MethodWebH2Stream, registry.MethodWebH2Stream}
			},
		},
		{
			name: "expired virtual address lease",
			mutateConfig: func(config *ClientDriverConfig) {
				config.PolicyOffer.TunnelPersonalityOffers = []uint64{registry.PersonalityIPLite}
			},
			mutateAccept: func(accept *protocol.PolicyAccept) {
				accept.SelectedTunnelPersonality = registry.PersonalityIPLite
				accept.VirtualAddressAssignment = validClientVirtualAddress(now)
				accept.VirtualAddressAssignment.LeaseExpiryUnix = 1
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config, provider, driver := newClientDriverTestSetup(t, now, fixture, tc.mutateConfig)
			opener := &scriptedClientOpener{
				fixture:              fixture,
				config:               config,
				mutatePolicyAccept:   tc.mutateAccept,
				mutateCapsule2:       tc.mutateCapsule,
				mutateCapsule2Record: tc.mutateRecord,
				allowInvalidPolicy:   tc.allowInvalidPolicy,
				skipRelayApplication: true,
			}
			opener.capsule2Route = tc.routeOverride

			established, err := driver.Connect(context.Background(), opener)
			if established != nil {
				_ = established.Close()
			}
			if err == nil {
				t.Fatal("client released an application after invalid Capsule2")
			}
			carrier := opener.lastCarrier()
			if carrier == nil {
				t.Fatal("client did not open carrier")
			}
			if provider.calls.Load() != 1 {
				t.Fatalf("proof provider calls = %d, want 1", provider.calls.Load())
			}
			if len(carrier.writes) != 2 {
				t.Fatalf("client wrote %d records, want Prelude0 and Capsule1", len(carrier.writes))
			}
			if carrier.streamRequests.Load() != 0 {
				t.Fatal("application streams released after invalid Capsule2")
			}
			if carrier.closes.Load() != 1 {
				t.Fatalf("carrier closes = %d, want 1", carrier.closes.Load())
			}
		})
	}
}

func TestClientDriverRejectsCanceledContextBeforeDisclosure(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if established, err := driver.Connect(ctx, opener); err == nil || established != nil {
		t.Fatal("client accepted a canceled handshake context")
	}
	if provider.calls.Load() != 0 {
		t.Fatal("proof provider called for canceled handshake")
	}
	if opener.lastCarrier() != nil {
		t.Fatal("carrier opened for canceled handshake")
	}
}

func TestClientDriverRejectsUnverifiedCarrierBindingBeforePrelude(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	cases := map[string]func(*FirstHopBinding){
		"bad channel hash": func(binding *FirstHopBinding) {
			binding.ConnectionIDHash[0] ^= 0xff
		},
		"bad stream binding": func(binding *FirstHopBinding) {
			binding.CoverStreamBinding[0] ^= 0xff
		},
		"bad handshake context": func(binding *FirstHopBinding) {
			binding.HandshakeBindingContext[0] ^= 0xff
		},
		"truncated exporter": func(binding *FirstHopBinding) {
			binding.OuterExporterValue = binding.OuterExporterValue[:47]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
			opener := &scriptedClientOpener{fixture: fixture, config: config, mutateBinding: mutate}

			if established, err := driver.Connect(context.Background(), opener); err == nil || established != nil {
				if established != nil {
					_ = established.Close()
				}
				t.Fatal("client accepted an unverified carrier binding")
			}
			carrier := opener.lastCarrier()
			if carrier == nil {
				t.Fatal("client did not open carrier")
			}
			if provider.calls.Load() != 0 || len(carrier.writes) != 0 || carrier.streamRequests.Load() != 0 {
				t.Fatal("client disclosed data through an unverified carrier binding")
			}
			if carrier.closes.Load() != 1 {
				t.Fatalf("carrier closes = %d, want 1", carrier.closes.Load())
			}
		})
	}
}

func TestClientDriverRejectsInvalidProofProviderOutputBeforeCapsule(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	cases := map[string]func(*protocol.AdmissionProof, *protocol.ReplayProof){
		"expired proof": func(proof *protocol.AdmissionProof, _ *protocol.ReplayProof) {
			proof.ExpiryUnix = 1
		},
		"wrong issuer": func(proof *protocol.AdmissionProof, _ *protocol.ReplayProof) {
			proof.IssuerID[0] ^= 0xff
		},
		"wrong relay bucket": func(proof *protocol.AdmissionProof, _ *protocol.ReplayProof) {
			proof.RelayBucketID[0] ^= 0xff
		},
		"wrong redemption context": func(proof *protocol.AdmissionProof, _ *protocol.ReplayProof) {
			proof.RedemptionContextHash[0] ^= 0xff
		},
		"wrong replay epoch": func(_ *protocol.AdmissionProof, replay *protocol.ReplayProof) {
			replay.ReplayEpochID++
		},
		"wrong replay window": func(_ *protocol.AdmissionProof, replay *protocol.ReplayProof) {
			replay.ReplayWindowID[0] ^= 0xff
		},
		"wrong token redemption": func(_ *protocol.AdmissionProof, replay *protocol.ReplayProof) {
			replay.TokenRedemptionHash[0] ^= 0xff
		},
		"wrong replay context": func(_ *protocol.AdmissionProof, replay *protocol.ReplayProof) {
			replay.ReplayContextHash[0] ^= 0xff
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := validClientDriverConfig(t, now)
			config.Deployment = fixture.deployment
			base := &productionClientProofProvider{
				issuerID:      append([]byte(nil), config.AccessHint.HintIssuerID...),
				relayBucketID: append([]byte(nil), config.AccessHint.RelayBucketID...),
			}
			provider := &mutatingClientProofProvider{base: base, mutate: mutate}
			config.ProofProvider = provider
			driver, err := NewClientDriver(config)
			if err != nil {
				t.Fatal(err)
			}
			opener := &scriptedClientOpener{fixture: fixture, config: config, skipRelayApplication: true}

			if established, err := driver.Connect(context.Background(), opener); err == nil || established != nil {
				if established != nil {
					_ = established.Close()
				}
				t.Fatal("client accepted invalid proof provider output")
			}
			carrier := opener.lastCarrier()
			if carrier == nil {
				t.Fatal("client did not open carrier")
			}
			if base.calls.Load() != 1 || len(carrier.writes) != 1 || carrier.streamRequests.Load() != 0 {
				t.Fatal("client advanced beyond invalid proof provider output")
			}
			if carrier.closes.Load() != 1 {
				t.Fatalf("carrier closes = %d, want 1", carrier.closes.Load())
			}
		})
	}
}

func TestClientDriverRejectsNilCarrierOpener(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	_, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	var typedNil *scriptedClientOpener
	for name, opener := range map[string]ClientCarrierOpener{"nil": nil, "typed nil": typedNil} {
		t.Run(name, func(t *testing.T) {
			if established, err := driver.Connect(context.Background(), opener); err == nil || established != nil {
				t.Fatal("client accepted nil carrier opener")
			}
		})
	}
	if provider.calls.Load() != 0 {
		t.Fatal("proof provider called without a carrier opener")
	}
}

func TestClientDriverClosesPartialApplicationStreamsOnAcquisitionError(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	readCarrier := &countingDriverCloser{}
	writeCarrier := &countingDriverCloser{}
	opener := &scriptedClientOpener{
		fixture:              fixture,
		config:               config,
		applicationRead:      readCarrier,
		applicationWrite:     writeCarrier,
		applicationStreamErr: errors.New("stream acquisition failed"),
	}

	if established, err := driver.Connect(context.Background(), opener); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("client accepted failed application stream acquisition")
	}
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client did not open carrier")
	}
	if provider.calls.Load() != 1 || carrier.streamRequests.Load() != 1 {
		t.Fatal("client did not reach authenticated stream acquisition")
	}
	if readCarrier.calls.Load() != 1 || writeCarrier.calls.Load() != 1 {
		t.Fatalf("partial stream closes = %d/%d, want 1/1", readCarrier.calls.Load(), writeCarrier.calls.Load())
	}
	if carrier.closes.Load() != 1 {
		t.Fatalf("carrier closes = %d, want 1", carrier.closes.Load())
	}
}

func newClientDriverTestSetup(t *testing.T, now time.Time, fixture testVerifiedDeploymentFixture, mutate func(*ClientDriverConfig)) (ClientDriverConfig, *productionClientProofProvider, *ClientDriver) {
	t.Helper()
	config := validClientDriverConfig(t, now)
	config.Deployment = fixture.deployment
	if mutate != nil {
		mutate(&config)
	}
	provider := &productionClientProofProvider{
		issuerID:      append([]byte(nil), config.AccessHint.HintIssuerID...),
		relayBucketID: append([]byte(nil), config.AccessHint.RelayBucketID...),
	}
	config.ProofProvider = provider
	driver, err := NewClientDriver(config)
	if err != nil {
		t.Fatal(err)
	}
	return config, provider, driver
}

func validClientVirtualAddress(now time.Time) *protocol.VirtualAddressAssignment {
	return &protocol.VirtualAddressAssignment{
		LeaseID:         bytes.Repeat([]byte{0x71}, 16),
		AddressFamily:   1,
		ClientAddress:   []byte{10, 0, 0, 2},
		PrefixLength:    24,
		DNSServerHint:   []byte{10, 0, 0, 1},
		LeaseExpiryUnix: uint64(now.Add(time.Hour).Unix()),
	}
}

type mutatingClientProofProvider struct {
	base   *productionClientProofProvider
	mutate func(*protocol.AdmissionProof, *protocol.ReplayProof)
}

func (p *mutatingClientProofProvider) BuildProofs(ctx context.Context, request ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	proof, replay, err := p.base.BuildProofs(ctx, request)
	if err == nil {
		p.mutate(&proof, &replay)
	}
	return proof, replay, err
}

type scriptedClientOpener struct {
	fixture testVerifiedDeploymentFixture
	config  ClientDriverConfig

	mutateBinding        func(*FirstHopBinding)
	mutatePrelude        func(*protocol.CoverPrelude1)
	mutateSignedPrelude  func(*protocol.CoverPrelude1)
	mutatePreludeRecord  func([]byte)
	mutatePolicyAccept   func(*protocol.PolicyAccept)
	mutateCapsule2       func(*protocol.CoverCapsule2Plain)
	mutateCapsule2Record func([]byte)
	capsule2Route        func(uint64) uint64
	allowInvalidPolicy   bool
	skipRelayApplication bool
	applicationRead      io.ReadCloser
	applicationWrite     io.WriteCloser
	applicationStreamErr error

	mu             sync.Mutex
	carrier        *scriptedClientCarrier
	coverRandom    []byte
	authorityHash  []byte
	pathTemplateID []byte
}

func (o *scriptedClientOpener) Open(ctx context.Context, coverRandom []byte) (BootstrapCarrier, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, context.Canceled
	}
	if len(coverRandom) != 32 {
		return nil, fmt.Errorf("test opener: cover random length %d", len(coverRandom))
	}
	template := o.fixture.deployment.Template()
	class := o.fixture.deployment.RequestClass()
	binding, err := clientTestBinding(o.fixture.deployment, coverRandom)
	if err != nil {
		return nil, err
	}
	if o.mutateBinding != nil {
		o.mutateBinding(&binding)
	}
	carrier := &scriptedClientCarrier{
		fixture:              o.fixture,
		config:               o.config,
		binding:              binding,
		mutatePrelude:        o.mutatePrelude,
		mutateSignedPrelude:  o.mutateSignedPrelude,
		mutatePreludeRecord:  o.mutatePreludeRecord,
		mutatePolicyAccept:   o.mutatePolicyAccept,
		mutateCapsule2:       o.mutateCapsule2,
		mutateCapsule2Record: o.mutateCapsule2Record,
		capsule2Route:        o.capsule2Route,
		allowInvalidPolicy:   o.allowInvalidPolicy,
		skipRelayApplication: o.skipRelayApplication,
		applicationRead:      o.applicationRead,
		applicationWrite:     o.applicationWrite,
		applicationStreamErr: o.applicationStreamErr,
	}
	o.mu.Lock()
	o.carrier = carrier
	o.coverRandom = append([]byte(nil), coverRandom...)
	o.authorityHash = append([]byte(nil), template.PublicNameHash...)
	o.pathTemplateID = append([]byte(nil), class.PathTemplateID...)
	o.mu.Unlock()
	return carrier, nil
}

func (o *scriptedClientOpener) lastCarrier() *scriptedClientCarrier {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.carrier
}

type scriptedClientCarrier struct {
	fixture testVerifiedDeploymentFixture
	config  ClientDriverConfig
	binding FirstHopBinding

	mutatePrelude        func(*protocol.CoverPrelude1)
	mutateSignedPrelude  func(*protocol.CoverPrelude1)
	mutatePreludeRecord  func([]byte)
	mutatePolicyAccept   func(*protocol.PolicyAccept)
	mutateCapsule2       func(*protocol.CoverCapsule2Plain)
	mutateCapsule2Record func([]byte)
	capsule2Route        func(uint64) uint64
	allowInvalidPolicy   bool
	skipRelayApplication bool
	applicationRead      io.ReadCloser
	applicationWrite     io.WriteCloser
	applicationStreamErr error

	writes           [][]byte
	reads            [][]byte
	p0               protocol.CoverPrelude0
	p1               protocol.CoverPrelude1
	preludeHash      []byte
	handshakeSecret  HandshakeSecrets
	routeInstanceID  uint64
	relayApplication *session.Application
	streamRequests   atomic.Int32
	closes           atomic.Int32
}

func (c *scriptedClientCarrier) Binding() FirstHopBinding { return cloneClientTestBinding(c.binding) }

func (c *scriptedClientCarrier) WriteRecord(record []byte) error {
	c.writes = append(c.writes, append([]byte(nil), record...))
	switch len(c.writes) {
	case 1:
		return c.respondPrelude(record)
	case 2:
		return c.respondCapsule(record)
	default:
		return fmt.Errorf("test carrier: unexpected bootstrap record")
	}
}

func (c *scriptedClientCarrier) ReadRecord() ([]byte, error) {
	if len(c.reads) == 0 {
		return nil, io.EOF
	}
	record := append([]byte(nil), c.reads[0]...)
	c.reads = c.reads[1:]
	return record, nil
}

func (c *scriptedClientCarrier) ApplicationStreams() (io.ReadCloser, io.WriteCloser, error) {
	c.streamRequests.Add(1)
	readCarrier := c.applicationRead
	if readCarrier == nil {
		readCarrier = &countingDriverCloser{}
	}
	writeCarrier := c.applicationWrite
	if writeCarrier == nil {
		writeCarrier = &countingDriverCloser{}
	}
	return readCarrier, writeCarrier, c.applicationStreamErr
}

func (c *scriptedClientCarrier) Close() error {
	c.closes.Add(1)
	zeroHandshakeSecrets(&c.handshakeSecret)
	if c.relayApplication != nil {
		return c.relayApplication.Close()
	}
	return nil
}

func (c *scriptedClientCarrier) respondPrelude(record []byte) error {
	p0, err := decodeClientTestPrelude0(record)
	if err != nil {
		return err
	}
	serverECDH, err := auroracrypto.GenerateECDHForSuite(c.fixture.deployment.Suite())
	if err != nil {
		return err
	}
	defer serverECDH.Destroy()
	sharedPQ, ciphertext, err := auroracrypto.EncapsulateMLKEMForSuite(c.fixture.deployment.Suite(), p0.ClientMLKEMEncapsulationKey)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(sharedPQ)
	sharedClassical, err := serverECDH.SharedSecret(p0.ClientClassicalEphPub)
	if err != nil {
		return err
	}
	defer zeroBindingBytes(sharedClassical)
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return err
	}
	descriptor := c.fixture.deployment.Descriptor()
	template := c.fixture.deployment.Template()
	p1 := protocol.CoverPrelude1{
		MsgType:                       registry.MsgCoverPrelude1,
		Version:                       registry.Version20,
		SelectedSuite:                 c.fixture.deployment.Suite(),
		RelayDescriptorHash:           c.fixture.deployment.DescriptorHash(),
		CoverTemplateHash:             c.fixture.deployment.TemplateHash(),
		RelayEpochID:                  descriptor.EpochID,
		ServerNonce:                   serverNonce,
		ServerClassicalEphPub:         serverECDH.PublicKeyBytes(),
		ServerMLKEMCiphertextToClient: ciphertext,
		SelectedCoverProfileID:        bytes.Repeat([]byte{0x91}, 16),
		SelectedBootstrapEnvelopeID:   append([]byte(nil), template.CapsuleEnvelope.EnvelopeID...),
	}
	if c.mutatePrelude != nil {
		c.mutatePrelude(&p1)
	}
	finalize := func(value protocol.CoverPrelude1) (protocol.CoverPrelude1, []byte, error) {
		transcript, err := PreludeTranscriptHash(c.fixture.deployment.Suite(), c.binding.CoverStreamBinding, p0, value)
		if err != nil {
			return protocol.CoverPrelude1{}, nil, err
		}
		value.ServerPreludeSignatureClassical, err = ecdsa.SignASN1(rand.Reader, c.fixture.epochClassical, transcript)
		if err != nil {
			return protocol.CoverPrelude1{}, nil, err
		}
		value.ServerPreludeSignaturePQ = make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(c.fixture.epochPQ, transcript, nil, false, value.ServerPreludeSignaturePQ); err != nil {
			return protocol.CoverPrelude1{}, nil, err
		}
		encoded, err := protocol.Encode(value)
		return value, encoded, err
	}
	p1, encoded, err := padCoverPrelude1(rand.Reader, p1, template.PreludeEnvelope.MinResponseBodySize, template.PreludeEnvelope.MaxResponseBodySize, finalize)
	if err != nil {
		return err
	}
	if c.mutateSignedPrelude != nil {
		c.mutateSignedPrelude(&p1)
		encoded, err = protocol.Encode(p1)
		if err != nil {
			return err
		}
	}
	if c.mutatePreludeRecord != nil {
		c.mutatePreludeRecord(encoded)
	}
	preludeHash, err := PreludeTranscriptHash(c.fixture.deployment.Suite(), c.binding.CoverStreamBinding, p0, p1)
	if err != nil {
		return err
	}
	secrets, err := DeriveHandshakeSecrets(c.fixture.deployment.Suite(), sharedPQ, sharedClassical, c.binding.HandshakeBindingContext, preludeHash)
	if err != nil {
		return err
	}
	routeID, err := auroracrypto.FirstHopRouteInstanceID(c.fixture.deployment.Suite(), preludeHash, c.fixture.deployment.DescriptorHash(), c.binding.HandshakeBindingContext, p0.ClientNonce)
	if err != nil {
		return err
	}
	c.p0 = p0
	c.p1 = p1
	c.preludeHash = preludeHash
	c.handshakeSecret = secrets
	c.routeInstanceID = routeID
	c.reads = append(c.reads, encoded)
	return nil
}

func (c *scriptedClientCarrier) respondCapsule(record []byte) error {
	control := ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   c.fixture.deployment.Suite(),
		RouteInstanceID:                 c.routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         c.binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: c.preludeHash,
		ClientHSKey:                     c.handshakeSecret.ClientHSKey,
		ClientHSIV:                      c.handshakeSecret.ClientHSIV,
		ServerHSKey:                     c.handshakeSecret.ServerHSKey,
		ServerHSIV:                      c.handshakeSecret.ServerHSIV,
	}
	capsule1, err := OpenCoverCapsule1(control, record)
	if err != nil {
		return err
	}
	accept := protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             c.fixture.deployment.Suite(),
		SelectedMethod:            c.fixture.deployment.Method(),
		SelectedPolicy:            c.config.PolicyOffer.RequestedPolicyID,
		SelectedRouteModeID:       c.config.PolicyOffer.RequestedRouteModeID,
		SelectedShape:             c.config.PolicyOffer.RequestedShapeID,
		SelectedTunnelPersonality: c.config.PolicyOffer.TunnelPersonalityOffers[0],
	}
	if c.mutatePolicyAccept != nil {
		c.mutatePolicyAccept(&accept)
	}
	serverFinished, capsule1Hash, policyHash, err := ComputeServerFinished(c.fixture.deployment.Suite(), c.handshakeSecret.ServerFinishedKey, c.preludeHash, capsule1, accept)
	if err != nil {
		if !c.allowInvalidPolicy {
			return err
		}
		hashLength, hashErr := auroracrypto.SuiteHashLength(c.fixture.deployment.Suite())
		if hashErr != nil {
			return hashErr
		}
		serverFinished = make([]byte, hashLength)
	}
	template := c.fixture.deployment.Template()
	capsule2 := protocol.CoverCapsule2Plain{
		MsgType:         registry.MsgCoverCapsule2,
		RouteInstanceID: c.routeInstanceID,
		PolicyAccept:    accept,
		ServerFinished:  serverFinished,
	}
	if c.mutateCapsule2 != nil {
		c.mutateCapsule2(&capsule2)
	}
	finalize := func(value protocol.CoverCapsule2Plain) (protocol.CoverCapsule2Plain, []byte, error) {
		if c.capsule2Route != nil {
			value.RouteInstanceID = c.capsule2Route(c.routeInstanceID)
			encoded, err := protocol.Encode(value)
			if err != nil {
				return protocol.CoverCapsule2Plain{}, nil, err
			}
			sealed, err := sealControl(control, registry.MsgCoverCapsule2, ControlDirectionHopToClient, control.ServerHSKey, control.ServerHSIV, encoded)
			return value, sealed, err
		}
		sealed, err := SealCoverCapsule2(control, value)
		return value, sealed, err
	}
	_, sealed, err := padCoverCapsule2(rand.Reader, capsule2, template.CapsuleEnvelope.MinCapsuleBodySize, template.CapsuleEnvelope.MaxCapsuleBodySize, finalize)
	if err != nil {
		return err
	}
	if c.mutateCapsule2Record != nil {
		c.mutateCapsule2Record(sealed)
	}
	c.reads = append(c.reads, sealed)
	if c.skipRelayApplication {
		return nil
	}
	applicationSecrets, err := DeriveApplicationSecrets(c.fixture.deployment.Suite(), c.handshakeSecret.HandshakeSecret, c.preludeHash, capsule1Hash, policyHash, serverFinished)
	if err != nil {
		return err
	}
	defer zeroApplicationSecrets(&applicationSecrets)
	c.relayApplication, err = session.NewApplication(session.Config{
		Suite:           c.fixture.deployment.Suite(),
		RouteInstanceID: c.routeInstanceID,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 1, Secret: applicationSecrets.ServerAppSecret0, Key: applicationSecrets.ServerAppKey0, IV: applicationSecrets.ServerAppIV0},
		Read:            session.DirectionConfig{Direction: 0, Secret: applicationSecrets.ClientAppSecret0, Key: applicationSecrets.ClientAppKey0, IV: applicationSecrets.ClientAppIV0},
		Limits:          c.config.SessionLimits,
		Rekey:           c.config.Rekey,
	})
	if err != nil {
		return err
	}
	return nil
}

type productionClientProofProvider struct {
	issuerID      []byte
	relayBucketID []byte
	calls         atomic.Int32
	mu            sync.Mutex
	requests      []clientProofObservation
}

type clientProofObservation struct {
	request     ClientProofRequest
	replayNonce []byte
}

func (p *productionClientProofProvider) BuildProofs(_ context.Context, request ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	p.calls.Add(1)
	tokenNonce := make([]byte, 32)
	replayNonce := make([]byte, 32)
	if _, err := rand.Read(tokenNonce); err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	if _, err := rand.Read(replayNonce); err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              append([]byte(nil), p.issuerID...),
		TokenKeyID:            bytes.Repeat([]byte{0x51}, 32),
		RelayBucketID:         append([]byte(nil), p.relayBucketID...),
		TokenScopeID:          bytes.Repeat([]byte{0x52}, 16),
		ExpiryUnix:            request.ReplayEpochValidUntil - 1,
		TokenNonce:            tokenNonce,
		RedemptionContextHash: append([]byte(nil), request.AdmissionContextHash...),
		TokenAuthenticator:    bytes.Repeat([]byte{0x53}, 256),
	}
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: bytes.Repeat([]byte{0x54}, 32),
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             []byte("issuer.test"),
		OriginInfo:             []byte("origin.test"),
		IssuerMetadataHash:     bytes.Repeat([]byte{0x55}, 48),
	}
	var err error
	proof.TokenPublicMetadata, err = protocol.Encode(metadata)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	replay := protocol.ReplayProof{
		ProofVersion:        registry.Version20,
		ReplayEpochID:       request.ReplayEpochID,
		TokenRedemptionHash: redemption,
		ClientReplayNonce:   replayNonce,
		ReplayWindowID:      append([]byte(nil), request.ReplayWindowID...),
	}
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemption, replay, request.RouteInstanceID, request.HopIndex, request.HandshakeBindingContext, request.AdmissionContextHash)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	p.mu.Lock()
	p.requests = append(p.requests, clientProofObservation{request: cloneClientProofRequest(request), replayNonce: append([]byte(nil), replayNonce...)})
	p.mu.Unlock()
	return proof, replay, nil
}

func (p *productionClientProofProvider) lastRequest() clientProofObservation {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[len(p.requests)-1]
}

func cloneClientProofRequest(in ClientProofRequest) ClientProofRequest {
	in.AdmissionContextHash = append([]byte(nil), in.AdmissionContextHash...)
	in.HandshakeBindingContext = append([]byte(nil), in.HandshakeBindingContext...)
	in.ReplayWindowID = append([]byte(nil), in.ReplayWindowID...)
	return in
}

func clientTestBinding(deployment interface {
	Template() protocol.CoverTemplate
	RequestClass() protocol.RequestClass
	Method() uint64
}, coverRandom []byte) (FirstHopBinding, error) {
	template := deployment.Template()
	class := deployment.RequestClass()
	outer := bytes.Repeat([]byte{0x61}, 48)
	channel := bytes.Repeat([]byte{0x62}, 48)
	connection := auroracrypto.PreHash([]byte("h2"), channel, make([]byte, 48))
	stream, err := CoverStreamBinding(CoverStreamBindingInput{
		OuterExporterValue:       outer,
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         connection,
		StreamIDOrRequestID:      1,
		MethodFamilyID:           deployment.Method(),
		NormalizedAuthorityHash:  template.PublicNameHash,
		NormalizedPathTemplateID: class.PathTemplateID,
		RequestClassID:           class.ClassID,
		ClientCoverRandom:        coverRandom,
	})
	if err != nil {
		return FirstHopBinding{}, err
	}
	bindingContext, err := FirstHopBindingContext(outer, stream)
	if err != nil {
		return FirstHopBinding{}, err
	}
	return FirstHopBinding{
		OuterExporterValue:      outer,
		TLSExporterChannelID:    channel,
		ConnectionIDHash:        connection,
		CoverStreamBinding:      stream,
		HandshakeBindingContext: bindingContext,
	}, nil
}

func cloneClientTestBinding(in FirstHopBinding) FirstHopBinding {
	in.OuterExporterValue = append([]byte(nil), in.OuterExporterValue...)
	in.TLSExporterChannelID = append([]byte(nil), in.TLSExporterChannelID...)
	in.ConnectionIDHash = append([]byte(nil), in.ConnectionIDHash...)
	in.CoverStreamBinding = append([]byte(nil), in.CoverStreamBinding...)
	in.HandshakeBindingContext = append([]byte(nil), in.HandshakeBindingContext...)
	return in
}

func decodeClientTestPrelude0(encoded []byte) (protocol.CoverPrelude0, error) {
	r := wire.NewReader(encoded)
	p0 := protocol.DecodeCoverPrelude0(r)
	if r.Err() != nil {
		return protocol.CoverPrelude0{}, r.Err()
	}
	if !r.EOF() {
		return protocol.CoverPrelude0{}, fmt.Errorf("trailing Prelude0 bytes")
	}
	return p0, nil
}

func assertApplicationsInteroperate(t *testing.T, client, relay *session.Application) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, direction := range []struct {
		name   string
		writer *session.Application
		reader *session.Application
		value  byte
	}{
		{name: "client to relay", writer: client, reader: relay, value: 0x81},
		{name: "relay to client", writer: relay, reader: client, value: 0x82},
	} {
		t.Run(direction.name, func(t *testing.T) {
			block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: []byte{direction.value}}}}
			if err := direction.writer.QueueFrames(ctx, block); err != nil {
				t.Fatal(err)
			}
			packet, err := direction.writer.NextPacket(ctx)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := direction.reader.HandlePacket(ctx, time.Now(), packet)
			if err != nil {
				t.Fatal(err)
			}
			if len(opened) != 1 || len(opened[0].Frames) != 1 || !bytes.Equal(opened[0].Frames[0].Payload, []byte{direction.value}) {
				t.Fatal("application packet did not interoperate")
			}
		})
	}
}
