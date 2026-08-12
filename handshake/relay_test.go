package handshake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestRelayDriverBeginSpendsHintBeforeSigningAuthenticatedPrelude(t *testing.T) {
	now := time.Now()
	deployment := newTestVerifiedDeploymentFixture(t, now)
	client := newRelayClientPreludeFixture(t, now, deployment)
	events := &relayEventLog{}
	resolver := &orderedHintResolver{events: events, credential: client.config.AccessHint}
	hintCache := &orderedRelayReplayCache{events: events, event: "insert spent hint", inner: admission.NewMemoryReplayCache()}
	driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
	driverConfig.HintResolver = resolver
	driverConfig.HintSpentCache = hintCache
	driverConfig.ClassicalSigner = &orderedRelaySigner{
		events:    events,
		event:     "sign classical transcript",
		publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey,
		classical: deployment.epochClassical,
	}
	driverConfig.PQSigner = &orderedRelaySigner{
		events:    events,
		event:     "sign PQ transcript",
		publicKey: deployment.deployment.Descriptor().EpochAuthPQKey,
		pq:        deployment.epochPQ,
	}
	driver, err := NewRelayDriver(driverConfig)
	if err != nil {
		t.Fatal(err)
	}
	relayHandshake, prelude1, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if relayHandshake == nil {
		t.Fatal("relay did not retain authenticated handshake state")
	}
	t.Cleanup(func() { _ = relayHandshake.Close() })
	if prelude1.MsgType != registry.MsgCoverPrelude1 || prelude1.SelectedSuite != deployment.deployment.Suite() {
		t.Fatal("relay returned invalid Prelude1 selection")
	}
	template := deployment.deployment.Template()
	if !bytes.Equal(prelude1.SelectedCoverProfileID, template.TemplateID) || !bytes.Equal(prelude1.SelectedBootstrapEnvelopeID, template.CapsuleEnvelope.EnvelopeID) {
		t.Fatal("relay returned unauthenticated cover profile or envelope")
	}
	if _, err := VerifyCoverPrelude1Signatures(CoverPreludeVerificationInput{
		Suite:              deployment.deployment.Suite(),
		CoverStreamBinding: client.binding.CoverStreamBinding,
		Prelude0:           client.prelude0,
		Prelude1:           prelude1,
		Descriptor:         deployment.deployment.Descriptor(),
		RequirePQ:          true,
	}); err != nil {
		t.Fatalf("relay Prelude1 did not verify: %v", err)
	}
	wantEvents := []string{"resolve exact tuple", "insert spent hint", "sign classical transcript", "sign PQ transcript"}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("relay Begin event order = %v, want %v", got, wantEvents)
	}
	if resolver.calls != 1 || hintCache.inserts != 1 {
		t.Fatalf("resolver/cache calls = %d/%d, want 1/1", resolver.calls, hintCache.inserts)
	}
}

func TestRelayDriverBeginFailsClosedAtEveryAdmissionBoundary(t *testing.T) {
	now := time.Now()
	deployment := newTestVerifiedDeploymentFixture(t, now)
	client := newRelayClientPreludeFixture(t, now, deployment)
	cases := []struct {
		name            string
		mutatePrelude   func(*protocol.CoverPrelude0)
		mutateBinding   func(*FirstHopBinding)
		mutateResolver  func(*orderedHintResolver)
		mutateCache     func(*orderedRelayReplayCache)
		mutateClassical func(*orderedRelaySigner)
		mutatePQ        func(*orderedRelaySigner)
		nowUnix         uint64
		cancel          bool
		wantEvents      []string
	}{
		{
			name: "malformed header",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.MsgType = registry.MsgCoverPrelude1
			},
		},
		{
			name: "undersized Prelude0 envelope",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.Padding = nil
			},
		},
		{
			name: "descriptor mismatch",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.RelayDescriptorHash[0] ^= 0xff
			},
		},
		{
			name: "template mismatch",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.CoverTemplateHash[0] ^= 0xff
			},
		},
		{
			name: "request class mismatch",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.RequestClassID++
			},
		},
		{
			name: "no shared suite",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.SuiteOffers = []uint64{registry.SuiteHybrid768AESGCM}
			},
		},
		{
			name: "duplicate suite offer",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.SuiteOffers = append(prelude.SuiteOffers, prelude.SuiteOffers[0])
			},
		},
		{
			name: "lab suite offer",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.SuiteOffers = append(prelude.SuiteOffers, registry.SuiteLabClassical)
			},
		},
		{
			name: "bad live binding",
			mutateBinding: func(binding *FirstHopBinding) {
				binding.HandshakeBindingContext[0] ^= 0xff
			},
		},
		{
			name: "malformed hybrid share",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.ClientClassicalEphPub = []byte{1}
			},
		},
		{
			name: "resolver error",
			mutateResolver: func(resolver *orderedHintResolver) {
				resolver.err = fmt.Errorf("resolver unavailable")
			},
			wantEvents: []string{"resolve exact tuple"},
		},
		{
			name: "zero resolved credential",
			mutateResolver: func(resolver *orderedHintResolver) {
				resolver.credential = admission.AccessHintCredential{}
			},
			wantEvents: []string{"resolve exact tuple"},
		},
		{
			name: "resolved tuple mismatch",
			mutateResolver: func(resolver *orderedHintResolver) {
				resolver.credential.HintSelector[0] ^= 0xff
			},
			wantEvents: []string{"resolve exact tuple"},
		},
		{
			name: "expired resolved credential",
			mutateResolver: func(resolver *orderedHintResolver) {
				resolver.credential.ExpiryUnix = uint64(now.Unix())
			},
			wantEvents: []string{"resolve exact tuple"},
		},
		{
			name: "bad access hint",
			mutatePrelude: func(prelude *protocol.CoverPrelude0) {
				prelude.AccessHint[0] ^= 0xff
			},
			wantEvents: []string{"resolve exact tuple"},
		},
		{
			name: "hint cache error",
			mutateCache: func(cache *orderedRelayReplayCache) {
				cache.err = fmt.Errorf("cache unavailable")
			},
			wantEvents: []string{"resolve exact tuple", "insert spent hint"},
		},
		{
			name: "duplicate hint",
			mutateCache: func(cache *orderedRelayReplayCache) {
				cache.forceDuplicate = true
			},
			wantEvents: []string{"resolve exact tuple", "insert spent hint"},
		},
		{
			name: "classical signer error after spend",
			mutateClassical: func(signer *orderedRelaySigner) {
				signer.err = fmt.Errorf("classical signer failed")
			},
			wantEvents: []string{"resolve exact tuple", "insert spent hint", "sign classical transcript"},
		},
		{
			name: "PQ signer error after spend",
			mutatePQ: func(signer *orderedRelaySigner) {
				signer.err = fmt.Errorf("PQ signer failed")
			},
			wantEvents: []string{"resolve exact tuple", "insert spent hint", "sign classical transcript", "sign PQ transcript"},
		},
		{name: "invalid zero time", nowUnix: 0},
		{name: "canceled context", cancel: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prelude0, err := cloneCoverPrelude0(client.prelude0)
			if err != nil {
				t.Fatal(err)
			}
			binding := cloneFirstHopBinding(client.binding)
			if tc.mutatePrelude != nil {
				tc.mutatePrelude(&prelude0)
			}
			if tc.mutateBinding != nil {
				tc.mutateBinding(&binding)
			}
			events := &relayEventLog{}
			resolver := &orderedHintResolver{
				events:     events,
				expected:   client.config.AccessHint,
				credential: cloneAccessHint(client.config.AccessHint),
			}
			hintCache := &orderedRelayReplayCache{events: events, event: "insert spent hint", inner: admission.NewMemoryReplayCache()}
			classicalSigner := &orderedRelaySigner{
				events:    events,
				event:     "sign classical transcript",
				publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey,
				classical: deployment.epochClassical,
			}
			pqSigner := &orderedRelaySigner{
				events:    events,
				event:     "sign PQ transcript",
				publicKey: deployment.deployment.Descriptor().EpochAuthPQKey,
				pq:        deployment.epochPQ,
			}
			if tc.mutateResolver != nil {
				tc.mutateResolver(resolver)
			}
			if tc.mutateCache != nil {
				tc.mutateCache(hintCache)
			}
			if tc.mutateClassical != nil {
				tc.mutateClassical(classicalSigner)
			}
			if tc.mutatePQ != nil {
				tc.mutatePQ(pqSigner)
			}
			driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
			driverConfig.HintResolver = resolver
			driverConfig.HintSpentCache = hintCache
			driverConfig.ClassicalSigner = classicalSigner
			driverConfig.PQSigner = pqSigner
			driver, err := NewRelayDriver(driverConfig)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			nowUnix := tc.nowUnix
			if tc.name != "invalid zero time" {
				nowUnix = uint64(now.Unix())
			}

			handshake, prelude1, err := driver.Begin(ctx, binding, prelude0, nowUnix)
			if err == nil || handshake != nil || !reflect.DeepEqual(prelude1, protocol.CoverPrelude1{}) {
				if handshake != nil {
					_ = handshake.Close()
				}
				t.Fatal("relay Begin did not fail closed")
			}
			if got := events.snapshot(); !reflect.DeepEqual(got, tc.wantEvents) {
				t.Fatalf("relay Begin events = %v, want %v", got, tc.wantEvents)
			}
		})
	}
}

func TestRelayDriverBeginDoesNotRollBackHintAfterSignerFailure(t *testing.T) {
	now := time.Now()
	deployment := newTestVerifiedDeploymentFixture(t, now)
	client := newRelayClientPreludeFixture(t, now, deployment)
	events := &relayEventLog{}
	resolver := &orderedHintResolver{events: events, expected: client.config.AccessHint, credential: client.config.AccessHint}
	hintCache := &orderedRelayReplayCache{events: events, event: "insert spent hint", inner: admission.NewMemoryReplayCache()}
	classicalSigner := &orderedRelaySigner{
		events:    events,
		event:     "sign classical transcript",
		publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey,
		classical: deployment.epochClassical,
		err:       fmt.Errorf("signer failed"),
	}
	pqSigner := &orderedRelaySigner{
		events:    events,
		event:     "sign PQ transcript",
		publicKey: deployment.deployment.Descriptor().EpochAuthPQKey,
		pq:        deployment.epochPQ,
	}
	driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
	driverConfig.HintResolver = resolver
	driverConfig.HintSpentCache = hintCache
	driverConfig.ClassicalSigner = classicalSigner
	driverConfig.PQSigner = pqSigner
	driver, err := NewRelayDriver(driverConfig)
	if err != nil {
		t.Fatal(err)
	}

	if handshake, _, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix())); err == nil || handshake != nil {
		t.Fatal("relay accepted signer failure")
	}
	classicalSigner.err = nil
	if handshake, _, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix())); err == nil || handshake != nil {
		t.Fatal("relay reused hint after signer failure")
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{
		"resolve exact tuple", "insert spent hint", "sign classical transcript",
		"resolve exact tuple", "insert spent hint",
	}) {
		t.Fatalf("retry event order = %v", got)
	}
}

func TestRelayHandshakeFinishAuthenticatesReplayBeforeReleasingApplication(t *testing.T) {
	now := time.Now()
	deployment := newTestVerifiedDeploymentFixture(t, now)
	client := newRelayClientPreludeFixture(t, now, deployment)
	events := &relayEventLog{}
	resolver := &orderedHintResolver{events: events, expected: client.config.AccessHint, credential: client.config.AccessHint}
	hintCache := &orderedRelayReplayCache{events: events, event: "insert spent hint", inner: admission.NewMemoryReplayCache()}
	tokenCache := &orderedRelayReplayCache{events: events, event: "insert spent token", inner: admission.NewMemoryReplayCache()}
	bootstrapCache := &orderedRelayReplayCache{events: events, event: "insert bootstrap attempt", inner: admission.NewMemoryReplayCache()}
	classicalSigner := &orderedRelaySigner{
		events: events, event: "sign classical transcript",
		publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey, classical: deployment.epochClassical,
	}
	pqSigner := &orderedRelaySigner{
		events: events, event: "sign PQ transcript",
		publicKey: deployment.deployment.Descriptor().EpochAuthPQKey, pq: deployment.epochPQ,
	}
	verifier := &orderedAdmissionVerifier{
		events: events,
		mutate: func(proof *protocol.AdmissionProof) {
			proof.TokenNonce[0] ^= 0xff
		},
	}
	selector := &orderedPolicySelector{
		events: events,
		accept: relayTestPolicyAccept(client.config, deployment.deployment),
		mutate: func(offer *protocol.PolicyOffer, hints *protocol.ClientTransportHints) {
			offer.OfferedMethods[0] = registry.MethodWebH1WS
			hints.Padding[0] ^= 0xff
		},
	}
	driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
	driverConfig.HintResolver = resolver
	driverConfig.HintSpentCache = hintCache
	driverConfig.TokenSpentCache = tokenCache
	driverConfig.BootstrapCache = bootstrapCache
	driverConfig.ClassicalSigner = classicalSigner
	driverConfig.PQSigner = pqSigner
	driverConfig.AdmissionVerifier = verifier
	driverConfig.PolicySelector = selector
	driver, err := NewRelayDriver(driverConfig)
	if err != nil {
		t.Fatal(err)
	}
	driver.newApplication = func(config session.Config) (*session.Application, error) {
		events.add("create application")
		return session.NewApplication(config)
	}
	relayHandshake, prelude1, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relayHandshake.Close() })
	capsule := newRelayClientCapsuleFixture(t, now, deployment.deployment, client, prelude1)
	events.reset()

	capsule2Record, relayApplication, accept, err := relayHandshake.Finish(context.Background(), capsule.record, uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if relayApplication == nil {
		t.Fatal("relay did not create application after authenticated replay")
	}
	t.Cleanup(func() { _ = relayApplication.Close() })
	wantEvents := []string{"verify admission", "insert spent token", "insert bootstrap attempt", "select policy", "create application"}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("relay Finish event order = %v, want %v", got, wantEvents)
	}
	encodedAccept, err := protocol.Encode(accept)
	if err != nil {
		t.Fatal(err)
	}
	encodedSelected, err := protocol.Encode(selector.accept)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodedAccept, encodedSelected) {
		t.Fatal("relay returned a different accepted policy")
	}
	capsule2, err := OpenCoverCapsule2(capsule.control, capsule2Record)
	if err != nil {
		t.Fatal(err)
	}
	expectedFinished, capsule1Hash, policyHash, err := ComputeServerFinished(deployment.deployment.Suite(), capsule.secrets.ServerFinishedKey, capsule.preludeHash, capsule.capsule1, accept)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&ClientSession{state: StateVerifyCoverCapsule2}).VerifyCoverCapsule2(capsule2, expectedFinished); err != nil {
		t.Fatal(err)
	}
	applicationSecrets, err := DeriveApplicationSecrets(deployment.deployment.Suite(), capsule.secrets.HandshakeSecret, capsule.preludeHash, capsule1Hash, policyHash, expectedFinished)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroApplicationSecrets(&applicationSecrets)
	clientApplication, err := session.NewApplication(session.Config{
		Suite:           deployment.deployment.Suite(),
		RouteInstanceID: capsule.routeInstanceID,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 0, Secret: applicationSecrets.ClientAppSecret0, Key: applicationSecrets.ClientAppKey0, IV: applicationSecrets.ClientAppIV0},
		Read:            session.DirectionConfig{Direction: 1, Secret: applicationSecrets.ServerAppSecret0, Key: applicationSecrets.ServerAppKey0, IV: applicationSecrets.ServerAppIV0},
		Limits:          client.config.SessionLimits,
		Rekey:           client.config.Rekey,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientApplication.Close() })
	assertApplicationsInteroperate(t, clientApplication, relayApplication)
}

func TestRelayHandshakeFinishFailsClosedAndBecomesTerminal(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name            string
		mutateRecord    func(*testing.T, relayClientCapsuleFixture) []byte
		mutateVerifier  func(*orderedAdmissionVerifier)
		mutateToken     func(*orderedRelayReplayCache)
		mutateBootstrap func(*orderedRelayReplayCache)
		mutateSelector  func(*orderedPolicySelector)
		mutateDriver    func(*RelayDriver, *relayEventLog)
		wantEvents      []string
	}{
		{
			name: "bad AEAD tag",
			mutateRecord: func(_ *testing.T, fixture relayClientCapsuleFixture) []byte {
				record := append([]byte(nil), fixture.record...)
				record[len(record)-1] ^= 0xff
				return record
			},
		},
		{
			name: "malformed plaintext",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				plaintext := bytes.Repeat([]byte{0xff}, len(fixture.record)-16)
				record, err := sealControl(fixture.control, registry.MsgCoverCapsule1, ControlDirectionClientToHop, fixture.control.ClientHSKey, fixture.control.ClientHSIV, plaintext)
				if err != nil {
					t.Fatal(err)
				}
				return record
			},
		},
		{
			name: "wrong route instance",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				capsule := cloneRelayTestCapsule1(t, fixture.capsule1)
				capsule.RouteInstanceID ^= 1
				encoded, err := protocol.Encode(capsule)
				if err != nil {
					t.Fatal(err)
				}
				record, err := sealControl(fixture.control, registry.MsgCoverCapsule1, ControlDirectionClientToHop, fixture.control.ClientHSKey, fixture.control.ClientHSIV, encoded)
				if err != nil {
					t.Fatal(err)
				}
				return record
			},
		},
		{
			name: "wrong client finished",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, false, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.ClientFinished[0] ^= 0xff
				})
			},
		},
		{
			name: "expired admission proof",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, true, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.AdmissionProof.ExpiryUnix = 1
				})
			},
		},
		{
			name: "wrong admission context",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, true, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.AdmissionProof.RedemptionContextHash[0] ^= 0xff
				})
			},
		},
		{
			name: "wrong replay epoch",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, true, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.ReplayProof.ReplayEpochID++
				})
			},
		},
		{
			name: "wrong replay window",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, true, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.ReplayProof.ReplayWindowID[0] ^= 0xff
				})
			},
		},
		{
			name: "wrong token redemption hash",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, true, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.ReplayProof.TokenRedemptionHash[0] ^= 0xff
				})
			},
		},
		{
			name: "wrong replay context hash",
			mutateRecord: func(t *testing.T, fixture relayClientCapsuleFixture) []byte {
				return resealRelayTestCapsule(t, fixture, true, func(capsule *protocol.CoverCapsule1Plain) {
					capsule.ReplayProof.ReplayContextHash[0] ^= 0xff
				})
			},
		},
		{
			name: "admission verifier denial",
			mutateVerifier: func(verifier *orderedAdmissionVerifier) {
				verifier.err = fmt.Errorf("proof denied")
			},
			wantEvents: []string{"verify admission"},
		},
		{
			name: "token cache uncertainty",
			mutateToken: func(cache *orderedRelayReplayCache) {
				cache.err = fmt.Errorf("cache unavailable")
			},
			wantEvents: []string{"verify admission", "insert spent token"},
		},
		{
			name: "token replay",
			mutateToken: func(cache *orderedRelayReplayCache) {
				cache.forceDuplicate = true
			},
			wantEvents: []string{"verify admission", "insert spent token"},
		},
		{
			name: "bootstrap cache uncertainty",
			mutateBootstrap: func(cache *orderedRelayReplayCache) {
				cache.err = fmt.Errorf("cache unavailable")
			},
			wantEvents: []string{"verify admission", "insert spent token", "insert bootstrap attempt"},
		},
		{
			name: "bootstrap replay",
			mutateBootstrap: func(cache *orderedRelayReplayCache) {
				cache.forceDuplicate = true
			},
			wantEvents: []string{"verify admission", "insert spent token", "insert bootstrap attempt"},
		},
		{
			name: "policy denial",
			mutateSelector: func(selector *orderedPolicySelector) {
				selector.err = fmt.Errorf("policy denied")
			},
			wantEvents: []string{"verify admission", "insert spent token", "insert bootstrap attempt", "select policy"},
		},
		{
			name: "policy method downgrade",
			mutateSelector: func(selector *orderedPolicySelector) {
				selector.accept.SelectedMethod = registry.MethodWebH1WS
			},
			wantEvents: []string{"verify admission", "insert spent token", "insert bootstrap attempt", "select policy"},
		},
		{
			name: "policy route downgrade",
			mutateSelector: func(selector *orderedPolicySelector) {
				selector.accept.SelectedRouteModeID = registry.RouteSplit2
			},
			wantEvents: []string{"verify admission", "insert spent token", "insert bootstrap attempt", "select policy"},
		},
		{
			name: "application construction failure",
			mutateDriver: func(driver *RelayDriver, events *relayEventLog) {
				driver.newApplication = func(session.Config) (*session.Application, error) {
					events.add("create application")
					return nil, fmt.Errorf("application unavailable")
				}
			},
			wantEvents: []string{"verify admission", "insert spent token", "insert bootstrap attempt", "select policy", "create application"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deployment := newTestVerifiedDeploymentFixture(t, now)
			client := newRelayClientPreludeFixture(t, now, deployment)
			events := &relayEventLog{}
			resolver := &orderedHintResolver{events: events, expected: client.config.AccessHint, credential: client.config.AccessHint}
			hintCache := &orderedRelayReplayCache{events: events, event: "insert spent hint", inner: admission.NewMemoryReplayCache()}
			tokenCache := &orderedRelayReplayCache{events: events, event: "insert spent token", inner: admission.NewMemoryReplayCache()}
			bootstrapCache := &orderedRelayReplayCache{events: events, event: "insert bootstrap attempt", inner: admission.NewMemoryReplayCache()}
			verifier := &orderedAdmissionVerifier{events: events}
			selector := &orderedPolicySelector{events: events, accept: relayTestPolicyAccept(client.config, deployment.deployment)}
			if tc.mutateVerifier != nil {
				tc.mutateVerifier(verifier)
			}
			if tc.mutateToken != nil {
				tc.mutateToken(tokenCache)
			}
			if tc.mutateBootstrap != nil {
				tc.mutateBootstrap(bootstrapCache)
			}
			if tc.mutateSelector != nil {
				tc.mutateSelector(selector)
			}
			driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
			driverConfig.HintResolver = resolver
			driverConfig.HintSpentCache = hintCache
			driverConfig.TokenSpentCache = tokenCache
			driverConfig.BootstrapCache = bootstrapCache
			driverConfig.ClassicalSigner = &orderedRelaySigner{
				events: events, event: "sign classical transcript",
				publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey, classical: deployment.epochClassical,
			}
			driverConfig.PQSigner = &orderedRelaySigner{
				events: events, event: "sign PQ transcript",
				publicKey: deployment.deployment.Descriptor().EpochAuthPQKey, pq: deployment.epochPQ,
			}
			driverConfig.AdmissionVerifier = verifier
			driverConfig.PolicySelector = selector
			driver, err := NewRelayDriver(driverConfig)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutateDriver != nil {
				tc.mutateDriver(driver, events)
			}
			handshake, prelude1, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix()))
			if err != nil {
				t.Fatal(err)
			}
			capsule := newRelayClientCapsuleFixture(t, now, deployment.deployment, client, prelude1)
			record := append([]byte(nil), capsule.record...)
			if tc.mutateRecord != nil {
				record = tc.mutateRecord(t, capsule)
			}
			events.reset()

			capsule2, application, accept, err := handshake.Finish(context.Background(), record, uint64(now.Unix()))
			if err == nil || capsule2 != nil || application != nil || !reflect.DeepEqual(accept, protocol.PolicyAccept{}) {
				if application != nil {
					_ = application.Close()
				}
				t.Fatal("relay Finish did not fail closed")
			}
			if got := events.snapshot(); !reflect.DeepEqual(got, tc.wantEvents) {
				t.Fatalf("relay Finish events = %v, want %v", got, tc.wantEvents)
			}
			beforeRetry := events.snapshot()
			if _, retryApplication, _, retryErr := handshake.Finish(context.Background(), record, uint64(now.Unix())); retryErr == nil || retryApplication != nil {
				t.Fatal("terminal relay handshake was reusable")
			}
			if got := events.snapshot(); !reflect.DeepEqual(got, beforeRetry) {
				t.Fatalf("terminal retry reached dependencies: %v", got)
			}
			if err := handshake.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytesAllZero(handshake.secrets.HandshakeSecret) || !bytesAllZero(handshake.handshakeBinding) {
				t.Fatal("terminal relay handshake retained secret material")
			}
		})
	}
}

func TestRelayHandshakeRejectsSpentTokenWithFreshReplayNonce(t *testing.T) {
	now := time.Now()
	deployment := newTestVerifiedDeploymentFixture(t, now)
	client := newRelayClientPreludeFixture(t, now, deployment)
	driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
	driverConfig.HintResolver = &orderedHintResolver{events: &relayEventLog{}, expected: client.config.AccessHint, credential: client.config.AccessHint}
	driverConfig.HintSpentCache = &orderedRelayReplayCache{inner: admission.NewMemoryReplayCache()}
	driverConfig.TokenSpentCache = testDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	driverConfig.BootstrapCache = testDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	driverConfig.ClassicalSigner = &orderedRelaySigner{
		events: &relayEventLog{}, publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey, classical: deployment.epochClassical,
	}
	driverConfig.PQSigner = &orderedRelaySigner{
		events: &relayEventLog{}, publicKey: deployment.deployment.Descriptor().EpochAuthPQKey, pq: deployment.epochPQ,
	}
	driverConfig.AdmissionVerifier = &orderedAdmissionVerifier{events: &relayEventLog{}}
	driverConfig.PolicySelector = &orderedPolicySelector{events: &relayEventLog{}, accept: relayTestPolicyAccept(client.config, deployment.deployment)}
	driver, err := NewRelayDriver(driverConfig)
	if err != nil {
		t.Fatal(err)
	}
	handshake, prelude1, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	replayedHandshake := cloneRelayTestHandshake(t, handshake)
	capsule := newRelayClientCapsuleFixture(t, now, deployment.deployment, client, prelude1)
	_, firstApplication, _, err := handshake.Finish(context.Background(), capsule.record, uint64(now.Unix()))
	if err != nil || firstApplication == nil {
		t.Fatalf("first token redemption failed: %v", err)
	}
	_ = firstApplication.Close()

	redemptionHash, err := admission.TokenRedemptionHash(capsule.capsule1.AdmissionProof)
	if err != nil {
		t.Fatal(err)
	}
	replayed := cloneRelayTestCapsule1(t, capsule.capsule1)
	replayed.ReplayProof.ClientReplayNonce = bytes.Repeat([]byte{0x62}, 32)
	replayed.ReplayProof.ReplayContextHash, err = admission.ReplayContextHash(redemptionHash, replayed.ReplayProof, capsule.routeInstanceID, 0, client.binding.HandshakeBindingContext, replayed.AdmissionProof.RedemptionContextHash)
	if err != nil {
		t.Fatal(err)
	}
	replayedRecord := resealRelayTestCapsule(t, capsule, true, func(value *protocol.CoverCapsule1Plain) {
		*value = replayed
	})
	if _, application, _, err := replayedHandshake.Finish(context.Background(), replayedRecord, uint64(now.Unix())); err == nil || application != nil {
		t.Fatal("relay accepted a spent token with a fresh replay nonce")
	}
}

func TestRelayHandshakeFinishIsSingleUseUnderConcurrency(t *testing.T) {
	now := time.Now()
	deployment := newTestVerifiedDeploymentFixture(t, now)
	client := newRelayClientPreludeFixture(t, now, deployment)
	events := &relayEventLog{}
	driverConfig := validRelayDriverConfigWithDeployment(t, deployment.deployment)
	driverConfig.HintResolver = &orderedHintResolver{events: events, expected: client.config.AccessHint, credential: client.config.AccessHint}
	driverConfig.HintSpentCache = &orderedRelayReplayCache{events: events, event: "hint", inner: admission.NewMemoryReplayCache()}
	driverConfig.TokenSpentCache = &orderedRelayReplayCache{events: events, event: "token", inner: admission.NewMemoryReplayCache()}
	driverConfig.BootstrapCache = &orderedRelayReplayCache{events: events, event: "bootstrap", inner: admission.NewMemoryReplayCache()}
	driverConfig.ClassicalSigner = &orderedRelaySigner{events: events, event: "classical", publicKey: deployment.deployment.Descriptor().EpochAuthClassicalKey, classical: deployment.epochClassical}
	driverConfig.PQSigner = &orderedRelaySigner{events: events, event: "pq", publicKey: deployment.deployment.Descriptor().EpochAuthPQKey, pq: deployment.epochPQ}
	verifier := &orderedAdmissionVerifier{events: events}
	driverConfig.AdmissionVerifier = verifier
	driverConfig.PolicySelector = &orderedPolicySelector{events: events, accept: relayTestPolicyAccept(client.config, deployment.deployment)}
	driver, err := NewRelayDriver(driverConfig)
	if err != nil {
		t.Fatal(err)
	}
	handshake, prelude1, err := driver.Begin(context.Background(), client.binding, client.prelude0, uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	capsule := newRelayClientCapsuleFixture(t, now, deployment.deployment, client, prelude1)
	events.reset()

	type result struct {
		application *session.Application
		err         error
	}
	start := make(chan struct{})
	results := make(chan result, 16)
	var callers sync.WaitGroup
	for range 16 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			_, application, _, err := handshake.Finish(context.Background(), capsule.record, uint64(now.Unix()))
			results <- result{application: application, err: err}
		}()
	}
	close(start)
	callers.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
			if result.application == nil {
				t.Fatal("successful Finish returned nil application")
			}
			_ = result.application.Close()
		} else if result.application != nil {
			t.Fatal("failed Finish returned application")
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent Finish successes = %d, want 1", successes)
	}
	if verifier.calls != 1 {
		t.Fatalf("admission verifier calls = %d, want 1", verifier.calls)
	}
}

func cloneRelayTestCapsule1(t *testing.T, input protocol.CoverCapsule1Plain) protocol.CoverCapsule1Plain {
	t.Helper()
	cloned, err := cloneCoverCapsule1(input)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func cloneRelayTestHandshake(t *testing.T, input *RelayHandshake) *RelayHandshake {
	t.Helper()
	return &RelayHandshake{
		driver:                input.driver,
		suite:                 input.suite,
		handshakeBinding:      append([]byte(nil), input.handshakeBinding...),
		hintIssuerID:          append([]byte(nil), input.hintIssuerID...),
		relayBucketID:         append([]byte(nil), input.relayBucketID...),
		preludeTranscriptHash: append([]byte(nil), input.preludeTranscriptHash...),
		secrets:               cloneRelayTestHandshakeSecrets(input.secrets),
		routeInstanceID:       input.routeInstanceID,
	}
}

func cloneRelayTestHandshakeSecrets(input HandshakeSecrets) HandshakeSecrets {
	return HandshakeSecrets{
		EarlySecret: append([]byte(nil), input.EarlySecret...), DerivedSecret: append([]byte(nil), input.DerivedSecret...),
		HandshakeSecret: append([]byte(nil), input.HandshakeSecret...), ClientHandshakeSecret: append([]byte(nil), input.ClientHandshakeSecret...),
		ServerHandshakeSecret: append([]byte(nil), input.ServerHandshakeSecret...), ClientFinishedKey: append([]byte(nil), input.ClientFinishedKey...),
		ServerFinishedKey: append([]byte(nil), input.ServerFinishedKey...), ClientHSKey: append([]byte(nil), input.ClientHSKey...),
		ClientHSIV: append([]byte(nil), input.ClientHSIV...), ServerHSKey: append([]byte(nil), input.ServerHSKey...),
		ServerHSIV: append([]byte(nil), input.ServerHSIV...),
	}
}

func resealRelayTestCapsule(t *testing.T, fixture relayClientCapsuleFixture, recomputeFinished bool, mutate func(*protocol.CoverCapsule1Plain)) []byte {
	t.Helper()
	capsule := cloneRelayTestCapsule1(t, fixture.capsule1)
	mutate(&capsule)
	if recomputeFinished {
		capsule.ClientFinished = nil
		finished, err := ComputeClientFinished(fixture.control.SelectedSuite, fixture.secrets.ClientFinishedKey, fixture.preludeHash, capsule)
		if err != nil {
			t.Fatal(err)
		}
		capsule.ClientFinished = finished
	}
	record, err := SealCoverCapsule1(fixture.control, capsule)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

type relayClientPreludeFixture struct {
	binding    FirstHopBinding
	prelude0   protocol.CoverPrelude0
	config     ClientDriverConfig
	clientECDH *auroracrypto.ECDHPrivateKey
	clientKEM  auroracrypto.MLKEMDecapsulationKey
}

func newRelayClientPreludeFixture(t *testing.T, now time.Time, deployment testVerifiedDeploymentFixture) relayClientPreludeFixture {
	t.Helper()
	config := validClientDriverConfig(t, now)
	config.Deployment = deployment.deployment
	coverRandom := make([]byte, 32)
	clientNonce := make([]byte, 32)
	if _, err := rand.Read(coverRandom); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(clientNonce); err != nil {
		t.Fatal(err)
	}
	binding, err := clientTestBinding(deployment.deployment, coverRandom)
	if err != nil {
		t.Fatal(err)
	}
	clientECDH, err := auroracrypto.GenerateECDHForSuite(deployment.deployment.Suite())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientECDH.Destroy)
	clientMLKEM, err := auroracrypto.GenerateMLKEMForSuite(deployment.deployment.Suite())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clientMLKEM.Destroy)
	accessHint, err := admission.ComputeAccessHint(config.AccessHint, binding.HandshakeBindingContext, clientNonce)
	if err != nil {
		t.Fatal(err)
	}
	template := deployment.deployment.Template()
	requestClass := deployment.deployment.RequestClass()
	prelude0 := protocol.CoverPrelude0{
		MsgType:                     registry.MsgCoverPrelude0,
		Version:                     registry.Version20,
		SuiteOffers:                 []uint64{deployment.deployment.Suite()},
		ClientNonce:                 clientNonce,
		ClientClassicalEphPub:       clientECDH.PublicKeyBytes(),
		ClientMLKEMEncapsulationKey: clientMLKEM.EncapsulationKeyBytes(),
		RelayDescriptorHash:         deployment.deployment.DescriptorHash(),
		CoverTemplateHash:           deployment.deployment.TemplateHash(),
		RequestClassID:              requestClass.ClassID,
		HintIssuerID:                append([]byte(nil), config.AccessHint.HintIssuerID...),
		RelayBucketID:               append([]byte(nil), config.AccessHint.RelayBucketID...),
		HintEpochID:                 config.AccessHint.HintEpochID,
		HintSelector:                append([]byte(nil), config.AccessHint.HintSelector...),
		AccessHint:                  accessHint,
		ClientCoverRandom:           coverRandom,
	}
	prelude0, encoded, err := padCoverPrelude0(rand.Reader, prelude0, template.PreludeEnvelope.MinRequestBodySize, template.PreludeEnvelope.MaxRequestBodySize)
	if err != nil {
		t.Fatal(err)
	}
	zeroBindingBytes(encoded)
	return relayClientPreludeFixture{binding: binding, prelude0: prelude0, config: config, clientECDH: clientECDH, clientKEM: clientMLKEM}
}

type relayClientCapsuleFixture struct {
	record          []byte
	capsule1        protocol.CoverCapsule1Plain
	control         ControlCapsuleContext
	secrets         HandshakeSecrets
	preludeHash     []byte
	routeInstanceID uint64
}

func newRelayClientCapsuleFixture(t *testing.T, now time.Time, deployment interface {
	Suite() uint64
	Descriptor() protocol.RelayDescriptor
	DescriptorHash() []byte
	TemplateHash() []byte
}, client relayClientPreludeFixture, prelude1 protocol.CoverPrelude1) relayClientCapsuleFixture {
	t.Helper()
	preludeHash, err := PreludeTranscriptHash(deployment.Suite(), client.binding.CoverStreamBinding, client.prelude0, prelude1)
	if err != nil {
		t.Fatal(err)
	}
	sharedClassical, err := client.clientECDH.SharedSecret(prelude1.ServerClassicalEphPub)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBindingBytes(sharedClassical)
	sharedPQ, err := client.clientKEM.Decapsulate(prelude1.ServerMLKEMCiphertextToClient)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBindingBytes(sharedPQ)
	secrets, err := DeriveHandshakeSecrets(deployment.Suite(), sharedPQ, sharedClassical, client.binding.HandshakeBindingContext, preludeHash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { zeroHandshakeSecrets(&secrets) })
	routeInstanceID, err := auroracrypto.FirstHopRouteInstanceID(deployment.Suite(), preludeHash, deployment.DescriptorHash(), client.binding.HandshakeBindingContext, client.prelude0.ClientNonce)
	if err != nil {
		t.Fatal(err)
	}
	admissionContextHash, err := admission.AdmissionContextHash(admission.ContextInput{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   deployment.Suite(),
		RelayDescriptorHash:             deployment.DescriptorHash(),
		CoverTemplateHash:               deployment.TemplateHash(),
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         client.binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: preludeHash,
		PolicyOffer:                     client.config.PolicyOffer,
		ClientTransportHints:            client.config.TransportHints,
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := deployment.Descriptor()
	provider := &productionClientProofProvider{
		issuerID:      append([]byte(nil), client.config.AccessHint.HintIssuerID...),
		relayBucketID: append([]byte(nil), client.config.AccessHint.RelayBucketID...),
	}
	proof, replay, err := provider.BuildProofs(context.Background(), ClientProofRequest{
		AdmissionContextHash:    admissionContextHash,
		HandshakeBindingContext: client.binding.HandshakeBindingContext,
		RouteInstanceID:         routeInstanceID,
		HopIndex:                0,
		ReplayEpochID:           descriptor.ReplayEpochID,
		ReplayEpochValidUntil:   descriptor.ReplayEpochValidUntilUnix,
		ReplayWindowID:          descriptor.ReplayWindowID,
	})
	if err != nil {
		t.Fatal(err)
	}
	capsule1 := protocol.CoverCapsule1Plain{
		MsgType:              registry.MsgCoverCapsule1,
		RouteInstanceID:      routeInstanceID,
		AdmissionProof:       proof,
		ReplayProof:          replay,
		PolicyOffer:          client.config.PolicyOffer,
		ClientTransportHints: client.config.TransportHints,
	}
	control := ControlCapsuleContext{
		SelectedVersion:                 registry.Version20,
		SelectedSuite:                   deployment.Suite(),
		RouteInstanceID:                 routeInstanceID,
		HopIndex:                        0,
		HandshakeBindingContext:         client.binding.HandshakeBindingContext,
		PreludeTranscriptHashForThisHop: preludeHash,
		ClientHSKey:                     secrets.ClientHSKey,
		ClientHSIV:                      secrets.ClientHSIV,
		ServerHSKey:                     secrets.ServerHSKey,
		ServerHSIV:                      secrets.ServerHSIV,
	}
	template := client.config.Deployment.Template()
	finalize := func(value protocol.CoverCapsule1Plain) (protocol.CoverCapsule1Plain, []byte, error) {
		value.ClientFinished = nil
		finished, err := ComputeClientFinished(deployment.Suite(), secrets.ClientFinishedKey, preludeHash, value)
		if err != nil {
			return protocol.CoverCapsule1Plain{}, nil, err
		}
		value.ClientFinished = finished
		sealed, err := SealCoverCapsule1(control, value)
		return value, sealed, err
	}
	capsule1, record, err := padCoverCapsule1(rand.Reader, capsule1, template.CapsuleEnvelope.MinCapsuleBodySize, template.CapsuleEnvelope.MaxCapsuleBodySize, finalize)
	if err != nil {
		t.Fatal(err)
	}
	return relayClientCapsuleFixture{record: record, capsule1: capsule1, control: control, secrets: secrets, preludeHash: preludeHash, routeInstanceID: routeInstanceID}
}

func relayTestPolicyAccept(config ClientDriverConfig, deployment interface {
	Suite() uint64
	Method() uint64
}) protocol.PolicyAccept {
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             deployment.Suite(),
		SelectedMethod:            deployment.Method(),
		SelectedPolicy:            config.PolicyOffer.RequestedPolicyID,
		SelectedRouteModeID:       config.PolicyOffer.RequestedRouteModeID,
		SelectedShape:             config.PolicyOffer.RequestedShapeID,
		SelectedTunnelPersonality: config.PolicyOffer.TunnelPersonalityOffers[0],
	}
}

type relayEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *relayEventLog) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *relayEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func (l *relayEventLog) reset() {
	l.mu.Lock()
	l.events = nil
	l.mu.Unlock()
}

type orderedHintResolver struct {
	events     *relayEventLog
	expected   admission.AccessHintCredential
	credential admission.AccessHintCredential
	calls      int
	err        error
}

func (r *orderedHintResolver) ResolveAccessHint(_ context.Context, issuerID, relayBucketID []byte, hintEpochID uint64, hintSelector []byte) (admission.AccessHintCredential, error) {
	r.calls++
	r.events.add("resolve exact tuple")
	want := r.expected
	if len(want.HintIssuerID) == 0 {
		want = r.credential
	}
	if !bytes.Equal(issuerID, want.HintIssuerID) || !bytes.Equal(relayBucketID, want.RelayBucketID) || hintEpochID != want.HintEpochID || !bytes.Equal(hintSelector, want.HintSelector) {
		return admission.AccessHintCredential{}, fmt.Errorf("test resolver received wrong tuple")
	}
	if r.err != nil {
		return admission.AccessHintCredential{}, r.err
	}
	return cloneAccessHint(r.credential), nil
}

type orderedRelayReplayCache struct {
	events         *relayEventLog
	event          string
	inner          admission.ReplayCache
	inserts        int
	err            error
	forceDuplicate bool
}

func (*orderedRelayReplayCache) Durable() bool { return true }

func (c *orderedRelayReplayCache) InsertIfAbsent(key []byte) (bool, error) {
	c.inserts++
	if c.events != nil {
		c.events.add(c.event)
	}
	if c.err != nil {
		return false, c.err
	}
	if c.forceDuplicate {
		return false, nil
	}
	return c.inner.InsertIfAbsent(key)
}

func (c *orderedRelayReplayCache) Has(key []byte) bool { return c.inner.Has(key) }

type orderedRelaySigner struct {
	events    *relayEventLog
	event     string
	publicKey protocol.PublicKeyRecord
	classical *ecdsa.PrivateKey
	pq        *mldsa65.PrivateKey
	err       error
}

func (s *orderedRelaySigner) PublicKey() protocol.PublicKeyRecord { return s.publicKey }

func (s *orderedRelaySigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, context.Canceled
	}
	s.events.add(s.event)
	if s.err != nil {
		return nil, s.err
	}
	if s.classical != nil {
		return ecdsa.SignASN1(rand.Reader, s.classical, transcript)
	}
	if s.pq != nil {
		signature := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(s.pq, transcript, nil, false, signature); err != nil {
			return nil, err
		}
		return signature, nil
	}
	return nil, fmt.Errorf("test signer has no private key")
}

type orderedAdmissionVerifier struct {
	events *relayEventLog
	err    error
	calls  int
	mutate func(*protocol.AdmissionProof)
}

func (v *orderedAdmissionVerifier) VerifyAdmission(ctx context.Context, proof protocol.AdmissionProof, _ uint64) error {
	v.calls++
	v.events.add("verify admission")
	if v.mutate != nil {
		v.mutate(&proof)
	}
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	return v.err
}

type orderedPolicySelector struct {
	events *relayEventLog
	accept protocol.PolicyAccept
	err    error
	calls  int
	mutate func(*protocol.PolicyOffer, *protocol.ClientTransportHints)
}

func (s *orderedPolicySelector) SelectPolicy(ctx context.Context, offer protocol.PolicyOffer, hints protocol.ClientTransportHints) (protocol.PolicyAccept, error) {
	s.calls++
	s.events.add("select policy")
	if s.mutate != nil {
		s.mutate(&offer, &hints)
	}
	if ctx == nil || ctx.Err() != nil {
		return protocol.PolicyAccept{}, context.Canceled
	}
	return s.accept, s.err
}
