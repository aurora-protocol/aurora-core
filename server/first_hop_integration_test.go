package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/evidence"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/relay"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/trust"
	"github.com/aurora-protocol/aurora-core/wire"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestLiveFirstHopRandomizedApplicationRoundTrip(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	clientDriver := fixture.newClientDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientFrames := make(chan []byte, 1)
	connectContext, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelConnect()
	established, err := clientDriver.Connect(connectContext, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	relayApplication := <-harness.relayApplications
	pumpContext, cancelPump := context.WithCancel(context.Background())
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(_ context.Context, block protocol.FrameBlock) error {
				clientFrames <- append([]byte(nil), block.Frames[0].Payload...)
				return nil
			},
			1<<20,
		)
	}()
	t.Cleanup(func() {
		cancelPump()
		_ = established.Close()
		select {
		case err := <-pumpResult:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, session.ErrClosed) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("live client packet pump stopped unexpectedly: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("live client packet pump did not stop")
		}
	})

	clientPayload := randomLiveFirstHopBytes(t, 96)
	if err := established.Application.QueueFrames(connectContext, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: clientPayload}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-harness.serverFrames:
		if !bytes.Equal(received, clientPayload) {
			t.Fatal("relay received different application payload")
		}
	case <-connectContext.Done():
		t.Fatal("client application payload did not reach relay")
	}
	serverPayload := randomLiveFirstHopBytes(t, 97)
	if err := relayApplication.QueueFrames(connectContext, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: serverPayload}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-clientFrames:
		if !bytes.Equal(received, serverPayload) {
			t.Fatal("client received different application payload")
		}
	case <-connectContext.Done():
		t.Fatal("relay application payload did not reach client")
	}

	if err := established.Application.InitiateKeyUpdate(connectContext, 1); err != nil {
		t.Fatalf("initiate client key update: %v", err)
	}
	clientUpdatedPayload := randomLiveFirstHopBytes(t, 98)
	if err := queueLiveFirstHopFrame(connectContext, established.Application, clientUpdatedPayload); err != nil {
		t.Fatalf("queue post-update client payload: %v", err)
	}
	select {
	case received := <-harness.serverFrames:
		if !bytes.Equal(received, clientUpdatedPayload) {
			t.Fatal("relay received different post-update application payload")
		}
	case <-connectContext.Done():
		t.Fatal("post-update client application payload did not reach relay")
	}

	if err := relayApplication.InitiateKeyUpdate(connectContext, 2); err != nil {
		t.Fatalf("initiate relay key update: %v", err)
	}
	relayUpdatedPayload := randomLiveFirstHopBytes(t, 99)
	if err := queueLiveFirstHopFrame(connectContext, relayApplication, relayUpdatedPayload); err != nil {
		t.Fatalf("queue post-update relay payload: %v", err)
	}
	select {
	case received := <-clientFrames:
		if !bytes.Equal(received, relayUpdatedPayload) {
			t.Fatal("client received different post-update application payload")
		}
	case <-connectContext.Done():
		t.Fatal("post-update relay application payload did not reach client")
	}
	for name, stats := range map[string]session.Stats{
		"client": established.Application.Stats(),
		"relay":  relayApplication.Stats(),
	} {
		if stats.PeakQueuedPackets == 0 || stats.PeakQueuedPackets > 32 || stats.PeakQueuedBytes == 0 || stats.PeakQueuedBytes > 256<<10 {
			t.Fatalf("%s application queue stats escaped configured bounds: %+v", name, stats)
		}
	}
}

func TestLiveFirstHopEvidenceReport(t *testing.T) {
	result, err := evidence.RunFirstHop(context.Background(), liveFirstHopEvidenceHarness{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || !result.TLS13 || !result.HTTP2 || !result.FreshConnection || !result.PreludeAuthenticated || !result.AdmissionSpent || !result.ReplayRejected || !result.ApplicationRoundTrip || !result.KeyUpdateRoundTrip || len(result.Findings) != 0 {
		t.Fatalf("incomplete live first-hop evidence: %+v", result)
	}
	if result.HandshakeDuration <= 0 || result.PeakQueuedPackets <= 0 || result.PeakQueuedPackets > 64 || result.PeakQueuedBytes <= 0 || result.PeakQueuedBytes > 512<<10 {
		t.Fatalf("invalid live first-hop evidence metrics: %+v", result)
	}
}

type liveFirstHopEvidenceHarness struct {
	t *testing.T
}

func (h liveFirstHopEvidenceHarness) RunFirstHop(ctx context.Context) (evidence.FirstHopObservation, error) {
	if h.t == nil {
		return evidence.FirstHopObservation{}, errors.New("live first-hop evidence test is missing testing state")
	}
	fixture := newLiveFirstHopFixture(h.t, time.Now())
	relayDriver := fixture.newRelayDriver(h.t)
	coverOrigin := &recordingFirstHopCoverOrigin{}
	harness := startLiveFirstHopHarness(h.t, fixture, relayDriver, coverOrigin)
	clientDriver := fixture.newClientDriver(h.t)
	observation := evidence.FirstHopObservation{}
	handshakeStarted := time.Now()
	established, err := clientDriver.Connect(ctx, harness.opener)
	observation.HandshakeDuration = time.Since(handshakeStarted)
	if err != nil {
		return observation, err
	}
	observation.TLS13 = true
	observation.HTTP2 = true
	observation.FreshConnection = true
	observation.PreludeAuthenticated = true

	var relayApplication *session.Application
	select {
	case relayApplication = <-harness.relayApplications:
		observation.AdmissionSpent = true
	case <-ctx.Done():
		_ = established.Close()
		return observation, ctx.Err()
	}
	clientFrames := make(chan []byte, 4)
	pumpContext, cancelPump := context.WithCancel(ctx)
	pumpResult := make(chan error, 1)
	go func() {
		pumpResult <- transport.RunPacketDuplex(
			pumpContext,
			established.ReadCarrier,
			established.WriteCarrier,
			established.Application,
			func(_ context.Context, block protocol.FrameBlock) error {
				clientFrames <- append([]byte(nil), block.Frames[0].Payload...)
				return nil
			},
			1<<20,
		)
	}()
	pumpStopped := false
	stopPump := func() error {
		if pumpStopped {
			return nil
		}
		pumpStopped = true
		cancelPump()
		_ = established.Close()
		_ = relayApplication.Close()
		select {
		case pumpErr := <-pumpResult:
			if pumpErr != nil && !errors.Is(pumpErr, context.Canceled) && !errors.Is(pumpErr, session.ErrClosed) && !errors.Is(pumpErr, net.ErrClosed) {
				return pumpErr
			}
			return nil
		case <-time.After(time.Second):
			return errors.New("live first-hop evidence packet pump did not stop")
		}
	}
	defer func() { _ = stopPump() }()

	clientPayload := randomLiveFirstHopBytes(h.t, 128)
	if err := queueLiveFirstHopFrame(ctx, established.Application, clientPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, harness.serverFrames, clientPayload); err != nil {
		return observation, err
	}
	relayPayload := randomLiveFirstHopBytes(h.t, 129)
	if err := queueLiveFirstHopFrame(ctx, relayApplication, relayPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, clientFrames, relayPayload); err != nil {
		return observation, err
	}
	observation.ApplicationRoundTrip = true

	if err := established.Application.InitiateKeyUpdate(ctx, 1); err != nil {
		return observation, err
	}
	clientUpdatedPayload := randomLiveFirstHopBytes(h.t, 130)
	if err := queueLiveFirstHopFrame(ctx, established.Application, clientUpdatedPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, harness.serverFrames, clientUpdatedPayload); err != nil {
		return observation, err
	}
	if err := relayApplication.InitiateKeyUpdate(ctx, 2); err != nil {
		return observation, err
	}
	relayUpdatedPayload := randomLiveFirstHopBytes(h.t, 131)
	if err := queueLiveFirstHopFrame(ctx, relayApplication, relayUpdatedPayload); err != nil {
		return observation, err
	}
	if err := awaitLiveFirstHopPayload(ctx, clientFrames, relayUpdatedPayload); err != nil {
		return observation, err
	}
	observation.KeyUpdateRoundTrip = true
	clientStats := established.Application.Stats()
	relayStats := relayApplication.Stats()
	observation.PeakQueuedPackets = clientStats.PeakQueuedPackets + relayStats.PeakQueuedPackets
	observation.PeakQueuedBytes = clientStats.PeakQueuedBytes + relayStats.PeakQueuedBytes
	if err := stopPump(); err != nil {
		return observation, err
	}

	replayed, replayErr := fixture.newClientDriver(h.t).Connect(ctx, harness.opener)
	if replayed != nil {
		_ = replayed.Close()
		return observation, errors.New("live first-hop evidence replay created a client session")
	}
	if replayErr == nil {
		return observation, errors.New("live first-hop evidence replay was accepted")
	}
	method, body := coverOrigin.snapshot()
	if method != http.MethodGet || len(body) != 0 {
		return observation, errors.New("live first-hop evidence replay did not use sanitized cover")
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		return observation, errors.New("live first-hop evidence replay created a relay session")
	default:
	}
	observation.ReplayRejected = true
	return observation, nil
}

func awaitLiveFirstHopPayload(ctx context.Context, received <-chan []byte, expected []byte) error {
	select {
	case payload := <-received:
		if !bytes.Equal(payload, expected) {
			return errors.New("live first-hop evidence payload mismatch")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func queueLiveFirstHopFrame(ctx context.Context, application *session.Application, payload []byte) error {
	for {
		err := application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: payload}}})
		if err == nil || !errors.Is(err, session.ErrBackpressure) {
			return err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func TestLiveFirstHopRelayFailureBoundaries(t *testing.T) {
	tests := []struct {
		name                string
		mutateRecord        func(int, []byte) ([]byte, error)
		mutateProofProvider func(*liveFirstHopProofProvider)
		relayOptions        func() liveFirstHopRelayOptions
		preHeaderCover      bool
	}{
		{
			name: "wrong request class",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.RequestClassID++
			}),
			preHeaderCover: true,
		},
		{
			name: "wrong live binding",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.ClientCoverRandom[0] ^= 0xff
			}),
			preHeaderCover: true,
		},
		{
			name: "malformed hybrid share",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.ClientClassicalEphPub[0] = 0x05
			}),
			preHeaderCover: true,
		},
		{
			name: "bad access hint",
			mutateRecord: mutateLiveFirstHopPrelude(func(prelude *protocol.CoverPrelude0) {
				prelude.AccessHint[0] ^= 0xff
			}),
			preHeaderCover: true,
		},
		{
			name: "duplicate access hint",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{hintCache: &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache(), duplicate: true}}
			},
			preHeaderCover: true,
		},
		{
			name: "access hint store error",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{hintCache: &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache(), err: errors.New("store unavailable")}}
			},
			preHeaderCover: true,
		},
		{
			name: "malformed Capsule1",
			mutateRecord: func(index int, record []byte) ([]byte, error) {
				if index == 1 {
					record[0] ^= 0xff
				}
				return record, nil
			},
		},
		{
			name: "admission verifier error",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{admissionVerifier: liveFirstHopAdmissionVerifier{err: errors.New("verification unavailable")}}
			},
		},
		{
			name: "invalid admission authenticator",
			mutateProofProvider: func(provider *liveFirstHopProofProvider) {
				provider.tamperAuthenticator = true
			},
		},
		{
			name: "replayed token",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{tokenCache: &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache(), duplicate: true}}
			},
		},
		{
			name: "policy failure",
			relayOptions: func() liveFirstHopRelayOptions {
				return liveFirstHopRelayOptions{policySelector: liveFirstHopPolicySelector{err: errors.New("policy unavailable")}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			options := liveFirstHopRelayOptions{}
			if test.relayOptions != nil {
				options = test.relayOptions()
			}
			relayDriver := fixture.newRelayDriver(t, options)
			clientDriver, proofProvider := fixture.newClientDriverWithProofProvider(t)
			if test.mutateProofProvider != nil {
				test.mutateProofProvider(proofProvider)
			}
			coverOrigin := &recordingFirstHopCoverOrigin{}
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
			opener := harness.opener
			if test.mutateRecord != nil {
				opener = &liveFirstHopMutatingOpener{base: opener, mutate: test.mutateRecord}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			established, err := clientDriver.Connect(ctx, opener)
			if err == nil || established != nil {
				if established != nil {
					_ = established.Close()
				}
				t.Fatal("live first-hop failure established an application session")
			}
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
				t.Fatal("relay created an application on failed live handshake")
			default:
			}
			method, body := coverOrigin.snapshot()
			if test.preHeaderCover {
				if method != http.MethodGet || len(body) != 0 {
					t.Fatalf("pre-header failure was not sanitized cover: method=%s body=%x", method, body)
				}
			} else if method != "" || len(body) != 0 {
				t.Fatalf("post-header failure invoked cover origin: method=%s body=%x", method, body)
			}
		})
	}
}

func TestLiveFirstHopRejectsMismatchedClientBindingMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*handshake.HTTP2BindingMetadata)
	}{
		{
			name: "authority hash",
			mutate: func(metadata *handshake.HTTP2BindingMetadata) {
				metadata.NormalizedAuthorityHash[0] ^= 0xff
			},
		},
		{
			name: "path template ID",
			mutate: func(metadata *handshake.HTTP2BindingMetadata) {
				metadata.PathTemplateID[0] ^= 0xff
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			relayDriver := fixture.newRelayDriver(t)
			coverOrigin := &recordingFirstHopCoverOrigin{}
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
			opener := &liveFirstHopBindingMetadataOpener{base: harness.opener, metadata: harness.bindingMetadata, mutate: test.mutate}
			clientDriver := fixture.newClientDriver(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if established, err := clientDriver.Connect(ctx, opener); err == nil || established != nil {
				if established != nil {
					_ = established.Close()
				}
				t.Fatal("mismatched live binding metadata established a session")
			}
			method, body := coverOrigin.snapshot()
			if method != "" || len(body) != 0 {
				t.Fatalf("locally rejected binding mismatch reached cover origin: method=%s body=%x", method, body)
			}
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
				t.Fatal("binding mismatch created a relay application")
			default:
			}
		})
	}
}

func TestLiveFirstHopRejectsBadPreludeSignatureBeforeProofs(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientDriver, proofProvider := fixture.newClientDriverWithProofProvider(t)
	opener := &liveFirstHopReadMutatingOpener{base: harness.opener, mutate: mutateLiveFirstHopPrelude1Signature}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if established, err := clientDriver.Connect(ctx, opener); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("bad Prelude1 signature established a session")
	}
	if calls := proofProvider.calls.Load(); calls != 0 {
		t.Fatalf("proof provider called %d times before Prelude1 authentication", calls)
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("bad Prelude1 signature created a relay application")
	default:
	}
}

func TestLiveFirstHopRejectsCorruptedCapsule2(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	clientDriver, proofProvider := fixture.newClientDriverWithProofProvider(t)
	opener := &liveFirstHopReadMutatingOpener{
		base: harness.opener,
		mutate: func(index int, record []byte) ([]byte, error) {
			if index == 1 {
				record[len(record)-1] ^= 0xff
			}
			return record, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if established, err := clientDriver.Connect(ctx, opener); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("corrupted Capsule2 established a client session")
	}
	if calls := proofProvider.calls.Load(); calls != 1 {
		t.Fatalf("proof provider calls = %d, want 1", calls)
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
	case <-ctx.Done():
		t.Fatal("relay did not reach committed admission before Capsule2 corruption")
	}
}

func TestLiveFirstHopRejectsSpentAccessHintOnFreshConnection(t *testing.T) {
	fixture := newLiveFirstHopFixture(t, time.Now())
	relayDriver := fixture.newRelayDriver(t)
	coverOrigin := &recordingFirstHopCoverOrigin{}
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, coverOrigin)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	firstApplication := <-harness.relayApplications
	_ = firstApplication.Close()

	second, err := fixture.newClientDriver(t).Connect(ctx, harness.opener)
	if err == nil || second != nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("spent access hint established a second session")
	}
	method, body := coverOrigin.snapshot()
	if method != http.MethodGet || len(body) != 0 {
		t.Fatalf("spent access hint was not sanitized cover: method=%s body=%x", method, body)
	}
	select {
	case application := <-harness.relayApplications:
		_ = application.Close()
		t.Fatal("spent access hint created a second relay application")
	default:
	}
}

func TestLiveFirstHopConcurrentIndependentConnections(t *testing.T) {
	const connectionCount = 32
	fixture := newLiveFirstHopFixture(t, time.Now())
	credentials := make([]admission.AccessHintCredential, connectionCount)
	clients := make([]*handshake.ClientDriver, connectionCount)
	for i := range credentials {
		credential := fixture.accessHint
		credential.HintIssuerID = append([]byte(nil), fixture.accessHint.HintIssuerID...)
		credential.RelayBucketID = append([]byte(nil), fixture.accessHint.RelayBucketID...)
		credential.HintSelector = randomLiveFirstHopBytes(t, 16)
		credential.HintSecret = randomLiveFirstHopBytes(t, 32)
		credentials[i] = credential
		clientFixture := fixture
		clientFixture.accessHint = credential
		clients[i] = clientFixture.newClientDriver(t)
	}
	relayDriver := fixture.newRelayDriver(t, liveFirstHopRelayOptions{
		hintResolver: liveFirstHopMultiHintResolver{credentials: credentials},
	})
	harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, connectionCount)
	var wait sync.WaitGroup
	for _, clientDriver := range clients {
		wait.Add(1)
		go func(driver *handshake.ClientDriver) {
			defer wait.Done()
			<-start
			established, err := driver.Connect(ctx, harness.opener)
			if established != nil {
				_ = established.Close()
			}
			results <- err
		}(clientDriver)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("independent live connection failed: %v", err)
		}
	}
	for i := 0; i < connectionCount; i++ {
		select {
		case application := <-harness.relayApplications:
			_ = application.Close()
		case <-ctx.Done():
			t.Fatalf("received %d of %d relay applications", i, connectionCount)
		}
	}
	if got := harness.connections.Load(); got != connectionCount {
		t.Fatalf("accepted connections = %d, want %d", got, connectionCount)
	}
}

func TestLiveFirstHopDisconnectsAtHandshakeBoundaries(t *testing.T) {
	tests := []struct {
		name                 string
		closeOnOpen          bool
		closeAfterWrite      int
		closeAfterRead       int
		mayCreateApplication bool
	}{
		{name: "after TLS open", closeOnOpen: true, closeAfterWrite: -1, closeAfterRead: -1},
		{name: "after Prelude0", closeAfterWrite: 0, closeAfterRead: -1},
		{name: "after Prelude1", closeAfterWrite: -1, closeAfterRead: 0},
		{name: "after Capsule1", closeAfterWrite: 1, closeAfterRead: -1, mayCreateApplication: true},
		{name: "after Capsule2", closeAfterWrite: -1, closeAfterRead: 1, mayCreateApplication: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLiveFirstHopFixture(t, time.Now())
			relayDriver := fixture.newRelayDriver(t)
			harness := startLiveFirstHopHarness(t, fixture, relayDriver, nil)
			opener := &liveFirstHopDisconnectingOpener{
				base:            harness.opener,
				closeOnOpen:     test.closeOnOpen,
				closeAfterWrite: test.closeAfterWrite,
				closeAfterRead:  test.closeAfterRead,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			established, err := fixture.newClientDriver(t).Connect(ctx, opener)
			if established != nil {
				_ = established.Close()
			}
			if err == nil || established != nil {
				t.Fatal("disconnected live handshake established a client session")
			}
			if test.mayCreateApplication {
				select {
				case application := <-harness.relayApplications:
					_ = application.Close()
				case <-time.After(100 * time.Millisecond):
				}
			} else {
				select {
				case application := <-harness.relayApplications:
					_ = application.Close()
					t.Fatal("pre-Capsule1 disconnect created a relay application")
				default:
				}
			}
			if got := harness.connections.Load(); got != 1 {
				t.Fatalf("disconnect case accepted %d connections, want 1", got)
			}
		})
	}
}

func BenchmarkLiveFirstHopBootstrap(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fixture := newLiveFirstHopFixture(b, time.Now())
		relayDriver := fixture.newRelayDriver(b)
		harness := startLiveFirstHopHarness(b, fixture, relayDriver, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		established, err := fixture.newClientDriver(b).Connect(ctx, harness.opener)
		if err != nil {
			cancel()
			_ = harness.close()
			b.Fatal(err)
		}
		select {
		case application := <-harness.relayApplications:
			_ = application.Close()
		case <-ctx.Done():
			_ = established.Close()
			cancel()
			_ = harness.close()
			b.Fatal(ctx.Err())
		}
		_ = established.Close()
		cancel()
		if err := harness.close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLiveFirstHopBootstrapParallel64(b *testing.B) {
	const connectionCount = 64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fixture := newLiveFirstHopFixture(b, time.Now())
		credentials := make([]admission.AccessHintCredential, connectionCount)
		clients := make([]*handshake.ClientDriver, connectionCount)
		for j := range credentials {
			credential := cloneLiveFirstHopHintCredential(fixture.accessHint)
			credential.HintSelector = randomLiveFirstHopBytes(b, 16)
			credential.HintSecret = randomLiveFirstHopBytes(b, 32)
			credentials[j] = credential
			clientFixture := fixture
			clientFixture.accessHint = credential
			clients[j] = clientFixture.newClientDriver(b)
		}
		relayDriver := fixture.newRelayDriver(b, liveFirstHopRelayOptions{
			hintResolver: liveFirstHopMultiHintResolver{credentials: credentials},
		})
		harness := startLiveFirstHopHarness(b, fixture, relayDriver, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := make(chan struct{})
		results := make(chan error, connectionCount)
		var wait sync.WaitGroup
		for _, clientDriver := range clients {
			wait.Add(1)
			go func(driver *handshake.ClientDriver) {
				defer wait.Done()
				<-start
				established, err := driver.Connect(ctx, harness.opener)
				if established != nil {
					_ = established.Close()
				}
				results <- err
			}(clientDriver)
		}
		close(start)
		wait.Wait()
		close(results)
		var runErr error
		for err := range results {
			if err != nil && runErr == nil {
				runErr = err
			}
		}
		for j := 0; j < connectionCount && runErr == nil; j++ {
			select {
			case application := <-harness.relayApplications:
				_ = application.Close()
			case <-ctx.Done():
				runErr = ctx.Err()
			}
		}
		if got := harness.connections.Load(); runErr == nil && got != connectionCount {
			runErr = fmt.Errorf("parallel benchmark accepted %d connections, want %d", got, connectionCount)
		}
		cancel()
		if err := harness.close(); runErr == nil && err != nil {
			runErr = err
		}
		if runErr != nil {
			b.Fatal(runErr)
		}
	}
}

type liveFirstHopHarness struct {
	opener            handshake.ClientCarrierOpener
	bindingMetadata   handshake.HTTP2BindingMetadata
	serverFrames      chan []byte
	relayApplications chan *session.Application
	connections       *atomic.Int32
	close             func() error
}

func startLiveFirstHopHarness(t testing.TB, fixture liveFirstHopFixture, relayDriver *handshake.RelayDriver, coverOrigin http.Handler) liveFirstHopHarness {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := listener.Addr().String()
	const path = "/assets/upload/42"
	serverFrames := make(chan []byte, 8)
	relayApplications := make(chan *session.Application, 64)
	connections := &atomic.Int32{}
	template := fixture.deployment.Template()
	requestClass := fixture.deployment.RequestClass()
	bindingMetadata := handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), template.PublicNameHash...),
		PathTemplateID:          append([]byte(nil), requestClass.PathTemplateID...),
		RequestClassID:          requestClass.ClassID,
		MethodFamilyID:          fixture.deployment.Method(),
	}
	handler, err := NewFirstHopHandler(FirstHopOptions{
		Driver:             relayDriver,
		Authority:          authority,
		Path:               path,
		BindingMetadata:    bindingMetadata,
		CoverStatus:        http.StatusCreated,
		CoverHeader:        http.Header{"Content-Type": {"application/octet-stream"}, "X-Cover-Mode": {"ordinary"}},
		Origin:             relay.StaticOrigin{Status: http.StatusNotFound, Body: []byte("not found")},
		CoverOrigin:        coverOrigin,
		MaxRecordBodyBytes: 1 << 20,
		FrameHandler: func(_ context.Context, block protocol.FrameBlock) error {
			serverFrames <- append([]byte(nil), block.Frames[0].Payload...)
			return nil
		},
		PostHeaderTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	productionFinish := handler.finish
	handler.finish = func(ctx context.Context, state *handshake.RelayHandshake, capsule1 []byte, nowUnix uint64) ([]byte, transport.PacketEndpoint, error) {
		capsule2, endpoint, finishErr := productionFinish(ctx, state, capsule1, nowUnix)
		if finishErr == nil {
			application, ok := endpoint.(*session.Application)
			if !ok {
				return nil, nil, fmt.Errorf("live relay endpoint type %T", endpoint)
			}
			relayApplications <- application
		}
		return capsule2, endpoint, finishErr
	}
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	clientTLS := certificateServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	certificateServer.Close()
	httpServer, err := NewFirstHopHTTPServer(authority, handler, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	httpServer.ConnContext = func(ctx context.Context, connection net.Conn) context.Context {
		connections.Add(1)
		return handler.ConnContext(ctx, connection)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.Serve(tls.NewListener(listener, httpServer.TLSConfig)) }()
	var closeOnce sync.Once
	var closeErr error
	closeHarness := func() error {
		closeOnce.Do(func() {
			closeErr = httpServer.Close()
			select {
			case serveErr := <-serveResult:
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
					closeErr = errors.Join(closeErr, serveErr)
				}
			case <-time.After(time.Second):
				closeErr = errors.Join(closeErr, errors.New("live first-hop server did not stop"))
			}
		})
		return closeErr
	}
	t.Cleanup(func() {
		if err := closeHarness(); err != nil {
			t.Errorf("close live first-hop server: %v", err)
		}
	})
	built, err := transport.BuildStreamingH2CarrierRequest(transport.CarrierRequestInput{
		Plan: transport.CarrierPlan{
			Carrier: transport.Carrier{MethodID: registry.MethodWebH2Stream},
			UDPMode: transport.UDPOverStreamFallback,
		},
		Template:       template,
		RequestClassID: requestClass.ClassID,
		Scheme:         "https",
		Authority:      authority,
		Path:           path,
		Header:         http.Header{"Accept": {"application/octet-stream"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = []string{"h2"}
	clientTLS.ClientSessionCache = nil
	opener, err := transport.NewHTTP2ClientCarrierOpener(transport.HTTP2ClientCarrierConfig{
		Request:            built.Request,
		TLSConfig:          clientTLS,
		BindingMetadata:    bindingMetadata,
		ExpectedStatus:     http.StatusCreated,
		ExpectedHeader:     http.Header{"Content-Type": {"application/octet-stream"}, "X-Cover-Mode": {"ordinary"}},
		MaxRecordBodyBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return liveFirstHopHarness{opener: opener, bindingMetadata: bindingMetadata, serverFrames: serverFrames, relayApplications: relayApplications, connections: connections, close: closeHarness}
}

type liveFirstHopMutatingOpener struct {
	base   handshake.ClientCarrierOpener
	mutate func(int, []byte) ([]byte, error)
}

type liveFirstHopDisconnectingOpener struct {
	base            handshake.ClientCarrierOpener
	closeOnOpen     bool
	closeAfterWrite int
	closeAfterRead  int
}

func (o *liveFirstHopDisconnectingOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	wrapped := &liveFirstHopDisconnectingCarrier{
		BootstrapCarrier: carrier,
		closeAfterWrite:  o.closeAfterWrite,
		closeAfterRead:   o.closeAfterRead,
	}
	if o.closeOnOpen {
		_ = carrier.Close()
	}
	return wrapped, nil
}

type liveFirstHopDisconnectingCarrier struct {
	handshake.BootstrapCarrier
	mu              sync.Mutex
	writes          int
	reads           int
	closeAfterWrite int
	closeAfterRead  int
}

func (c *liveFirstHopDisconnectingCarrier) WriteRecord(record []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.writes
	c.writes++
	err := c.BootstrapCarrier.WriteRecord(record)
	if err == nil && index == c.closeAfterWrite {
		_ = c.BootstrapCarrier.Close()
	}
	return err
}

func (c *liveFirstHopDisconnectingCarrier) ReadRecord() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.reads
	c.reads++
	record, err := c.BootstrapCarrier.ReadRecord()
	if err == nil && index == c.closeAfterRead {
		_ = c.BootstrapCarrier.Close()
	}
	return record, err
}

type liveFirstHopBindingMetadataOpener struct {
	base     handshake.ClientCarrierOpener
	metadata handshake.HTTP2BindingMetadata
	mutate   func(*handshake.HTTP2BindingMetadata)
}

func (o *liveFirstHopBindingMetadataOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	metadata := handshake.HTTP2BindingMetadata{
		NormalizedAuthorityHash: append([]byte(nil), o.metadata.NormalizedAuthorityHash...),
		PathTemplateID:          append([]byte(nil), o.metadata.PathTemplateID...),
		RequestClassID:          o.metadata.RequestClassID,
		MethodFamilyID:          o.metadata.MethodFamilyID,
	}
	o.mutate(&metadata)
	binding := carrier.Binding()
	streamBinding, err := handshake.CoverStreamBinding(handshake.CoverStreamBindingInput{
		OuterExporterValue:       binding.OuterExporterValue,
		HTTPVersion:              []byte("h2"),
		ConnectionIDHash:         binding.ConnectionIDHash,
		StreamIDOrRequestID:      1,
		MethodFamilyID:           metadata.MethodFamilyID,
		NormalizedAuthorityHash:  metadata.NormalizedAuthorityHash,
		NormalizedPathTemplateID: metadata.PathTemplateID,
		RequestClassID:           metadata.RequestClassID,
		ClientCoverRandom:        coverRandom,
	})
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}
	bindingContext, err := handshake.FirstHopBindingContext(binding.OuterExporterValue, streamBinding)
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}
	binding.CoverStreamBinding = streamBinding
	binding.HandshakeBindingContext = bindingContext
	return &liveFirstHopBindingCarrier{BootstrapCarrier: carrier, binding: binding}, nil
}

type liveFirstHopBindingCarrier struct {
	handshake.BootstrapCarrier
	binding handshake.FirstHopBinding
}

func (c *liveFirstHopBindingCarrier) Binding() handshake.FirstHopBinding {
	return handshake.FirstHopBinding{
		OuterExporterValue:      append([]byte(nil), c.binding.OuterExporterValue...),
		TLSExporterChannelID:    append([]byte(nil), c.binding.TLSExporterChannelID...),
		ConnectionIDHash:        append([]byte(nil), c.binding.ConnectionIDHash...),
		CoverStreamBinding:      append([]byte(nil), c.binding.CoverStreamBinding...),
		HandshakeBindingContext: append([]byte(nil), c.binding.HandshakeBindingContext...),
	}
}

type liveFirstHopReadMutatingOpener struct {
	base   handshake.ClientCarrierOpener
	mutate func(int, []byte) ([]byte, error)
}

func (o *liveFirstHopReadMutatingOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	return &liveFirstHopReadMutatingCarrier{BootstrapCarrier: carrier, mutate: o.mutate}, nil
}

type liveFirstHopReadMutatingCarrier struct {
	handshake.BootstrapCarrier
	mu     sync.Mutex
	reads  int
	mutate func(int, []byte) ([]byte, error)
}

func (c *liveFirstHopReadMutatingCarrier) ReadRecord() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	record, err := c.BootstrapCarrier.ReadRecord()
	if err != nil {
		return nil, err
	}
	mutated, err := c.mutate(c.reads, append([]byte(nil), record...))
	c.reads++
	return mutated, err
}

func (o *liveFirstHopMutatingOpener) Open(ctx context.Context, coverRandom []byte) (handshake.BootstrapCarrier, error) {
	carrier, err := o.base.Open(ctx, coverRandom)
	if err != nil {
		return nil, err
	}
	return &liveFirstHopMutatingCarrier{BootstrapCarrier: carrier, mutate: o.mutate}, nil
}

type liveFirstHopMutatingCarrier struct {
	handshake.BootstrapCarrier
	mu     sync.Mutex
	writes int
	mutate func(int, []byte) ([]byte, error)
}

func (c *liveFirstHopMutatingCarrier) WriteRecord(record []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	owned := append([]byte(nil), record...)
	mutated, err := c.mutate(c.writes, owned)
	c.writes++
	if err != nil {
		return err
	}
	return c.BootstrapCarrier.WriteRecord(mutated)
}

func mutateLiveFirstHopPrelude(mutate func(*protocol.CoverPrelude0)) func(int, []byte) ([]byte, error) {
	return func(index int, record []byte) ([]byte, error) {
		if index != 0 {
			return record, nil
		}
		prelude, err := decodeFirstHopPrelude0(record)
		if err != nil {
			return nil, err
		}
		mutate(&prelude)
		return protocol.Encode(prelude)
	}
}

func mutateLiveFirstHopPrelude1Signature(index int, record []byte) ([]byte, error) {
	if index != 0 {
		return record, nil
	}
	reader := wire.NewReader(record)
	prelude := protocol.DecodeCoverPrelude1(reader)
	if reader.Err() != nil {
		return nil, reader.Err()
	}
	if !reader.EOF() || len(prelude.ServerPreludeSignatureClassical) == 0 {
		return nil, errors.New("live first-hop Prelude1 signature is unavailable")
	}
	prelude.ServerPreludeSignatureClassical[0] ^= 0xff
	return protocol.Encode(prelude)
}

type liveFirstHopFixture struct {
	deployment     trust.VerifiedRelayDeployment
	accessHint     admission.AccessHintCredential
	epochClassical *ecdsa.PrivateKey
	epochPQ        *mldsa65.PrivateKey
	tokenPrivate   *rsa.PrivateKey
	tokenPublicDER []byte
}

func newLiveFirstHopFixture(t testing.TB, now time.Time) liveFirstHopFixture {
	t.Helper()
	longtermClassical := generateLiveFirstHopECDSA(t)
	epochClassical := generateLiveFirstHopECDSA(t)
	templateAuthority := generateLiveFirstHopECDSA(t)
	longtermPQPublic, longtermPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epochPQPublic, epochPQPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tokenPublicDER, err := marshalLiveFirstHopRSAPSSPublicKey(&tokenPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nowUnix := uint64(now.Unix())
	template := protocol.CoverTemplate{
		TemplateVersion:  registry.Version20,
		TemplateID:       randomLiveFirstHopBytes(t, 16),
		TemplateFamilyID: randomLiveFirstHopBytes(t, 16),
		ValidFromUnix:    nowUnix - 60,
		ValidUntilUnix:   nowUnix + 3600,
		OriginSPKIHash:   randomLiveFirstHopBytes(t, 48),
		PublicNameHash:   randomLiveFirstHopBytes(t, 48),
		RequestClasses: []protocol.RequestClass{{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: registry.MethodWebH2Stream,
			PathTemplateID:      randomLiveFirstHopBytes(t, 16),
			BodyPolicyID:        1,
			ResponsePolicyID:    2,
			MayCarryPrelude:     true,
			MayCarryCapsule:     true,
		}},
		GatewayOwnedSlotCommitments:      [][]byte{randomLiveFirstHopBytes(t, 48)},
		OriginPassThroughSlotCommitments: [][]byte{randomLiveFirstHopBytes(t, 48)},
		PreludeEnvelope: protocol.PreludeEnvelope{
			MinRequestBodySize:         1536,
			MaxRequestBodySize:         4096,
			RequestSizeDistributionID:  randomLiveFirstHopBytes(t, 16),
			MinResponseBodySize:        6144,
			MaxResponseBodySize:        8192,
			ResponseSizeDistributionID: randomLiveFirstHopBytes(t, 16),
		},
		CapsuleEnvelope: protocol.CapsuleEnvelope{
			EnvelopeID:               randomLiveFirstHopBytes(t, 16),
			MinCapsuleBodySize:       1024,
			MaxCapsuleBodySize:       8192,
			BodySizeDistributionID:   randomLiveFirstHopBytes(t, 16),
			ConsumeFailedBodyLocally: true,
		},
		H2Profile:         protocol.H2CoverProfile{ProfileID: 1, RecordSizeDistributionID: randomLiveFirstHopBytes(t, 16)},
		H3Profile:         protocol.H3CoverProfile{ProfileID: 2, DatagramSizeDistributionID: randomLiveFirstHopBytes(t, 16), DatagramRateDistributionID: randomLiveFirstHopBytes(t, 16)},
		WebSocketProfile:  protocol.WebSocketCoverProfile{ProfileID: 3, FrameSizeDistributionID: randomLiveFirstHopBytes(t, 16)},
		CacheCookiePolicy: protocol.CacheCookiePolicy{PolicyID: 4},
		TimingEnvelope:    protocol.TimingEnvelope{TimingPolicyID: 5, JitterDistributionID: randomLiveFirstHopBytes(t, 16)},
	}
	template.CoverOriginCommitment, err = trust.CoverOriginCommitment(template)
	if err != nil {
		t.Fatal(err)
	}
	templateHash, err := trust.CoverTemplateHash(template)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      randomLiveFirstHopBytes(t, 32),
		RoleFlags:                    1,
		ValidFromUnix:                nowUnix - 60,
		ValidUntilUnix:               nowUnix + 3600,
		RelayLongtermClassicalKey:    liveFirstHopECDSAPublicRecord(t, longtermClassical),
		RelayLongtermPQKey:           protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: longtermPQPublic.Bytes()},
		EpochID:                      9,
		EpochAuthClassicalKey:        liveFirstHopECDSAPublicRecord(t, epochClassical),
		EpochAuthPQKey:               protocol.PublicKeyRecord{SignatureScheme: registry.SigMLDSA65, KeyEncoding: registry.KeyMLDSA65RawPublic, PublicKey: epochPQPublic.Bytes()},
		EpochValidFromUnix:           nowUnix - 60,
		EpochValidUntilUnix:          nowUnix + 3600,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    nowUnix + 3600,
		ReplayWindowID:               randomLiveFirstHopBytes(t, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: randomLiveFirstHopBytes(t, 48),
		SupportedShapeIDsCommitment:  randomLiveFirstHopBytes(t, 48),
		CoverTemplateInstanceHashes:  [][]byte{templateHash},
		ExitPolicyCommitment:         randomLiveFirstHopBytes(t, 48),
		AbusePolicyCommitment:        randomLiveFirstHopBytes(t, 48),
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
	familyInput, err := trust.CoverTemplateFamilySignatureInput(template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateFamilySignature, err = ecdsa.SignASN1(rand.Reader, templateAuthority, familyInput)
	if err != nil {
		t.Fatal(err)
	}
	instanceInput, err := trust.CoverTemplateInstanceSignatureInput(descriptorHash, template)
	if err != nil {
		t.Fatal(err)
	}
	template.TemplateInstanceSignature, err = ecdsa.SignASN1(rand.Reader, longtermClassical, instanceInput)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor:               descriptor,
		TrustedDescriptorHash:    descriptorHash,
		Template:                 template,
		TemplateAuthorityKey:     liveFirstHopECDSAPublicRecord(t, templateAuthority),
		RequestClassID:           7,
		Suite:                    registry.SuiteHybrid768P256AESGCM,
		Method:                   registry.MethodWebH2Stream,
		NowUnix:                  nowUnix,
		MaxTemplateFutureSkew:    120,
		RequirePQDescriptorProof: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return liveFirstHopFixture{
		deployment: deployment,
		accessHint: admission.AccessHintCredential{
			HintIssuerID:  randomLiveFirstHopBytes(t, 16),
			RelayBucketID: randomLiveFirstHopBytes(t, 16),
			HintEpochID:   3,
			HintSelector:  randomLiveFirstHopBytes(t, 16),
			HintSecret:    randomLiveFirstHopBytes(t, 32),
			ExpiryUnix:    nowUnix + 1800,
			MaxUses:       1,
		},
		epochClassical: epochClassical,
		epochPQ:        epochPQPrivate,
		tokenPrivate:   tokenPrivate,
		tokenPublicDER: tokenPublicDER,
	}
}

func (f liveFirstHopFixture) newClientDriver(t testing.TB) *handshake.ClientDriver {
	t.Helper()
	driver, _ := f.newClientDriverWithProofProvider(t)
	return driver
}

func (f liveFirstHopFixture) newClientDriverWithProofProvider(t testing.TB) (*handshake.ClientDriver, *liveFirstHopProofProvider) {
	t.Helper()
	proofProvider := &liveFirstHopProofProvider{
		issuerID:      f.accessHint.HintIssuerID,
		relayBucketID: f.accessHint.RelayBucketID,
		privateKey:    f.tokenPrivate,
		publicKeyDER:  f.tokenPublicDER,
	}
	driver, err := handshake.NewClientDriver(handshake.ClientDriverConfig{
		Deployment: f.deployment,
		Suite:      f.deployment.Suite(),
		AccessHint: f.accessHint,
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{f.deployment.Suite()},
			OfferedMethods:          []uint64{f.deployment.Method()},
			MinimumPolicyID:         registry.PolicyFastWeb,
			RequestedPolicyID:       registry.PolicyBalancedWeb,
			RequestedRouteModeID:    registry.RouteFast1,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
		TransportHints: protocol.ClientTransportHints{Padding: randomLiveFirstHopBytes(t, 8)},
		ProofProvider:  proofProvider,
		RequirePQ:      true,
		SessionLimits:  liveFirstHopSessionLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return driver, proofProvider
}

type liveFirstHopRelayOptions struct {
	hintResolver      handshake.HintCredentialResolver
	hintCache         handshake.DurableReplayCache
	admissionVerifier handshake.AdmissionVerifier
	tokenCache        handshake.DurableReplayCache
	bootstrapCache    handshake.DurableReplayCache
	policySelector    handshake.PolicySelector
}

func (f liveFirstHopFixture) newRelayDriver(t testing.TB, supplied ...liveFirstHopRelayOptions) *handshake.RelayDriver {
	t.Helper()
	options := liveFirstHopRelayOptions{}
	if len(supplied) > 0 {
		options = supplied[0]
	}
	if options.hintCache == nil {
		options.hintCache = &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	}
	if options.admissionVerifier == nil {
		options.admissionVerifier = liveFirstHopAdmissionVerifier{tokenPublicKeyDER: f.tokenPublicDER}
	}
	if options.tokenCache == nil {
		options.tokenCache = &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	}
	if options.bootstrapCache == nil {
		options.bootstrapCache = &liveFirstHopDurableReplayCache{MemoryReplayCache: admission.NewMemoryReplayCache()}
	}
	if options.policySelector == nil {
		options.policySelector = liveFirstHopPolicySelector{}
	}
	if options.hintResolver == nil {
		options.hintResolver = liveFirstHopHintResolver{credential: f.accessHint}
	}
	descriptor := f.deployment.Descriptor()
	driver, err := handshake.NewRelayDriver(handshake.RelayDriverConfig{
		Deployment:        f.deployment,
		HintResolver:      options.hintResolver,
		HintSpentCache:    options.hintCache,
		AdmissionVerifier: options.admissionVerifier,
		TokenSpentCache:   options.tokenCache,
		BootstrapCache:    options.bootstrapCache,
		ClassicalSigner:   liveFirstHopSigner{publicKey: descriptor.EpochAuthClassicalKey, classical: f.epochClassical},
		PQSigner:          liveFirstHopSigner{publicKey: descriptor.EpochAuthPQKey, pq: f.epochPQ},
		PolicySelector:    options.policySelector,
		RequirePQ:         true,
		SessionLimits:     liveFirstHopSessionLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

type liveFirstHopProofProvider struct {
	issuerID            []byte
	relayBucketID       []byte
	privateKey          *rsa.PrivateKey
	publicKeyDER        []byte
	tamperAuthenticator bool
	calls               atomic.Int32
}

func (p *liveFirstHopProofProvider) BuildProofs(ctx context.Context, request handshake.ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	p.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	if p.privateKey == nil || len(p.publicKeyDER) == 0 {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, errors.New("live first-hop proof provider is missing its RSA key")
	}
	keyID := sha256.Sum256(p.publicKeyDER)
	tokenScope, err := randomLiveFirstHopBytesResult(16)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	tokenNonce, err := randomLiveFirstHopBytesResult(32)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	proof := protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              append([]byte(nil), p.issuerID...),
		TokenKeyID:            keyID[:],
		RelayBucketID:         append([]byte(nil), p.relayBucketID...),
		TokenScopeID:          tokenScope,
		ExpiryUnix:            request.ReplayEpochValidUntil - 1,
		TokenNonce:            tokenNonce,
		RedemptionContextHash: append([]byte(nil), request.AdmissionContextHash...),
	}
	issuerName := []byte("issuer.invalid")
	originInfo := []byte("origin.invalid")
	challengeDigest, err := admission.RFC9577TokenChallengeDigest(proof.ProofType, issuerName, originInfo, proof.RedemptionContextHash)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	issuerMetadataHash, err := randomLiveFirstHopBytesResult(48)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	metadata := protocol.AuroraTokenMetadata{
		RFC9577TokenType:       uint16(proof.ProofType),
		RFC9577ChallengeDigest: challengeDigest,
		RFC9577TokenKeyID:      append([]byte(nil), proof.TokenKeyID...),
		IssuerName:             issuerName,
		OriginInfo:             originInfo,
		IssuerMetadataHash:     issuerMetadataHash,
	}
	proof.TokenPublicMetadata, err = protocol.Encode(metadata)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	authenticatorInput, err := admission.RFC9577AuthenticatorInput(proof, challengeDigest)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	digest := sha512.Sum384(authenticatorInput)
	proof.TokenAuthenticator, err = rsa.SignPSS(rand.Reader, p.privateKey, crypto.SHA384, digest[:], &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	})
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	if p.tamperAuthenticator {
		proof.TokenAuthenticator[0] ^= 0xff
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, err
	}
	replayNonce, err := randomLiveFirstHopBytesResult(32)
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
	return proof, replay, err
}

type liveFirstHopHintResolver struct {
	credential admission.AccessHintCredential
}

func (r liveFirstHopHintResolver) ResolveAccessHint(_ context.Context, issuerID, relayBucketID []byte, hintEpochID uint64, hintSelector []byte) (admission.AccessHintCredential, error) {
	credential := r.credential
	if !bytes.Equal(issuerID, credential.HintIssuerID) || !bytes.Equal(relayBucketID, credential.RelayBucketID) || hintEpochID != credential.HintEpochID || !bytes.Equal(hintSelector, credential.HintSelector) {
		return admission.AccessHintCredential{}, errors.New("live first-hop hint tuple mismatch")
	}
	return cloneLiveFirstHopHintCredential(credential), nil
}

type liveFirstHopMultiHintResolver struct {
	credentials []admission.AccessHintCredential
}

func (r liveFirstHopMultiHintResolver) ResolveAccessHint(_ context.Context, issuerID, relayBucketID []byte, hintEpochID uint64, hintSelector []byte) (admission.AccessHintCredential, error) {
	for _, credential := range r.credentials {
		if bytes.Equal(issuerID, credential.HintIssuerID) && bytes.Equal(relayBucketID, credential.RelayBucketID) && hintEpochID == credential.HintEpochID && bytes.Equal(hintSelector, credential.HintSelector) {
			return cloneLiveFirstHopHintCredential(credential), nil
		}
	}
	return admission.AccessHintCredential{}, errors.New("live first-hop hint tuple mismatch")
}

func cloneLiveFirstHopHintCredential(credential admission.AccessHintCredential) admission.AccessHintCredential {
	credential.HintIssuerID = append([]byte(nil), credential.HintIssuerID...)
	credential.RelayBucketID = append([]byte(nil), credential.RelayBucketID...)
	credential.HintSelector = append([]byte(nil), credential.HintSelector...)
	credential.HintSecret = append([]byte(nil), credential.HintSecret...)
	return credential
}

type liveFirstHopDurableReplayCache struct {
	*admission.MemoryReplayCache
	err       error
	duplicate bool
}

func (*liveFirstHopDurableReplayCache) Durable() bool { return true }

func (c *liveFirstHopDurableReplayCache) InsertIfAbsent(key []byte) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	if c.duplicate {
		return false, nil
	}
	return c.MemoryReplayCache.InsertIfAbsent(key)
}

type liveFirstHopAdmissionVerifier struct {
	tokenPublicKeyDER []byte
	err               error
}

func (v liveFirstHopAdmissionVerifier) VerifyAdmission(ctx context.Context, proof protocol.AdmissionProof, _ uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.err != nil {
		return v.err
	}
	return admission.VerifyBlindRSA2048(proof, v.tokenPublicKeyDER)
}

type liveFirstHopSigner struct {
	publicKey protocol.PublicKeyRecord
	classical *ecdsa.PrivateKey
	pq        *mldsa65.PrivateKey
}

func (s liveFirstHopSigner) PublicKey() protocol.PublicKeyRecord { return s.publicKey }

func (s liveFirstHopSigner) SignTranscript(ctx context.Context, transcript []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
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
	return nil, errors.New("live first-hop signer has no key")
}

type liveFirstHopPolicySelector struct{ err error }

func (s liveFirstHopPolicySelector) SelectPolicy(ctx context.Context, offer protocol.PolicyOffer, _ protocol.ClientTransportHints) (protocol.PolicyAccept, error) {
	if err := ctx.Err(); err != nil {
		return protocol.PolicyAccept{}, err
	}
	if s.err != nil {
		return protocol.PolicyAccept{}, s.err
	}
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             offer.OfferedSuites[0],
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            offer.RequestedPolicyID,
		SelectedRouteModeID:       offer.RequestedRouteModeID,
		SelectedShape:             offer.RequestedShapeID,
		SelectedTunnelPersonality: offer.TunnelPersonalityOffers[0],
	}, nil
}

func liveFirstHopSessionLimits() session.Limits {
	return session.Limits{MaxQueuedPackets: 32, MaxQueuedBytes: 256 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 1024}
}

func generateLiveFirstHopECDSA(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func liveFirstHopECDSAPublicRecord(t testing.TB, key *ecdsa.PrivateKey) protocol.PublicKeyRecord {
	t.Helper()
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return protocol.PublicKeyRecord{SignatureScheme: registry.SigECDSAP256SHA384DER, KeyEncoding: registry.KeyP256SEC1Uncompressed, PublicKey: encoded}
}

func marshalLiveFirstHopRSAPSSPublicKey(key *rsa.PublicKey) ([]byte, error) {
	rsaKey, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		},
		SubjectPublicKey: asn1.BitString{Bytes: rsaKey, BitLength: len(rsaKey) * 8},
	})
}

func randomLiveFirstHopBytes(t testing.TB, length int) []byte {
	t.Helper()
	value, err := randomLiveFirstHopBytesResult(length)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func randomLiveFirstHopBytesResult(length int) ([]byte, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}
