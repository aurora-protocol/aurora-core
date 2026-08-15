package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
)

func TestProvisionedSessionBuildsIssuerWorkAndClosesDeferredHandshake(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, work, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, time.Unix(1_700_000_000, 0).UTC(), nil),
		ProvisionedSessionOptions{
			now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x73}, 32)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if work.IssuerURL != "https://issuer.example" || work.IssuerCarrierPath != "/assets/issue/42" || len(work.RequestBody) == 0 {
		t.Fatalf("unexpected issuer work: %+v", work)
	}
	carrierType, payload, err := server.DecodeCarrier(work.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	if carrierType != server.CarrierBlindRSAIssueReq || len(payload) == 0 {
		t.Fatalf("unexpected issuer carrier: type=%d bytes=%d", carrierType, len(payload))
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if !deferred.Closed() {
		t.Fatal("closing provisioned session did not close deferred handshake")
	}
}

func TestProvisionedSessionTakesOwnershipOfStarterProofRequest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := provisionedSessionTestRequest()
	expected := cloneProvisionedProofRequest(request)
	defer zeroProvisionedProofRequest(&expected)
	deferred := &provisionedSessionTestHandshake{}
	session, work, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, now, nil),
		ProvisionedSessionOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x75}, 32)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, request, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer work.Zero()
	defer session.Close()
	if !bytes.Equal(session.request.AdmissionContextHash, expected.AdmissionContextHash) ||
		!bytes.Equal(session.request.HandshakeBindingContext, expected.HandshakeBindingContext) ||
		!bytes.Equal(session.request.ReplayWindowID, expected.ReplayWindowID) {
		t.Fatal("provisioned session did not retain an independent proof request")
	}
	for _, field := range [][]byte{request.AdmissionContextHash, request.HandshakeBindingContext, request.ReplayWindowID} {
		if !bytes.Equal(field, make([]byte, len(field))) {
			t.Fatal("provisioned session retained starter proof request material")
		}
	}
}

func TestProvisionedSessionClosesDeferredHandshakeReturnedWithError(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	_, _, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, time.Unix(1_700_000_000, 0).UTC(), nil),
		ProvisionedSessionOptions{
			now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), errors.New("starter failed after opening handshake")
			},
		},
	)
	if err == nil {
		t.Fatal("provisioned session accepted a failing starter")
	}
	if !deferred.Closed() {
		t.Fatal("failing provisioned session starter left its handshake open")
	}
}

func TestProvisionedSessionExpiresAbandonedIssuerWork(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, work, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, time.Unix(1_700_000_000, 0).UTC(), nil),
		ProvisionedSessionOptions{
			IssuerTimeout: time.Nanosecond,
			now:           func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			random:        bytes.NewReader(bytes.Repeat([]byte{0x74}, 32)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer work.Zero()
	deadline := time.After(time.Second)
	for !deferred.Closed() {
		select {
		case <-deadline:
			t.Fatal("abandoned provisioned issuer work did not expire")
		case <-time.After(time.Millisecond):
		}
	}
	if session.Established() != nil {
		t.Fatal("expired provisioned session retained an established session")
	}
}

func TestIssuerWorkZeroErasesRequestBody(t *testing.T) {
	work := IssuerWork{RequestBody: []byte("opaque issuer request")}
	body := work.RequestBody
	work.Zero()
	if work.IssuerURL != "" || work.IssuerCarrierPath != "" || work.RequestBody != nil {
		t.Fatalf("issuer work was not cleared: %+v", work)
	}
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("issuer request body was not erased")
	}
}

func TestProvisionedSessionRejectsMalformedIssuerResponseAndCloses(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, _, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, time.Unix(1_700_000_000, 0).UTC(), nil),
		ProvisionedSessionOptions{
			now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x74}, 32)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Complete(context.Background(), []byte{0x01}); err == nil {
		t.Fatal("malformed issuer response was accepted")
	}
	if !deferred.Closed() {
		t.Fatal("malformed issuer response left deferred handshake open")
	}
}

func TestProvisionedSessionRejectsIssuerResponseOutsideVerifiedMetadata(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	trustedIssuer := newProvisionedSessionTestIssuer(t, now)
	untrustedIssuer := newProvisionedSessionTestIssuer(t, now)
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 9,
		Write: session.DirectionConfig{
			Direction: 0,
			Secret:    bytes.Repeat([]byte{0x11}, 48),
			Key:       bytes.Repeat([]byte{0x12}, 32),
			IV:        bytes.Repeat([]byte{0x13}, 12),
		},
		Read: session.DirectionConfig{
			Direction: 1,
			Secret:    bytes.Repeat([]byte{0x21}, 48),
			Key:       bytes.Repeat([]byte{0x22}, 32),
			IV:        bytes.Repeat([]byte{0x23}, 12),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	deferred := &provisionedSessionTestHandshake{established: &handshake.EstablishedSession{
		Application:  application,
		ReadCarrier:  io.NopCloser(bytes.NewReader(nil)),
		WriteCarrier: provisionedSessionDiscardWriteCloser{Writer: io.Discard},
	}}
	session, _, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, now, trustedIssuer),
		ProvisionedSessionOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Complete(context.Background(), provisionedSessionIssuerResponse(t, untrustedIssuer, provisionedSessionTestRequest(), now)); err == nil {
		t.Fatal("provisioned session accepted a response outside its verified issuer metadata")
	}
	if deferred.Completed() {
		t.Fatal("untrusted issuer response reached the relay handshake")
	}
	if !deferred.Closed() {
		t.Fatal("untrusted issuer response left the relay handshake open")
	}
}

func TestProvisionedSessionRejectsCompletionAfterClose(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, _, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, time.Unix(1_700_000_000, 0).UTC(), nil),
		ProvisionedSessionOptions{
			now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x75}, 32)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Complete(context.Background(), []byte{0x01}); err == nil {
		t.Fatal("closed session accepted issuer completion")
	}
}

func TestProvisionedSessionCompletionHonorsCallerCancellation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := newProvisionedSessionTestIssuer(t, now)
	deferred := newBlockingProvisionedSessionHandshake()
	session, _, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, now, issuer),
		ProvisionedSessionOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	issuerResponse := provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now)
	defer zeroProvisionedBytes(issuerResponse)
	completionContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := session.Complete(completionContext, issuerResponse)
		result <- err
	}()
	select {
	case <-deferred.started:
	case <-time.After(time.Second):
		_ = session.Close()
		t.Fatal("provisioned completion did not reach the deferred handshake")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("provisioned completion cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(100 * time.Millisecond):
		_ = session.Close()
		<-result
		t.Fatal("provisioned completion ignored caller cancellation")
	}
	if !deferred.Closed() {
		t.Fatal("caller cancellation left the deferred handshake open")
	}
}

func TestProvisionedSessionTransfersEstablishedSessionOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	issuer := newProvisionedSessionTestIssuer(t, now)
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 9,
		Write: session.DirectionConfig{
			Direction: 0,
			Secret:    bytes.Repeat([]byte{0x11}, 48),
			Key:       bytes.Repeat([]byte{0x12}, 32),
			IV:        bytes.Repeat([]byte{0x13}, 12),
		},
		Read: session.DirectionConfig{
			Direction: 1,
			Secret:    bytes.Repeat([]byte{0x21}, 48),
			Key:       bytes.Repeat([]byte{0x22}, 32),
			IV:        bytes.Repeat([]byte{0x23}, 12),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	established := &handshake.EstablishedSession{
		Application:  application,
		ReadCarrier:  io.NopCloser(bytes.NewReader(nil)),
		WriteCarrier: provisionedSessionDiscardWriteCloser{Writer: io.Discard},
	}
	deferred := &provisionedSessionTestHandshake{established: established}
	session, _, err := newProvisionedSession(
		context.Background(),
		provisionedSessionTestProvisioning(t, now, issuer),
		ProvisionedSessionOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := session.Complete(context.Background(), provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now))
	if err != nil {
		t.Fatal(err)
	}
	if got != established || session.Established() != established || !deferred.Completed() {
		t.Fatal("provisioned session did not transfer the established carrier")
	}
	if _, err := session.Complete(context.Background(), provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now)); err == nil {
		t.Fatal("provisioned session accepted a second completion")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func provisionedSessionTestRequest() handshake.ClientProofRequest {
	return handshake.ClientProofRequest{
		AdmissionContextHash:    bytes.Repeat([]byte{0x41}, 48),
		HandshakeBindingContext: bytes.Repeat([]byte{0x42}, 48),
		RouteInstanceID:         7,
		HopIndex:                0,
		ReplayEpochID:           3,
		ReplayEpochValidUntil:   1_700_000_600,
		ReplayWindowID:          bytes.Repeat([]byte{0x43}, 16),
	}
}

type provisionedSessionTestHandshake struct {
	mu          sync.Mutex
	closed      bool
	completed   bool
	established *handshake.EstablishedSession
}

func (h *provisionedSessionTestHandshake) Complete(context.Context, protocol.AdmissionProof, protocol.ReplayProof) (*handshake.EstablishedSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.established == nil {
		return nil, errors.New("test handshake completion must not receive malformed issuer data")
	}
	h.completed = true
	return h.established, nil
}

func (h *provisionedSessionTestHandshake) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	return nil
}

func (h *provisionedSessionTestHandshake) Closed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func (h *provisionedSessionTestHandshake) Completed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.completed
}

type blockingProvisionedSessionHandshake struct {
	mu      sync.Mutex
	started chan struct{}
	closed  bool
}

func newBlockingProvisionedSessionHandshake() *blockingProvisionedSessionHandshake {
	return &blockingProvisionedSessionHandshake{started: make(chan struct{})}
}

func (h *blockingProvisionedSessionHandshake) Complete(ctx context.Context, _ protocol.AdmissionProof, _ protocol.ReplayProof) (*handshake.EstablishedSession, error) {
	close(h.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *blockingProvisionedSessionHandshake) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	return nil
}

func (h *blockingProvisionedSessionHandshake) Closed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func provisionedSessionTestProvisioning(t testing.TB, now time.Time, issuer *issuerd.Service) NativeProvisioning {
	t.Helper()
	if issuer == nil {
		issuer = newProvisionedSessionTestIssuer(t, now)
	}
	metadata, err := protocol.Encode(issuer.PublishIssuerMetadata())
	if err != nil {
		t.Fatal(err)
	}
	publishedMetadata := issuer.PublishIssuerMetadata()
	signedSeed, signedSeedTrust := nativeProvisioningSignedSeedAndTrust(t, now, publishedMetadata, issuer.AuthorityKeys(), publishedMetadata.IssuerID, nil)
	return NativeProvisioning{
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/assets/issue/42",
		IssuerMetadata:    metadata,
		SignedSeed:        signedSeed,
		signedSeedTrust:   signedSeedTrust,
	}
}

func newProvisionedSessionTestIssuer(t testing.TB, now time.Time) *issuerd.Service {
	t.Helper()
	issuer, err := issuerd.NewHarnessService(uint64(now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func provisionedSessionIssuerResponse(t testing.TB, issuer *issuerd.Service, request handshake.ClientProofRequest, now time.Time) []byte {
	t.Helper()
	proof, err := issuer.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{
		TokenNonce:            bytes.Repeat([]byte{0x55}, 32),
		RedemptionContextHash: request.AdmissionContextHash,
		ExpiryUnix:            uint64(now.Add(5 * time.Minute).Unix()),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	return server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encoded)
}

type provisionedSessionDiscardWriteCloser struct {
	io.Writer
}

func (provisionedSessionDiscardWriteCloser) Close() error { return nil }

var _ provisionedSessionHandshake = (*provisionedSessionTestHandshake)(nil)
var _ provisionedSessionHandshake = (*blockingProvisionedSessionHandshake)(nil)
