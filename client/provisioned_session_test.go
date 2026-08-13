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
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
)

func TestProvisionedSessionBuildsIssuerWorkAndClosesDeferredHandshake(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, work, err := newProvisionedSession(
		context.Background(),
		NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"},
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

func TestProvisionedSessionExpiresAbandonedIssuerWork(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, work, err := newProvisionedSession(
		context.Background(),
		NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"},
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
		NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"},
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

func TestProvisionedSessionRejectsCompletionAfterClose(t *testing.T) {
	deferred := &provisionedSessionTestHandshake{}
	session, _, err := newProvisionedSession(
		context.Background(),
		NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"},
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

func TestProvisionedSessionTransfersEstablishedSessionOnce(t *testing.T) {
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
		NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"},
		ProvisionedSessionOptions{
			now:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, provisionedSessionTestRequest(), nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := session.Complete(context.Background(), provisionedSessionIssuerResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != established || session.Established() != established || !deferred.Completed() {
		t.Fatal("provisioned session did not transfer the established carrier")
	}
	if _, err := session.Complete(context.Background(), provisionedSessionIssuerResponse(t)); err == nil {
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

func provisionedSessionIssuerResponse(t testing.TB) []byte {
	t.Helper()
	encoded, err := protocol.Encode(protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofLabStaticToken,
		IssuerID:              bytes.Repeat([]byte{0x51}, 16),
		TokenKeyID:            bytes.Repeat([]byte{0x52}, 32),
		RelayBucketID:         bytes.Repeat([]byte{0x53}, 16),
		TokenScopeID:          bytes.Repeat([]byte{0x54}, 16),
		ExpiryUnix:            1_700_000_300,
		TokenNonce:            bytes.Repeat([]byte{0x55}, 32),
		RedemptionContextHash: bytes.Repeat([]byte{0x56}, 48),
		TokenAuthenticator:    []byte("test-token"),
	})
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
