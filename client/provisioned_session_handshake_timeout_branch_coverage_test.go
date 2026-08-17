package client

// Prototype (temporary): adversarial white-box coverage for the count-0
// handshake-timeout / nil-handshake guards in newProvisionedSession.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
)

type timeoutPathHandshake struct {
	closed bool
}

func (h *timeoutPathHandshake) Complete(context.Context, protocol.AdmissionProof, protocol.ReplayProof) (*handshake.EstablishedSession, error) {
	return nil, errors.New("Complete must not be called in the timeout path")
}

func (h *timeoutPathHandshake) Close() error {
	h.closed = true
	return nil
}

func TestProvisionedSessionHandshakeTimeoutClosesDeferredHandshake(t *testing.T) {
	now := time.Unix(1700000000, 0)
	provisioning := validNativeProvisioning(t, now)
	deferred := &timeoutPathHandshake{}
	options := ProvisionedSessionOptions{
		HandshakeTimeout: 10 * time.Millisecond,
		now:              func() time.Time { return now },
		start: func(ctx context.Context, _ NativeProvisioning, _ time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
			<-ctx.Done() // block until the handshake timer cancels the context
			return deferred, handshake.ClientProofRequest{}, nil
		},
	}
	_, _, err := newProvisionedSession(context.Background(), provisioning, options)
	if err == nil {
		t.Fatal("newProvisionedSession timeout err = nil, want non-nil (:111 should reject)")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout err = %q, want substring \"timed out\" (:111)", err.Error())
	}
	if !deferred.closed {
		t.Fatal("the deferred handshake was not closed (:110 deferred.Close must run when deferred != nil in the timeout path)")
	}
}

func TestProvisionedSessionHandshakeTimeoutNilDeferredGuard(t *testing.T) {
	now := time.Unix(1700000000, 0)
	provisioning := validNativeProvisioning(t, now)
	options := ProvisionedSessionOptions{
		HandshakeTimeout: 10 * time.Millisecond,
		now:              func() time.Time { return now },
		start: func(ctx context.Context, _ NativeProvisioning, _ time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
			<-ctx.Done()
			return nil, handshake.ClientProofRequest{}, nil
		},
	}
	_, _, err := newProvisionedSession(context.Background(), provisioning, options)
	if err == nil {
		t.Fatal("newProvisionedSession timeout (nil deferred) err = nil, want non-nil (:113 should reject)")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout err = %q, want substring \"timed out\" (:113)", err.Error())
	}
}

func TestProvisionedSessionStarterReturningNoHandshakeGuard(t *testing.T) {
	now := time.Unix(1700000000, 0)
	provisioning := validNativeProvisioning(t, now)
	options := ProvisionedSessionOptions{
		HandshakeTimeout: time.Second,
		now:              func() time.Time { return now },
		start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
			return nil, handshake.ClientProofRequest{}, nil // returns immediately; no deferred handshake
		},
	}
	_, _, err := newProvisionedSession(context.Background(), provisioning, options)
	if err == nil {
		t.Fatal("newProvisionedSession no-handshake err = nil, want non-nil (:126 should reject)")
	}
	if !strings.Contains(err.Error(), "no handshake") {
		t.Fatalf("no-handshake err = %q, want substring \"no handshake\" (:126)", err.Error())
	}
}
