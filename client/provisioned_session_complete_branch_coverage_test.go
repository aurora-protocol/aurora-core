package client

// Prototype (temporary): adversarial white-box coverage for the count-0
// error-sub-path guards inside the err==nil block of
// ProvisionedSession.Complete (provisioned_session.go :194/:196/:210/:234).
// Reuses the existing test harness (newProvisionedSessionTestIssuer,
// provisionedSessionTestProvisioning, provisionedSessionIssuerResponse,
// provisionedSessionTestRequest, provisionedSessionTestHandshake) so no
// crypto forging is needed: provisionedSessionIssuerResponse produces a valid
// signed Blind RSA admission proof (issuer.IssueBlindRSA2048 with
// RedemptionContextHash=request.AdmissionContextHash, ExpiryUnix=now+5min) so
// provisionedProofsForIssuerResponse returns err==nil and the flow reaches the
// guarded sub-paths. The response MUST be signed by the same issuer whose
// metadata is in the provisioning, so newCompleteTestSession returns that issuer.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
)

// establishedErrorHandshake is a fake provisionedSessionHandshake whose Complete
// returns a non-nil established together with a non-nil error, driving the
// :234 "established != nil in the error tail" guard (provisionedSessionTestHandshake
// can only return (established, nil) or (nil, error), not (non-nil, non-nil)).
type establishedErrorHandshake struct {
	established *handshake.EstablishedSession
	completeErr error
	closed      bool
}

func (h *establishedErrorHandshake) Complete(context.Context, protocol.AdmissionProof, protocol.ReplayProof) (*handshake.EstablishedSession, error) {
	return h.established, h.completeErr
}

func (h *establishedErrorHandshake) Close() error {
	h.closed = true
	return nil
}

// newCompleteTestSession builds a completable ProvisionedSession via the real
// newProvisionedSession with a mock start returning the given deferred handshake
// and the shared test request, mirroring TestProvisionedSessionTransfersEstablishedSessionOnce.
// It returns the session and the issuer that signed the provisioning metadata,
// so the caller can build a matching issuer response with the SAME issuer.
func newCompleteTestSession(t *testing.T, now time.Time, deferred provisionedSessionHandshake) (*ProvisionedSession, *issuerd.Service) {
	t.Helper()
	issuer := newProvisionedSessionTestIssuer(t, now)
	provisioning := provisionedSessionTestProvisioning(t, now, issuer)
	request := provisionedSessionTestRequest()
	session, _, err := newProvisionedSession(
		context.Background(),
		provisioning,
		ProvisionedSessionOptions{
			HandshakeTimeout: time.Second,
			IssuerTimeout:    time.Hour,
			now:              func() time.Time { return now },
			random:           bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
			start: func(context.Context, NativeProvisioning, time.Time) (provisionedSessionHandshake, handshake.ClientProofRequest, error) {
				return deferred, request, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("newProvisionedSession: %v", err)
	}
	return session, issuer
}

func TestProvisionedSessionCompleteNilSessionContextGuard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	deferred := &provisionedSessionTestHandshake{}
	session, issuer := newCompleteTestSession(t, now, deferred)
	session.ctx = nil // in-package: force the :194 sessionContext == nil guard
	response := provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now)
	_, err := session.Complete(context.Background(), response)
	if err == nil {
		t.Fatal("Complete(nil session ctx) err = nil, want non-nil (:195 should reject)")
	}
	if !strings.Contains(err.Error(), "context is unavailable") {
		t.Fatalf("err = %q, want substring \"context is unavailable\" (:195)", err.Error())
	}
}

func TestProvisionedSessionCompleteCancelledSessionContextGuard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	deferred := &provisionedSessionTestHandshake{}
	session, issuer := newCompleteTestSession(t, now, deferred)
	session.cancel() // in-package: cancel the session context -> :196 sessionContext.Err() != nil
	response := provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now)
	_, err := session.Complete(context.Background(), response)
	if err == nil {
		t.Fatal("Complete(cancelled session ctx) err = nil, want non-nil (:197 should surface the session ctx error)")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %q, want errors.Is(context.Canceled) (:197 sets err = sessionContext.Err())", err.Error())
	}
}

func TestProvisionedSessionCompleteRejectsEstablishedWithoutCarrierStreams(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	deferred := &provisionedSessionTestHandshake{established: &handshake.EstablishedSession{}}
	session, issuer := newCompleteTestSession(t, now, deferred)
	response := provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now)
	_, err := session.Complete(context.Background(), response)
	if err == nil {
		t.Fatal("Complete(partial established) err = nil, want non-nil (:215 should reject a completed session without carrier streams)")
	}
	if !strings.Contains(err.Error(), "without carrier streams") {
		t.Fatalf("err = %q, want substring \"without carrier streams\" (:215)", err.Error())
	}
}

func TestProvisionedSessionCompleteClosesEstablishedOnHandshakeError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	deferred := &establishedErrorHandshake{established: &handshake.EstablishedSession{}, completeErr: errors.New("simulated handshake completion failure")}
	session, issuer := newCompleteTestSession(t, now, deferred)
	response := provisionedSessionIssuerResponse(t, issuer, provisionedSessionTestRequest(), now)
	_, err := session.Complete(context.Background(), response)
	if err == nil {
		t.Fatal("Complete(handshake error) err = nil, want non-nil (:240 wraps the handshake error)")
	}
	if !strings.Contains(err.Error(), "simulated handshake completion failure") {
		t.Fatalf("err = %q, want substring \"simulated handshake completion failure\" (:240 wraps deferred.Complete's error)", err.Error())
	}
}
