//go:build cgo

package main

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestNativeSessionHandleRejectsUnknownAndClosedValues(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	if err := registry.close(1); err == nil {
		t.Fatal("unknown native session handle was accepted")
	}
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.close(work.Handle); err != nil {
		t.Fatal(err)
	}
	if !stub.closedValue() {
		t.Fatal("closing a native session did not close its pending handshake")
	}
	if err := registry.close(work.Handle); err == nil {
		t.Fatal("closed native session handle was accepted")
	}
	if err := registry.queueFrameBlock(work.Handle, []byte{0}); err == nil {
		t.Fatal("closed native session accepted a frame block")
	}
}

func TestNativeSessionBeginReturnsIssuerRequestOnlyAfterPrelude1(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	request := nativeTestProofRequest(now)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, request, nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.close(work.Handle)
	if work.Handle == 0 || work.IssuerURL != "https://issuer.example" || work.IssuerCarrierPath != "/assets/issue/42" {
		t.Fatalf("unexpected issuer work: %+v", work)
	}
	carrierType, payload, err := server.DecodeCarrier(work.RequestBody)
	if err != nil || carrierType != server.CarrierBlindRSAIssueReq {
		t.Fatalf("unexpected native issuer carrier request: type=%d err=%v", carrierType, err)
	}
	tokenNonce, admissionContextHash, expiryUnix, err := server.DecodeCarrierIssueRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenNonce) != 32 || !bytes.Equal(admissionContextHash, request.AdmissionContextHash) || expiryUnix <= uint64(now.Unix()) || expiryUnix >= request.ReplayEpochValidUntil {
		t.Fatalf("unexpected native issuer request: nonce=%d context=%x expiry=%d", len(tokenNonce), admissionContextHash, expiryUnix)
	}
}

func TestNativeSessionCompletionOwnsAndDestroysProvisioningSecrets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	application := nativeTestApplication(t)
	stub := &nativeTestHandshake{session: &handshake.EstablishedSession{Application: application}}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	secret := bytes.Repeat([]byte{0xa4}, 32)
	provisioning := client.NativeProvisioning{
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/assets/issue/42",
		AccessHint:        secret,
	}
	work, err := registry.begin(provisioning)
	if err != nil {
		t.Fatal(err)
	}
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	issuerResponse := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)
	if err := registry.complete(work.Handle, issuerResponse); err != nil {
		t.Fatal(err)
	}
	issuerResponse[0] ^= 0xff
	if !stub.completedWith(proof) {
		t.Fatal("native session did not own the decoded admission proof")
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stub.replayTokenRedemptionHash(), redemption) {
		t.Fatal("native session did not retain an independently owned replay redemption hash")
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("native session retained provisioning secret bytes after begin")
	}
	if err := registry.close(work.Handle); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(application.Err(), session.ErrClosed) {
		t.Fatalf("closing a completed native session left application active: %v", application.Err())
	}
}

func TestNativeSessionPacketCallsRejectMalformedFramesAndPackets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	application := nativeTestApplication(t)
	stub := &nativeTestHandshake{session: &handshake.EstablishedSession{Application: application}}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.close(work.Handle)
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.complete(work.Handle, server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)); err != nil {
		t.Fatal(err)
	}
	if err := registry.queueFrameBlock(work.Handle, []byte{0xff}); err == nil {
		t.Fatal("native session accepted a malformed frame block")
	}
	if _, err := registry.handlePacket(work.Handle, []byte{0}); err == nil {
		t.Fatal("native session accepted a malformed encrypted packet")
	}
	frame, err := protocol.NewStreamDataFrame(1, []byte("payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	encodedBlock, err := protocol.Encode(protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.queueFrameBlock(work.Handle, encodedBlock); err != nil {
		t.Fatal(err)
	}
	packet, err := registry.nextPacket(work.Handle)
	if err != nil || len(packet) == 0 {
		t.Fatalf("native session did not produce encrypted packet: %x %v", packet, err)
	}
	if packet, err := registry.nextPacket(work.Handle); !errors.Is(err, session.ErrNoPacket) || packet != nil {
		t.Fatalf("native session next packet after drain = %x, %v; want no packet", packet, err)
	}
}

func TestNativeSessionDispatchUsesBoundedOpaqueOperations(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	application := nativeTestApplication(t)
	stub := &nativeTestHandshake{session: &handshake.EstablishedSession{Application: application}}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x88}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	previousRegistry := nativeSessions
	nativeSessions = registry
	defer func() { nativeSessions = previousRegistry }()

	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	status, payload := dispatch(opCompleteNativeSession, nativeHandlePayload(t, work.Handle, server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)), 0)
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("complete dispatch = status %d payload %x", status, payload)
	}
	frame, err := protocol.NewStreamDataFrame(1, []byte("payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	encodedBlock, err := protocol.Encode(protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
	if err != nil {
		t.Fatal(err)
	}
	status, payload = dispatch(opQueueFrameBlock, nativeHandlePayload(t, work.Handle, encodedBlock), 0)
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("queue dispatch = status %d payload %x", status, payload)
	}
	status, payload = dispatch(opNextPacket, nil, work.Handle)
	if status != statusOK || len(payload) == 0 {
		t.Fatalf("next packet dispatch = status %d payload %x", status, payload)
	}
	status, payload = dispatch(opNextPacket, nil, work.Handle)
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("empty next packet dispatch = status %d payload %x", status, payload)
	}
	status, payload = dispatch(opCloseNativeSession, nil, work.Handle)
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("close dispatch = status %d payload %x", status, payload)
	}
	status, payload = dispatch(opCloseNativeSession, nil, work.Handle)
	if status != statusError || len(payload) != 0 {
		t.Fatalf("closed handle dispatch = status %d payload %x", status, payload)
	}
}

func TestNativeSessionRegistryConcurrentLifecycle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x99}, 32*32)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return &nativeTestHandshake{}, nativeTestProofRequest(now), nil
		},
	})
	const workers = 16
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
			if err == nil {
				err = registry.close(work.Handle)
			}
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.sessions) != 0 {
		t.Fatalf("native session registry retained %d sessions", len(registry.sessions))
	}
}

func TestNativeSessionRegistryExpiresAbandonedIssuerWork(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:           func() time.Time { return now },
		random:        bytes.NewReader(bytes.Repeat([]byte{0xaa}, 64)),
		issuerTimeout: 10 * time.Millisecond,
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for {
		if stub.closedValue() {
			break
		}
		select {
		case <-deadline:
			t.Fatal("abandoned native issuer work did not expire")
		case <-time.After(time.Millisecond):
		}
	}
	if _, err := registry.lookup(work.Handle); err == nil {
		t.Fatal("expired native session handle remained live")
	}
}

type nativeTestHandshake struct {
	mu        sync.Mutex
	session   *handshake.EstablishedSession
	closed    bool
	admission protocol.AdmissionProof
	replay    protocol.ReplayProof
}

func (h *nativeTestHandshake) Complete(_ context.Context, admissionProof protocol.AdmissionProof, replayProof protocol.ReplayProof) (*handshake.EstablishedSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.admission.TokenNonce = append([]byte(nil), admissionProof.TokenNonce...)
	h.admission.RedemptionContextHash = append([]byte(nil), admissionProof.RedemptionContextHash...)
	h.replay.TokenRedemptionHash = append([]byte(nil), replayProof.TokenRedemptionHash...)
	h.replay.ClientReplayNonce = append([]byte(nil), replayProof.ClientReplayNonce...)
	return h.session, nil
}

func (h *nativeTestHandshake) replayTokenRedemptionHash() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]byte(nil), h.replay.TokenRedemptionHash...)
}

func (h *nativeTestHandshake) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	return nil
}

func (h *nativeTestHandshake) closedValue() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func (h *nativeTestHandshake) completedWith(want protocol.AdmissionProof) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return bytes.Equal(h.admission.TokenNonce, want.TokenNonce) && bytes.Equal(h.admission.RedemptionContextHash, want.RedemptionContextHash) && len(h.replay.ClientReplayNonce) == 32
}

func nativeTestProofRequest(now time.Time) handshake.ClientProofRequest {
	return handshake.ClientProofRequest{
		AdmissionContextHash:    bytes.Repeat([]byte{0x12}, 48),
		HandshakeBindingContext: bytes.Repeat([]byte{0x13}, 48),
		RouteInstanceID:         7,
		HopIndex:                0,
		ReplayEpochID:           9,
		ReplayEpochValidUntil:   uint64(now.Add(30 * time.Minute).Unix()),
		ReplayWindowID:          bytes.Repeat([]byte{0x14}, 16),
	}
}

func nativeTestAdmissionProof(now time.Time, admissionContextHash []byte) protocol.AdmissionProof {
	return protocol.AdmissionProof{
		ProofVersion:          registry.Version20,
		ProofType:             registry.ProofBlindRSA2048,
		IssuerID:              bytes.Repeat([]byte{0x21}, 16),
		TokenKeyID:            bytes.Repeat([]byte{0x22}, 32),
		RelayBucketID:         bytes.Repeat([]byte{0x23}, 16),
		TokenScopeID:          bytes.Repeat([]byte{0x24}, 16),
		ExpiryUnix:            uint64(now.Add(5 * time.Minute).Unix()),
		TokenNonce:            bytes.Repeat([]byte{0x25}, 32),
		RedemptionContextHash: append([]byte(nil), admissionContextHash...),
		TokenPublicMetadata:   []byte("metadata"),
		TokenAuthenticator:    []byte("authenticator"),
	}
}

func nativeTestApplication(t *testing.T) *session.Application {
	t.Helper()
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 7,
		HopLayer:        0,
		Write: session.DirectionConfig{
			Direction: 0,
			Secret:    bytes.Repeat([]byte{0x31}, 48),
			Key:       bytes.Repeat([]byte{0x32}, 32),
			IV:        bytes.Repeat([]byte{0x33}, 12),
		},
		Read: session.DirectionConfig{
			Direction: 1,
			Secret:    bytes.Repeat([]byte{0x41}, 48),
			Key:       bytes.Repeat([]byte{0x42}, 32),
			IV:        bytes.Repeat([]byte{0x43}, 12),
		},
		Limits: session.Limits{
			MaxQueuedPackets:       8,
			MaxQueuedBytes:         64 << 10,
			ControlReservedPackets: 2,
			ControlReservedBytes:   8 << 10,
			ReplayWindow:           64,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func nativeHandlePayload(t testing.TB, handle uint64, payload []byte) []byte {
	t.Helper()
	encoder := wire.NewEncoder()
	encoder.WriteVarint(handle)
	encoder.WriteOpaque24(payload)
	encoded, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
