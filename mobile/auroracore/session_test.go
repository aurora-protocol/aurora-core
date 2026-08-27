//go:build cgo

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
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

func TestNativeSessionBeginClosesDeferredHandshakeReturnedWithError(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x45}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), errors.New("starter failed after opening handshake")
		},
	})
	if _, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"}); err == nil {
		t.Fatal("native session accepted a failing starter")
	}
	if !stub.closedValue() {
		t.Fatal("failing native session starter left its handshake open")
	}
}

func TestNativeSessionBeginReturnsIssuerRequestOnlyAfterPrelude1(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	request := nativeTestProofRequest(now)
	admissionContextHash := append([]byte(nil), request.AdmissionContextHash...)
	defer zeroNativeBytes(admissionContextHash)
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
	tokenNonce, decodedAdmissionContextHash, expiryUnix, err := server.DecodeCarrierIssueRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenNonce) != 32 || !bytes.Equal(decodedAdmissionContextHash, admissionContextHash) || expiryUnix <= uint64(now.Unix()) || expiryUnix >= request.ReplayEpochValidUntil {
		t.Fatalf("unexpected native issuer request: nonce=%d context=%x expiry=%d", len(tokenNonce), decodedAdmissionContextHash, expiryUnix)
	}
}

func TestNativeSessionTakesOwnershipOfStarterProofRequest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	request := nativeTestProofRequest(now)
	expected := cloneNativeProofRequest(request)
	defer zeroNativeProofRequest(&expected)
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x56}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return &nativeTestHandshake{}, request, nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeIssuerWork(&work)
	defer registry.close(work.Handle)
	session, err := registry.lookup(work.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(session.request.AdmissionContextHash, expected.AdmissionContextHash) ||
		!bytes.Equal(session.request.HandshakeBindingContext, expected.HandshakeBindingContext) ||
		!bytes.Equal(session.request.ReplayWindowID, expected.ReplayWindowID) {
		t.Fatal("native session did not retain an independent proof request")
	}
	for _, field := range [][]byte{request.AdmissionContextHash, request.HandshakeBindingContext, request.ReplayWindowID} {
		if !bytes.Equal(field, make([]byte, len(field))) {
			t.Fatal("native session retained starter proof request material")
		}
	}
}

func TestNativeIssuerWorkJSONRemainsOpaqueToNativeAdapters(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x76}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return &nativeTestHandshake{}, nativeTestProofRequest(now), nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.close(work.Handle)
	encoded, err := encodeNativeIssuerWorkJSON(work)
	if err != nil {
		t.Fatal(err)
	}
	var decoded nativeIssuerWorkJSON
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(decoded.RequestBodyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Handle != work.Handle || decoded.IssuerURL != work.IssuerURL || decoded.IssuerCarrierPath != work.IssuerCarrierPath || !bytes.Equal(body, work.RequestBody) {
		t.Fatalf("native issuer JSON changed opaque issuer work: %+v", decoded)
	}
}

func TestNativeLocalPacketJSONRemainsOpaqueToNativeAdapters(t *testing.T) {
	packets := [][]byte{{0x45, 0x00, 0x00, 0x14}}
	encoded, err := encodeNativeLocalPacketsJSON(packets)
	if err != nil {
		t.Fatal(err)
	}
	var decoded nativeLocalPacketsJSON
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.PacketsBase64) != 1 {
		t.Fatalf("native local packet JSON count = %d", len(decoded.PacketsBase64))
	}
	packet, err := base64.StdEncoding.DecodeString(decoded.PacketsBase64[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, packets[0]) {
		t.Fatalf("native local packet JSON changed packet: %x", packet)
	}
}

func TestNativeSessionRawCompletionDispatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	application := nativeTestApplication(t)
	stub := &nativeTestHandshake{session: &handshake.EstablishedSession{Application: application}}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x78}, 64)),
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
	defer registry.close(work.Handle)
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	status, payload := dispatch(opCompleteNativeSessionRaw, server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof), work.Handle)
	if status != statusOK || len(payload) != 0 {
		t.Fatalf("raw completion dispatch = status %d payload %x", status, payload)
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

func TestNativeSessionRejectsIssuerProofForDifferentHandshake(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x67}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeIssuerWork(&work)
	proof := nativeTestAdmissionProof(now, bytes.Repeat([]byte{0xff}, 48))
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encodedProof)
	issuerResponse := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)
	defer zeroNativeBytes(issuerResponse)
	if err := registry.complete(work.Handle, issuerResponse); err == nil {
		t.Fatal("native session accepted an issuer proof bound to a different handshake")
	}
	if stub.completedWith(proof) {
		t.Fatal("context-mismatched issuer proof reached the deferred handshake")
	}
	if !stub.closedValue() {
		t.Fatal("rejecting a context-mismatched issuer proof left the handshake open")
	}
}

func TestNativeSessionRejectsExpiredIssuerProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x69}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeIssuerWork(&work)
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	proof.ExpiryUnix = uint64(now.Unix())
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encodedProof)
	issuerResponse := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)
	defer zeroNativeBytes(issuerResponse)
	if err := registry.complete(work.Handle, issuerResponse); err == nil {
		t.Fatal("native session accepted an expired issuer proof")
	}
	if stub.completedValue() {
		t.Fatal("expired issuer proof reached the deferred handshake")
	}
	if !stub.closedValue() {
		t.Fatal("rejecting an expired issuer proof left the handshake open")
	}
}

func TestNativeSessionVerifiesIssuerProofAgainstProvisionedMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newNativeSessionFixture(t, now)
	defer fixture.Close(t)
	stub := &nativeTestHandshake{}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x68}, 64)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return stub, nativeTestProofRequest(now), nil
		},
	})
	work, err := registry.begin(fixture.Provisioning(t))
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeIssuerWork(&work)
	issuerResponse := fixture.Issue(t, work.RequestBody)
	defer zeroNativeBytes(issuerResponse)
	carrierType, payload, err := server.DecodeCarrier(issuerResponse)
	if err != nil || carrierType != server.CarrierBlindRSAIssueResp {
		t.Fatalf("decode fixture issuer response: type=%d err=%v", carrierType, err)
	}
	proof, err := issuerd.DecodeAdmissionProofBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	proof.TokenAuthenticator[0] ^= 0xff
	tamperedProof, err := protocol.Encode(proof)
	zeroNativeAdmissionProof(&proof)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(tamperedProof)
	tamperedResponse := server.EncodeCarrier(server.CarrierBlindRSAIssueResp, tamperedProof)
	defer zeroNativeBytes(tamperedResponse)
	if err := registry.complete(work.Handle, tamperedResponse); err == nil {
		t.Fatal("native session accepted an issuer proof invalid under provisioned metadata")
	}
	if stub.completedValue() {
		t.Fatal("issuer proof invalid under provisioned metadata reached the deferred handshake")
	}
	if !stub.closedValue() {
		t.Fatal("rejecting an invalid issuer proof left the handshake open")
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

func TestNativeSessionPacketHandlingConsumesOwnedEncryptedInput(t *testing.T) {
	clientApplication := nativeTestApplication(t)
	peerApplication := nativePeerApplication(t)
	defer peerApplication.Close()
	registry := &nativeSessionRegistry{
		now: func() time.Time { return time.Unix(1_700_000_000, 0) },
		sessions: map[uint64]*nativeSession{
			1: {
				context:     context.Background(),
				cancel:      func() {},
				established: &handshake.EstablishedSession{Application: clientApplication},
			},
		},
	}
	defer registry.close(1)

	frame, err := protocol.NewStreamDataFrame(7, []byte("owned native packet"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := peerApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	encoded, err := peerApplication.TryNextPacket()
	if err != nil {
		t.Fatal(err)
	}
	view, err := packet.DecodeAuroraPacketView(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sealedOffset := len(encoded) - len(view.Ciphertext) - len(view.AuthTag)

	encodedBlocks, err := registry.handlePacket(1, encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroNativeBytes(encodedBlocks)
	reader := wire.NewReader(encodedBlocks)
	if count := reader.ReadVarint(); count != 1 {
		t.Fatalf("native owned packet block count = %d, want 1", count)
	}
	blocks, err := protocol.DecodeFrameBlock(reader.ReadOpaque24())
	if err != nil || reader.Err() != nil || !reader.EOF() {
		t.Fatalf("decode native owned packet blocks: %v %v", err, reader.Err())
	}
	defer zeroNativeFrameBlock(&blocks)
	if len(blocks.Frames) != 1 || !bytes.Equal(blocks.Frames[0].Payload, []byte("owned native packet")) {
		t.Fatalf("native owned packet blocks = %#v", blocks)
	}
	for index, value := range encoded[sealedOffset:] {
		if value != 0 {
			t.Fatalf("native encrypted input byte %d = %x after handling, want zero", index, value)
		}
	}

	if err := peerApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatal(err)
	}
	tampered, err := peerApplication.TryNextPacket()
	if err != nil {
		t.Fatal(err)
	}
	tamperedView, err := packet.DecodeAuroraPacketView(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedOffset := len(tampered) - len(tamperedView.Ciphertext) - len(tamperedView.AuthTag)
	tampered[tamperedOffset] ^= 0xff
	if _, err := registry.handlePacket(1, tampered); err == nil {
		t.Fatal("native packet handling accepted a tampered encrypted packet")
	}
	for index, value := range tampered[tamperedOffset:] {
		if value != 0 {
			t.Fatalf("tampered native encrypted input byte %d = %x after handling, want zero", index, value)
		}
	}
}

func TestNativeSessionDuplexConvertsRawPacketsWithoutExposingCarrierFrames(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clientRead, relayWrite := io.Pipe()
	relayRead, clientWrite := io.Pipe()
	clientApplication := nativeTestApplication(t)
	relayApplication := nativePeerApplication(t)
	defer relayApplication.Close()
	pumpContext, cancelPump := context.WithCancel(context.Background())
	defer cancelPump()
	flowIDs := make(chan uint64, 1)
	relayResult := make(chan error, 1)
	go func() {
		relayResult <- transport.RunPacketDuplex(pumpContext, relayRead, relayWrite, relayApplication, func(_ context.Context, block protocol.FrameBlock) error {
			for _, frame := range block.Frames {
				if frame.FrameType != registry.FrameFlowOpen {
					continue
				}
				reader := wire.NewReader(frame.Payload)
				open := protocol.DecodeFlowOpen(reader)
				if reader.Err() != nil || !reader.EOF() {
					return errors.New("malformed client flow open")
				}
				flowIDs <- open.FlowID
			}
			return nil
		}, transport.DefaultMaxRecordBodyBytes)
	}()
	stub := &nativeTestHandshake{session: &handshake.EstablishedSession{
		Application:  clientApplication,
		ReadCarrier:  clientRead,
		WriteCarrier: clientWrite,
	}}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x70}, 64)),
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

	syn := nativeTCPv4([4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x02, nil)
	immediate, err := registry.ingressLocalPacket(work.Handle, syn)
	if err != nil {
		t.Fatal(err)
	}
	if len(immediate) != 1 || len(immediate[0]) < 34 || immediate[0][33] != 0x12 {
		t.Fatalf("TCP SYN did not produce a synthetic SYN/ACK: %x", immediate)
	}
	flowID := <-flowIDs
	response, err := protocol.NewStreamDataFrame(flowID, []byte("response"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{response}}); err != nil {
		t.Fatal(err)
	}
	nextContext, cancelNext := context.WithTimeout(context.Background(), time.Second)
	defer cancelNext()
	local, err := registry.nextLocalPacket(nextContext, work.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if len(local) < 40 || local[33] != 0x18 || !bytes.Equal(local[40:], []byte("response")) {
		t.Fatalf("relay stream data did not emerge as a raw local TCP packet: %x", local)
	}
	if err := registry.queueFrameBlock(work.Handle, []byte{0xff}); err == nil {
		t.Fatal("carrier-backed native session accepted a caller-supplied frame block")
	}
	if _, err := registry.handlePacket(work.Handle, []byte{0}); err == nil {
		t.Fatal("carrier-backed native session accepted a caller-supplied encrypted packet")
	}
	if err := registry.close(work.Handle); err != nil {
		t.Fatal(err)
	}
	select {
	case <-time.After(time.Second):
		t.Fatal("relay duplex did not stop after native session close")
	case <-relayResult:
	}
}

func TestNativeSessionTerminalDuplexReleasesRegistrySlot(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	application := nativeTestApplication(t)
	adapter, err := client.NewPacketAdapter(application, client.PacketAdapterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	readCarrier, remoteWrite := io.Pipe()
	_, writeCarrier := io.Pipe()
	if err := remoteWrite.Close(); err != nil {
		t.Fatal(err)
	}
	packetContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	native := &nativeSession{
		context:      packetContext,
		cancel:       cancel,
		established:  &handshake.EstablishedSession{Application: application, ReadCarrier: readCarrier, WriteCarrier: writeCarrier},
		adapter:      adapter,
		localPackets: make(chan []byte, 1),
	}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 128)),
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return &nativeTestHandshake{}, nativeTestProofRequest(now), nil
		},
	})
	registry.sessions[1] = native
	for handle := uint64(2); handle <= maximumNativeSessions; handle++ {
		registry.sessions[handle] = &nativeSession{}
	}
	registry.next = maximumNativeSessions + 1

	waiter := make(chan error, 1)
	go func() {
		_, err := registry.nextLocalPacket(context.Background(), 1)
		waiter <- err
	}()
	select {
	case err := <-waiter:
		t.Fatalf("local packet wait returned before terminal duplex: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	duplexDone := make(chan struct{})
	go func() {
		registry.runNativeDuplex(1, native)
		close(duplexDone)
	}()
	select {
	case <-duplexDone:
	case <-time.After(time.Second):
		t.Fatal("terminal native duplex did not stop")
	}
	select {
	case err := <-waiter:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("local packet wait error = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("local packet wait did not observe terminal duplex")
	}
	if _, err := registry.nextLocalPacket(context.Background(), 1); !errors.Is(err, io.EOF) {
		t.Fatalf("late local packet wait error = %v, want io.EOF", err)
	}
	if _, err := registry.lookup(1); err == nil {
		t.Fatal("terminal native duplex retained its registry handle")
	}
	work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
	if err != nil {
		t.Fatalf("terminal native duplex did not release a session slot: %v", err)
	}
	if err := registry.close(work.Handle); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSessionLocalPacketWaitStopsWhenClosed(t *testing.T) {
	packetQueue := make(chan []byte, 1)
	ctx, cancel := context.WithCancel(context.Background())
	application := nativeTestApplication(t)
	defer application.Close()
	adapter, err := client.NewPacketAdapter(application, client.PacketAdapterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	session := &nativeSession{context: ctx, cancel: cancel, established: &handshake.EstablishedSession{Application: application}, adapter: adapter, localPackets: packetQueue}
	registry := &nativeSessionRegistry{sessions: map[uint64]*nativeSession{1: session}}
	result := make(chan error, 1)
	go func() {
		_, err := registry.nextLocalPacket(context.Background(), 1)
		result <- err
	}()
	select {
	case <-time.After(10 * time.Millisecond):
	case err := <-result:
		t.Fatalf("local packet wait returned before close: %v", err)
	}
	if err := registry.close(1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-time.After(time.Second):
		t.Fatal("local packet wait did not stop after close")
	case err := <-result:
		if err == nil {
			t.Fatal("local packet wait succeeded after close")
		}
	}
}

func TestNativeSessionCloseClosesPacketAdapter(t *testing.T) {
	application := nativeTestApplication(t)
	adapter, err := client.NewPacketAdapter(application, client.PacketAdapterOptions{})
	if err != nil {
		application.Close()
		t.Fatal(err)
	}
	registry := &nativeSessionRegistry{sessions: map[uint64]*nativeSession{
		1: {
			context:      context.Background(),
			cancel:       func() {},
			established:  &handshake.EstablishedSession{Application: application},
			adapter:      adapter,
			localPackets: make(chan []byte, 1),
		},
	}}
	if err := registry.close(1); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.NextEncryptedPacket(context.Background()); !errors.Is(err, client.ErrPacketAdapterClosed) {
		t.Fatalf("adapter after native session close = %v, want ErrPacketAdapterClosed", err)
	}
}

func TestNativeSessionCloseZeroesQueuedLocalPackets(t *testing.T) {
	application := nativeTestApplication(t)
	pending := []byte("queued native local packet")
	packetQueue := make(chan []byte, 1)
	packetQueue <- pending
	registry := &nativeSessionRegistry{sessions: map[uint64]*nativeSession{
		1: {
			context:      context.Background(),
			cancel:       func() {},
			established:  &handshake.EstablishedSession{Application: application},
			localPackets: packetQueue,
		},
	}}
	if err := registry.close(1); err != nil {
		t.Fatal(err)
	}
	for index, value := range pending {
		if value != 0 {
			t.Fatalf("queued local packet byte %d = %x after native session close, want zero", index, value)
		}
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

func TestNativeSessionDispatchAdaptsRawLocalPackets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	application := nativeTestApplication(t)
	stub := &nativeTestHandshake{session: &handshake.EstablishedSession{Application: application}}
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now:    func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{0x89}, 64)),
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
	defer registry.close(work.Handle)
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	if status, payload := dispatch(opCompleteNativeSession, nativeHandlePayload(t, work.Handle, server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)), 0); status != statusOK || len(payload) != 0 {
		t.Fatalf("complete dispatch = status %d payload %x", status, payload)
	}
	syn := nativeTCPv4([4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, 0x02, nil)
	status, payload := dispatch(opIngressLocalPacket, syn, work.Handle)
	if status != statusOK {
		t.Fatalf("raw packet ingress status = %d", status)
	}
	local := nativeLocalPacketList(t, payload)
	if len(local) != 1 || len(local[0]) < 34 || local[0][33] != 0x12 {
		t.Fatalf("raw packet ingress did not return a synthetic SYN/ACK: %x", local)
	}
	nativeSession, err := registry.lookup(work.Handle)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x45, 0x00, 0x00, 0x14}
	nativeSession.localPackets <- append([]byte(nil), want...)
	status, payload = dispatch(opNextLocalPacket, nil, work.Handle)
	if status != statusOK || !bytes.Equal(payload, want) {
		t.Fatalf("next local packet dispatch = status %d payload %x, want %x", status, payload, want)
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

func (h *nativeTestHandshake) completedValue() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.admission.TokenNonce) != 0
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

func nativePeerApplication(t *testing.T) *session.Application {
	t.Helper()
	application, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 7,
		HopLayer:        0,
		Write: session.DirectionConfig{
			Direction: 1,
			Secret:    bytes.Repeat([]byte{0x41}, 48),
			Key:       bytes.Repeat([]byte{0x42}, 32),
			IV:        bytes.Repeat([]byte{0x43}, 12),
		},
		Read: session.DirectionConfig{
			Direction: 0,
			Secret:    bytes.Repeat([]byte{0x31}, 48),
			Key:       bytes.Repeat([]byte{0x32}, 32),
			IV:        bytes.Repeat([]byte{0x33}, 12),
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

func nativeTCPv4(source, target [4]byte, sourcePort, targetPort uint16, sequence, acknowledgment uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], source[:])
	copy(packet[16:20], target[:])
	binary.BigEndian.PutUint16(packet[10:12], nativeChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], targetPort)
	binary.BigEndian.PutUint32(packet[24:28], sequence)
	binary.BigEndian.PutUint32(packet[28:32], acknowledgment)
	packet[32] = 0x50
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:36], 65535)
	copy(packet[40:], payload)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], target[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	binary.BigEndian.PutUint16(packet[36:38], nativeChecksum(pseudo, packet[20:]))
	return packet
}

func nativeChecksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd byte
	hasOdd := false
	for _, part := range parts {
		for _, value := range part {
			if !hasOdd {
				odd = value
				hasOdd = true
				continue
			}
			sum += uint32(odd)<<8 | uint32(value)
			hasOdd = false
		}
	}
	if hasOdd {
		sum += uint32(odd) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
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

func nativeLocalPacketList(t testing.TB, encoded []byte) [][]byte {
	t.Helper()
	reader := wire.NewReader(encoded)
	count := reader.ReadVarint()
	packets := make([][]byte, 0, count)
	for index := uint64(0); index < count; index++ {
		packets = append(packets, append([]byte(nil), reader.ReadOpaque24()...))
	}
	if reader.Err() != nil || !reader.EOF() {
		t.Fatalf("decode native local packet list: %v", reader.Err())
	}
	return packets
}
