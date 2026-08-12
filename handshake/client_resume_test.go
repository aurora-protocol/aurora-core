package handshake

import (
	"context"
	"testing"
	"time"
)

func TestClientHandshakeDefersCapsuleUntilProofsArrive(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}

	handshake, request, err := driver.Begin(context.Background(), opener)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	t.Cleanup(func() { _ = handshake.Close() })
	if len(request.AdmissionContextHash) != 48 {
		t.Fatalf("admission context length = %d, want 48", len(request.AdmissionContextHash))
	}
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client opener did not retain carrier")
	}
	if len(carrier.writes) != 1 {
		t.Fatalf("bootstrap records before proofs = %d, want 1", len(carrier.writes))
	}
	if provider.calls.Load() != 0 {
		t.Fatalf("proof provider calls before request use = %d, want 0", provider.calls.Load())
	}
	if carrier.streamRequests.Load() != 0 {
		t.Fatalf("application stream requests before proofs = %d, want 0", carrier.streamRequests.Load())
	}

	proof, replay, err := provider.BuildProofs(context.Background(), request)
	if err != nil {
		t.Fatalf("build client proofs: %v", err)
	}
	established, err := handshake.Complete(context.Background(), proof, replay)
	if err != nil {
		t.Fatalf("complete client handshake: %v", err)
	}
	t.Cleanup(func() { _ = established.Close() })
	if len(carrier.writes) != 2 {
		t.Fatalf("bootstrap records after proofs = %d, want 2", len(carrier.writes))
	}
	if carrier.streamRequests.Load() != 1 {
		t.Fatalf("application stream requests after proofs = %d, want 1", carrier.streamRequests.Load())
	}
}

func TestClientHandshakeCloseCancelsPendingProofRequest(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, _, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}

	handshake, _, err := driver.Begin(context.Background(), opener)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	if err := handshake.Close(); err != nil {
		t.Fatalf("close pending client handshake: %v", err)
	}
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client opener did not retain carrier")
	}
	if carrier.closes.Load() != 1 {
		t.Fatalf("carrier closes = %d, want 1", carrier.closes.Load())
	}
	if _, _, err := driver.Begin(context.Background(), opener); err == nil {
		t.Fatal("client reused access hint after closing a sent Prelude0")
	}
	if opener.lastCarrier() != carrier {
		t.Fatal("client reopened a carrier after exhausting the access hint")
	}
}

func TestClientHandshakeRejectsSecondCompletionWithoutAnotherCapsule(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}

	handshake, request, err := driver.Begin(context.Background(), opener)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	proof, replay, err := provider.BuildProofs(context.Background(), request)
	if err != nil {
		t.Fatalf("build client proofs: %v", err)
	}
	wantAuthenticator := append([]byte(nil), proof.TokenAuthenticator...)
	wantReplayNonce := append([]byte(nil), replay.ClientReplayNonce...)
	established, err := handshake.Complete(context.Background(), proof, replay)
	if err != nil {
		t.Fatalf("complete client handshake: %v", err)
	}
	t.Cleanup(func() { _ = established.Close() })
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client opener did not retain carrier")
	}
	if _, err := handshake.Complete(context.Background(), proof, replay); err == nil {
		t.Fatal("second client handshake completion succeeded")
	}
	if len(carrier.writes) != 2 {
		t.Fatalf("bootstrap records after second completion = %d, want 2", len(carrier.writes))
	}
	if string(proof.TokenAuthenticator) != string(wantAuthenticator) || string(replay.ClientReplayNonce) != string(wantReplayNonce) {
		t.Fatal("client handshake completion modified caller-owned proof material")
	}
}

func TestClientHandshakeRejectsInvalidProofBeforeCapsuleWrite(t *testing.T) {
	now := time.Now()
	fixture := newTestVerifiedDeploymentFixture(t, now)
	config, provider, driver := newClientDriverTestSetup(t, now, fixture, nil)
	opener := &scriptedClientOpener{fixture: fixture, config: config}

	handshake, request, err := driver.Begin(context.Background(), opener)
	if err != nil {
		t.Fatalf("begin client handshake: %v", err)
	}
	proof, replay, err := provider.BuildProofs(context.Background(), request)
	if err != nil {
		t.Fatalf("build client proofs: %v", err)
	}
	proof.RedemptionContextHash[0] ^= 0xff
	if established, err := handshake.Complete(context.Background(), proof, replay); err == nil || established != nil {
		if established != nil {
			_ = established.Close()
		}
		t.Fatal("invalid client proof completed handshake")
	}
	carrier := opener.lastCarrier()
	if carrier == nil {
		t.Fatal("client opener did not retain carrier")
	}
	if len(carrier.writes) != 1 {
		t.Fatalf("bootstrap records after invalid proof = %d, want 1", len(carrier.writes))
	}
}
