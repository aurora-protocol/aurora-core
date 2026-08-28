//go:build cgo

// Concurrency regression coverage for the native session registry
// (session.go): the Swift/Android adapters call the ABI from multiple
// threads, so an in-flight issuer completion or any packet-path operation can
// race a close of the same handle. These tests pin the interleavings that
// TestNativeSessionRegistryConcurrentLifecycle (begin/close only) does not
// reach:
//
//   - complete × close: whatever the ordering, the handle must end forgotten
//     and the pending handshake must be closed exactly once (a successful
//     Complete marks the handshake closed itself; a cancelled one is closed
//     by session.close).
//   - queueFrameBlock / nextPacket / handlePacket / ingressLocalPacket /
//     nextLocalPacket × close: every call must resolve without a panic or
//     deadlock, and the handle must be forgotten afterwards.
//
// Iteration counts are sized for CI: large enough for the race detector to
// observe both orderings, small enough to stay far under the C harness
// watchdogs.

package main

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/server"
)

// nativeBlockingHandshake blocks in Complete until released or the context is
// cancelled, so a test can interleave close() with an in-flight completion.
// It mirrors the real ClientHandshake contract: a successful Complete marks
// the handshake closed and transfers the established session to the caller,
// after which the registry nils session.handshake and close() must not
// re-close it.
type nativeBlockingHandshake struct {
	release chan struct{}
	session *handshake.EstablishedSession

	mu     sync.Mutex
	closed bool
}

func (h *nativeBlockingHandshake) Complete(ctx context.Context, _ protocol.AdmissionProof, _ protocol.ReplayProof) (*handshake.EstablishedSession, error) {
	select {
	case <-h.release:
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
		return h.session, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *nativeBlockingHandshake) Close() error {
	h.mu.Lock()
	h.closed = true
	select {
	case <-h.release:
	default:
		close(h.release)
	}
	h.mu.Unlock()
	return nil
}

func (h *nativeBlockingHandshake) closedValue() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func nativeConcurrencyIssuerResponse(t *testing.T, now time.Time) []byte {
	t.Helper()
	proof := nativeTestAdmissionProof(now, nativeTestProofRequest(now).AdmissionContextHash)
	encodedProof, err := protocol.Encode(proof)
	if err != nil {
		t.Fatal(err)
	}
	return server.EncodeCarrier(server.CarrierBlindRSAIssueResp, encodedProof)
}

func TestNativeSessionCompletionRacesClose(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for iteration := 0; iteration < 32; iteration++ {
		stub := &nativeBlockingHandshake{
			release: make(chan struct{}),
			session: &handshake.EstablishedSession{Application: nativeTestApplication(t)},
		}
		registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 256)),
			start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
				return stub, nativeTestProofRequest(now), nil
			},
		})
		work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
		if err != nil {
			t.Fatal(err)
		}
		response := nativeConcurrencyIssuerResponse(t, now)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			_ = registry.complete(work.Handle, response)
		}()
		go func() {
			defer wait.Done()
			if iteration%2 == 0 {
				close(stub.release) // let the completion win half the time
			}
			_ = registry.close(work.Handle)
		}()
		wait.Wait()
		if _, err := registry.lookup(work.Handle); err == nil {
			t.Fatalf("iteration %d: handle survived the complete/close race", iteration)
		}
		if !stub.closedValue() {
			t.Fatalf("iteration %d: pending handshake leaked after the complete/close race", iteration)
		}
	}
}

func TestNativeSessionPacketOperationsRaceClose(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	frame, err := protocol.NewStreamDataFrame(1, []byte("payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	encodedBlock, err := protocol.Encode(protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
	if err != nil {
		t.Fatal(err)
	}
	udp := nativeUDPv4([4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, []byte("data"))
	for iteration := 0; iteration < 24; iteration++ {
		stub := &nativeTestHandshake{session: &handshake.EstablishedSession{Application: nativeTestApplication(t)}}
		registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
			now:    func() time.Time { return now },
			random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 256)),
			start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
				return stub, nativeTestProofRequest(now), nil
			},
		})
		work, err := registry.begin(client.NativeProvisioning{IssuerURL: "https://issuer.example", IssuerCarrierPath: "/assets/issue/42"})
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.complete(work.Handle, nativeConcurrencyIssuerResponse(t, now)); err != nil {
			t.Fatal(err)
		}
		var wait sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			wait.Add(1)
			go func(worker int) {
				defer wait.Done()
				for call := 0; call < 6; call++ {
					switch worker {
					case 0:
						_ = registry.queueFrameBlock(work.Handle, encodedBlock)
						_, _ = registry.nextPacket(work.Handle)
					case 1:
						_, _ = registry.handlePacket(work.Handle, []byte{0x01, 0x02, 0x03})
					case 2:
						_, _ = registry.ingressLocalPacket(work.Handle, udp)
					case 3:
						// Watchdog only: close() must unblock the wait long
						// before this deadline.
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						_, _ = registry.nextLocalPacket(ctx, work.Handle)
						cancel()
					}
				}
			}(worker)
		}
		_ = registry.close(work.Handle)
		wait.Wait()
		if _, err := registry.lookup(work.Handle); err == nil {
			t.Fatalf("iteration %d: handle survived close", iteration)
		}
		if err := registry.queueFrameBlock(work.Handle, encodedBlock); err == nil {
			t.Fatalf("iteration %d: closed handle accepted a frame block", iteration)
		}
	}
}
