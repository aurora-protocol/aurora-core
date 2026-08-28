package client

// Adversarial white-box coverage for four count-0 nil-safety guards in the
// client package: two nil-application guards in the packet adapter, a
// nil-mapping guard in the relay-close handler, and a nil-second-argument
// guard in the provisioned-close error combiner.
//
//   - packet_adapter.go:375 (*PacketAdapter).NextEncryptedPacket
//     application == nil -> "client: packet adapter application is unavailable"
//     (fires after the nil-receiver guard at :365 and the closed guard at :369,
//     before the application.NextPacket call at :378).
//   - packet_adapter.go:400 (*PacketAdapter).HandleEncryptedPacket
//     application == nil -> "client: packet adapter application is unavailable"
//     (fires after the nil-receiver guard at :383, the ctx == nil guard at :386,
//     the now validity guard at :389, and the closed guard at :393, before the
//     application.NextPackets call).
//   - packet_adapter.go:832 (*PacketAdapter).handleRelayCloseLocked
//     mapping == nil -> "client: packet adapter received close for unknown flow"
//     (first statement; fires before the wire.NewReader / DecodeFlowClose
//     payload decode at :837, so the frame payload is never read).
//   - provisioned_session.go:535 combineProvisionedCloseErrors
//     second == nil -> return first (fires after the first == nil guard at
//     :532, before the combined error formatting at :538).
//
// The existing client tests drive the packet adapter only on an activated
// adapter (application wired up, flowsByID populated), so the nil-application
// and nil-mapping branches stayed count-0 even though each is plainly reachable
// on a zero-value PacketAdapter. combineProvisionedCloseErrors is exercised
// only on the first == nil path (:532 is covered) and never with a non-nil
// first and nil second, so :535 (both its condition and body) stayed count-0.
//
// Proof technique:
//
//   - NextEncryptedPacket / HandleEncryptedPacket (nil-field clean return): a
//     zero-value &PacketAdapter{} has a usable zero-value mutex, closed == false,
//     and application == nil. The nil-receiver guards at :365 / :383 are false
//     (a is non-nil), the closed guards at :369 / :393 are false, and (for
//     HandleEncryptedPacket) the ctx == nil guard at :386 is false (a real
//     context.Background is passed, so no SA1012 surface) and the now validity
//     guard at :389 is false (time.Now is non-zero), so the nil-application
//     guard at :375 / :400 fires and returns "packet adapter application is
//     unavailable" before the application is invoked. The non-nil receiver, the
//     real context / valid time, and the not-closed state uniquely identify
//     :375 / :400 as the source (the nil-receiver and closed guards return
//     different paths and are not reached). No network, no goroutine.
//
//   - handleRelayCloseLocked (nil-field clean return): a zero-value
//     &PacketAdapter{} has flowsByID == nil; reading a nil map
//     (a.flowsByID[frame.FlowID]) is a well-defined no-op that returns the zero
//     value (nil), so mapping is nil and :834 returns "received close for
//     unknown flow" before the payload is decoded. The "unknown flow" message
//     is unique to :835. The frame payload is never read, so an empty frame
//     suffices. handleRelayCloseLocked is an unexported "Locked"-suffix method
//     (caller holds the mutex) but does not acquire the lock itself, so calling
//     it directly in a single-goroutine test is safe (no deadlock, no race).
//
//   - combineProvisionedCloseErrors (nil-argument clean return): pass a non-nil
//     sentinel as first (so the :532 first == nil guard is false and skipped)
//     and nil as second. The :535 second == nil guard returns first, so the
//     result is the sentinel; errors.Is(result, sentinel) proves the :535 body
//     ran. Pure (no IO).
//
// None of the exercised guards is a ctx == nil guard (the ctx == nil guards at
// packet_adapter.go:286/386/420 are not triggered — a real context.Background
// is passed), so there is no SA1012 surface. In-package (package client) because
// handleRelayCloseLocked and combineProvisionedCloseErrors are unexported.
//
// This test file adds only TestXxx entry points and references existing
// exported (PacketAdapter, NextEncryptedPacket, HandleEncryptedPacket) and
// unexported in-package (handleRelayCloseLocked, combineProvisionedCloseErrors)
// symbols plus the exported protocol.AuroraFrame type, so it adds no U1000
// surface.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestPacketAdapterNextEncryptedPacketNilApplicationGuard(t *testing.T) {
	// 375: a zero-value PacketAdapter is non-nil (skips :365), not closed
	// (skips :369), and has application == nil, so :375 fires and returns
	// "application is unavailable" before application.NextPacket at :378.
	a := &PacketAdapter{}
	_, err := a.NextEncryptedPacket(context.Background())
	if err == nil {
		t.Fatal("NextEncryptedPacket(zero-value adapter) err = nil, want non-nil (:375 should reject nil application)")
	} else if !strings.Contains(err.Error(), "packet adapter application is unavailable") {
		t.Fatalf("NextEncryptedPacket err = %q, want substring \"packet adapter application is unavailable\" (:375)", err.Error())
	}
}

func TestPacketAdapterHandleEncryptedPacketNilApplicationGuard(t *testing.T) {
	// 400: a zero-value PacketAdapter is non-nil (skips :383), a real
	// context.Background is non-nil (skips :386, no SA1012), time.Now is valid
	// (skips :389), not closed (skips :393), and application == nil, so :400
	// fires before application.NextPackets. The encoded payload is nil and is
	// never decoded (the guard returns first).
	a := &PacketAdapter{}
	_, err := a.HandleEncryptedPacket(context.Background(), nil, time.Now())
	if err == nil {
		t.Fatal("HandleEncryptedPacket(zero-value adapter) err = nil, want non-nil (:400 should reject nil application)")
	} else if !strings.Contains(err.Error(), "packet adapter application is unavailable") {
		t.Fatalf("HandleEncryptedPacket err = %q, want substring \"packet adapter application is unavailable\" (:400)", err.Error())
	}
}

func TestPacketAdapterHandleRelayCloseLockedNilMappingGuard(t *testing.T) {
	// 834: a zero-value PacketAdapter has flowsByID == nil; reading the nil map
	// returns nil, so mapping == nil and :834 returns "unknown flow" before the
	// payload is decoded at :837. The frame payload is never read. Calling the
	// "Locked" method directly is safe: it does not acquire the mutex and the
	// test is single-goroutine.
	a := &PacketAdapter{}
	_, err := a.handleRelayCloseLocked(protocol.AuroraFrame{FlowID: 1}, time.Now())
	if err == nil {
		t.Fatal("handleRelayCloseLocked(zero-value adapter) err = nil, want non-nil (:834 should reject nil mapping)")
	} else if !strings.Contains(err.Error(), "received close for unknown flow") {
		t.Fatalf("handleRelayCloseLocked err = %q, want substring \"received close for unknown flow\" (:834)", err.Error())
	}
}

func TestCombineProvisionedCloseErrorsNilSecondGuard(t *testing.T) {
	// 535: a non-nil first (skips :532) and a nil second trips :535, which
	// returns first. The result is the sentinel; errors.Is proves :535 ran.
	sentinel := errors.New("client-test: first close error")
	got := combineProvisionedCloseErrors(sentinel, nil)
	if !errors.Is(got, sentinel) {
		t.Fatalf("combineProvisionedCloseErrors(sentinel, nil) = %v, want sentinel (:535 should return first when second is nil)", got)
	}
}
