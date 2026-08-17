//go:build cgo

package main

// Adversarial white-box coverage for the remaining count-0 first-statement
// nil-receiver safety guards on *nativeSessionRegistry / *nativeSession in
// mobile/auroracore/session.go. A sibling file (session_registry_nil_safety_
// branch_coverage_test.go) already covered begin (:119), finishDuplex (:604),
// localPacketTerminationError (:628) and (*nativeSession).close (:714). These
// seven were left count-0 — six *nativeSessionRegistry methods plus the
// (*nativeSession).enqueueLocalPacket nil-receiver guard — because the existing
// mobile tests only ever drive a populated registry / live native session along
// the native path. Each guard returns at its very first statement, before any
// field is dereferenced (r.mu, s.localPacketMu, session.mu, s.established) or any
// helper is called, so a nil receiver is safe and the guard is plainly reachable.
//
//   - :362 (*nativeSessionRegistry).close(handle uint64) error
//     r == nil || handle == 0 -> "auroracore: native session handle is invalid"
//   - :378 (*nativeSessionRegistry).expire(handle uint64, want *nativeSession)
//     r == nil || handle == 0 || want == nil -> no-op return (void)
//   - :533 (*nativeSessionRegistry).runNativeDuplex(handle uint64, session *nativeSession)
//     r == nil || session == nil -> no-op return (void)
//   - :562 (*nativeSessionRegistry).finishNativeDuplex(handle uint64, session *nativeSession, err error)
//     r == nil || handle == 0 || session == nil -> no-op return (void)
//   - :577 (*nativeSession).enqueueLocalPacket(ctx context.Context, packet []byte) error
//     s == nil || ctx == nil || len(packet)==0 || len>max -> "auroracore: native local packet is invalid"
//   - :640 (*nativeSessionRegistry).lookup(handle uint64) (*nativeSession, error)
//     r == nil || handle == 0 -> (nil, "auroracore: native session handle is invalid")
//   - :653 (*nativeSessionRegistry).terminalLocalPacketError(handle uint64) error
//     r == nil || handle == 0 -> nil
//
// These are nil-RECEIVER first-statement guards. None pass a nil context (a real
// context.Background() is supplied to enqueueLocalPacket and short-circuited by
// the s==nil condition before it is read), so there is no SA1012 surface. No
// network, no goroutine, no cgo call, no native session handles — each guard
// returns before any mutex / registry / session-field access, so this test
// cannot trigger the TestNativeSessionFFIStopsOnCarrierCancellation
// handle-lifecycle flake. In-package (package main, //go:build cgo) matching the
// existing mobile test-file convention. This file adds only TestXxx entry points
// and uses existing unexported in-package symbols + stdlib strings/testing and
// the context/session/client packages already imported by the sibling file, so
// it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
)

func TestNativeSessionRegistryMethodNilReceiverGuards(t *testing.T) {
	// 362/378/533/562/640/653: a nil *nativeSessionRegistry returns at the first
	// statement of close / expire / runNativeDuplex / finishNativeDuplex / lookup
	// / terminalLocalPacketError rather than dereferencing r.mu. handle==0 alone
	// would also fire close/lookup/terminalLocalPacketError, but a nil receiver
	// fires first (short-circuit) and exercises the same guard body.
	var r *nativeSessionRegistry

	// 362: close returns the "handle is invalid" error; r==nil fires first.
	if err := r.close(0); err == nil {
		t.Fatal("nil.close(0) err = nil, want non-nil (:362 should reject)")
	} else if !strings.Contains(err.Error(), "handle is invalid") {
		t.Fatalf("nil.close(0) err = %q, want substring \"handle is invalid\" (:362)", err.Error())
	}

	// 378: expire is void; the r==nil guard fires before r.mu.Lock. No-panic proof.
	r.expire(0, nil)

	// 533: runNativeDuplex is void; the r==nil guard fires before session.mu.Lock.
	// No-panic proof.
	r.runNativeDuplex(0, nil)

	// 562: finishNativeDuplex is void; the r==nil guard fires before
	// session.finishDuplex. No-panic proof.
	r.finishNativeDuplex(0, nil, nil)

	// 640: lookup returns (nil, "handle is invalid"); r==nil fires first.
	if session, err := r.lookup(0); err == nil {
		t.Fatal("nil.lookup(0) err = nil, want non-nil (:640 should reject)")
	} else if session != nil {
		t.Fatalf("nil.lookup(0) session = %v, want nil (:640)", session)
	} else if !strings.Contains(err.Error(), "handle is invalid") {
		t.Fatalf("nil.lookup(0) err = %q, want substring \"handle is invalid\" (:640)", err.Error())
	}

	// 653: terminalLocalPacketError returns nil; the r==nil guard fires before
	// r.mu.Lock. The nil return distinguishes the nil-receiver path from a
	// populated registry that would consult its terminal error state.
	if err := r.terminalLocalPacketError(0); err != nil {
		t.Fatalf("nil.terminalLocalPacketError(0) err = %v, want nil (:653)", err)
	}
}

func TestNativeSessionEnqueueLocalPacketNilReceiverGuard(t *testing.T) {
	// 577: a nil *nativeSession returns at the first statement of
	// enqueueLocalPacket rather than dereferencing s.localPacketMu. The s==nil
	// condition short-circuits before ctx / packet are read, so a real
	// context.Background() and a non-empty packet are safe to pass (no SA1012
	// surface — no nil context literal). The shared guard body returns
	// "native local packet is invalid".
	var s *nativeSession
	if err := s.enqueueLocalPacket(context.Background(), []byte{0x41}); err == nil {
		t.Fatal("nil.enqueueLocalPacket(...) err = nil, want non-nil (:577 should reject)")
	} else if !strings.Contains(err.Error(), "native local packet is invalid") {
		t.Fatalf("nil.enqueueLocalPacket(...) err = %q, want substring \"native local packet is invalid\" (:577)", err.Error())
	}
}
