package handshake

// Adversarial white-box coverage for the uncovered branches of
// handshake/session.go. session.go holds two single-goroutine state machines:
// ClientSession (a State field advanced through the cover-prelude handshake)
// and RelaySession (an admission replay cache plus a CoverPrelude0 acceptance
// routine). Neither machine performs cryptography on the covered paths and
// neither touches the network or filesystem; every time-dependent decision in
// the relay path takes an explicit nowUnix argument (the wrapper
// AcceptCoverPrelude0 passes 0,0), so the machines are fully deterministic.
// The uncovered branches are the out-of-order state-precondition guards on the
// ClientSession transitions, the default-cache branch of NewRelaySession, and
// the structural-validation gate on AcceptCoverPrelude0At that fires BEFORE the
// admission check.
//
// Targets covered:
//
//   - ClientSession.MarkDescriptorLoaded:37-39 — the wrong-state guard. The
//     existing suite only calls MarkDescriptorLoaded once from the initial
//     state, so the "cannot load descriptor from state N" return is unreached.
//     Calling it again after a successful transition (state is now
//     StateOpenCover) hits the guard.
//   - ClientSession.MarkCoverOpened:45-47 — the wrong-state guard. The existing
//     suite drives MarkCoverOpened only after loading the descriptor, so the
//     "cannot open cover from state 0" return is unreached. A fresh session is
//     still in StateLoadDescriptor.
//   - ClientSession.MarkCoverPrelude0Sent:53-55 — the wrong-state guard. The
//     existing suite reaches it only after opening the cover, so the "cannot
//     send CoverPrelude0 from state 0" return is unreached. A fresh session is
//     still in StateLoadDescriptor.
//   - ClientSession.VerifyCoverPrelude1:61-63 — the wrong-state guard, which
//     fires BEFORE VerifyCoverPrelude1Signatures at 64. The existing suite
//     verifies only after sending CoverPrelude0, so the "cannot verify
//     CoverPrelude1 from state 0" return is unreached. A fresh session is still
//     in StateLoadDescriptor, so the guard returns before any signature
//     verification runs (the zero CoverPreludeVerificationInput is never
//     inspected).
//   - ClientSession.VerifyCoverCapsule2:82-84 — the wrong-state guard, which
//     fires BEFORE c.ValidateStructural at 85. The existing suite verifies only
//     after building CoverCapsule1, so the "cannot verify CoverCapsule2 from
//     state 0" return is unreached. A fresh session is still in
//     StateLoadDescriptor, so the guard returns before any capsule validation
//     runs (the zero CoverCapsule2Plain is never inspected).
//   - NewRelaySession:102-103 — the `hintCache == nil` default-cache branch. The
//     existing suite always constructs a RelaySession with an explicit cache,
//     so the default MemoryReplayCache allocation is unreached. A nil cache
//     triggers it; the returned session is non-nil and usable.
//   - RelaySession.AcceptCoverPrelude0At:113-115 — the
//     CoverPrelude0.ValidateStructural gate, which fires BEFORE
//     ValidatePrelude0ClientHybridShares at 116 and the admission check at 119.
//     The existing suite drives acceptance with a well-formed CoverPrelude0, so
//     the structural-failure propagation is unreached. A zero CoverPrelude0
//     has MsgType 0, but registry.MsgCoverPrelude0 is 0x0101, so
//     ValidateStructural (protocol/bootstrap.go:73) rejects it with "malformed
//     CoverPrelude0 message type 0x0" and the relay surfaces the error before
//     the hybrid-share and admission paths run.
//
// No new package-level helpers or types are introduced (only test functions and
// inline zero-value structs), so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no cryptography, no real
// network or filesystem.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestHandshakeClientSessionRejectsOutOfOrderStateTransitions(t *testing.T) {
	// A fresh session is in StateLoadDescriptor (0). Every transition below
	// requires a later state, so each wrong-state guard fires BEFORE any
	// signature/capsule validation runs; the state is unchanged by a failed
	// transition, so the session stays in StateLoadDescriptor throughout.
	s := NewClientSession()

	// 45-47: MarkCoverOpened needs StateOpenCover (1).
	if err := s.MarkCoverOpened(); err == nil ||
		!strings.Contains(err.Error(), "cannot open cover from state 0") {
		t.Fatalf("MarkCoverOpened(LoadDescriptor) err = %v, want substring \"cannot open cover from state 0\"", err)
	}
	// 53-55: MarkCoverPrelude0Sent needs StateSendCoverPrelude0 (2).
	if err := s.MarkCoverPrelude0Sent(); err == nil ||
		!strings.Contains(err.Error(), "cannot send CoverPrelude0 from state 0") {
		t.Fatalf("MarkCoverPrelude0Sent(LoadDescriptor) err = %v, want substring \"cannot send CoverPrelude0 from state 0\"", err)
	}
	// 61-63: VerifyCoverPrelude1 needs StateVerifyCoverPrelude1 (3); the guard
	// fires before VerifyCoverPrelude1Signatures, so the zero input is safe.
	if _, err := s.VerifyCoverPrelude1(CoverPreludeVerificationInput{}); err == nil ||
		!strings.Contains(err.Error(), "cannot verify CoverPrelude1 from state 0") {
		t.Fatalf("VerifyCoverPrelude1(LoadDescriptor) err = %v, want substring \"cannot verify CoverPrelude1 from state 0\"", err)
	}
	// 82-84: VerifyCoverCapsule2 needs StateVerifyCoverCapsule2 (5); the guard
	// fires before c.ValidateStructural, so the zero capsule is safe.
	if err := s.VerifyCoverCapsule2(protocol.CoverCapsule2Plain{}, nil); err == nil ||
		!strings.Contains(err.Error(), "cannot verify CoverCapsule2 from state 0") {
		t.Fatalf("VerifyCoverCapsule2(LoadDescriptor) err = %v, want substring \"cannot verify CoverCapsule2 from state 0\"", err)
	}

	// 37-39: a successful MarkDescriptorLoaded advances to StateOpenCover (1),
	// so a second call hits the wrong-state guard from that later state. This
	// anchors the MarkDescriptorLoaded guard independently of the initial state.
	if err := s.MarkDescriptorLoaded(); err != nil {
		t.Fatalf("MarkDescriptorLoaded(first) err = %v, want nil", err)
	}
	if s.State() != StateOpenCover {
		t.Fatalf("State() = %d, want StateOpenCover after first MarkDescriptorLoaded", s.State())
	}
	if err := s.MarkDescriptorLoaded(); err == nil ||
		!strings.Contains(err.Error(), "cannot load descriptor from state 1") {
		t.Fatalf("MarkDescriptorLoaded(OpenCover) err = %v, want substring \"cannot load descriptor from state 1\"", err)
	}
}

func TestRelaySessionAcceptCoverPrelude0RejectsMalformedStructural(t *testing.T) {
	// 102-103: a nil hintCache is replaced by a fresh in-memory
	// MemoryReplayCache, so NewRelaySession(nil) returns a usable session
	// instead of a nil cache. (The default-cache allocation is the coverage
	// target; the assertion anchors that the session is non-nil and ready.)
	s := NewRelaySession(nil)
	if s == nil {
		t.Fatal("NewRelaySession(nil) = nil, want non-nil session with default cache")
	}

	// 113-115: a zero CoverPrelude0 has MsgType 0, but registry.MsgCoverPrelude0
	// is 0x0101, so ValidateStructural (protocol/bootstrap.go:73) rejects it with
	// "malformed CoverPrelude0 message type 0x0" and AcceptCoverPrelude0At
	// surfaces the error BEFORE ValidatePrelude0ClientHybridShares (116) and the
	// admission check (119) run. The remaining arguments are therefore never
	// inspected, so zero values are safe.
	_, err := s.AcceptCoverPrelude0(
		protocol.CoverPrelude0{},
		admission.AccessHintCredential{},
		nil,
		protocol.CoverPrelude1{},
	)
	if err == nil ||
		!strings.Contains(err.Error(), "malformed CoverPrelude0 message type 0x0") {
		t.Fatalf("AcceptCoverPrelude0(zero p0) err = %v, want substring \"malformed CoverPrelude0 message type 0x0\"", err)
	}
}
