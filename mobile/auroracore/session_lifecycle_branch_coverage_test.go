//go:build cgo

package main

// Adversarial white-box coverage for three count-0 lifecycle guards in
// mobile/auroracore/session.go that the existing mobile tests leave at 0
// because they only drive the populated-registry / happy-path native flow:
//
//   - :146 if deferred == nil  (inside begin, the err == nil path)
//     -> the injected nativeSessionStarter returned (nil, request, nil): a nil
//        handshake with NO error is a contract violation
//        ("native session starter returned no handshake").
//   - :541 if packetContext == nil || established == nil || adapter == nil
//     (runNativeDuplex) -> the session lacks the carrier streams / adapter
//        needed to pump packets, so it is routed to finishNativeDuplex with
//        "native duplex is unavailable" instead of entering RunPacketDuplex.
//   - :612 if err == nil  (finishDuplex)
//     -> the duplex pump stopped with no error (a clean EOF); the nil err is
//        replaced with "native duplex stopped unexpectedly" so pumpErr is never
//        left empty for localPacketTerminationError to misreport.
//
// Coverage targets (baseline measured on main; all three bodies COUNT 0 while
// their conditions were already evaluated):
//   - session.go:146.21,150.3 0
//   - session.go:541.66,544.3 0
//   - session.go:612.16,614.3 0
//
// Three sibling count-0 guards are deliberately NOT covered here:
//   - :132 (timeout-fired + deferred != nil) needs the starter to block until
//     the 30s nativeSessionHandshakeTimeout timer fires — a 30s wall-clock test,
//     race/timing dependent; deferred like the :198 SKIP in the prior session.
//   - :259 / :268 / :269 / :290 / :313 (complete) all sit behind
//     proofsForIssuerResponse succeeding (server.DecodeCarrier of a BlindRSA
//     issuer response), which requires real issuer-response crypto material the
//     in-process harness does not build; deferred to a crypto-harness vein.
//
// Proof (in-process, no crypto / network / 30s timer):
//   - :146 — newNativeSessionRegistry with a custom start that returns
//     (nil, handshake.ClientProofRequest{}, nil); begin reaches :146 (deferred
//     == nil) before issueWork is ever called, so the provisioning fields are
//     irrelevant. The r.start seam (nativeSessionStarter, session.go:42/:60) is
//     the established injection point used by session_test.go.
//   - :541 — a zero-value &nativeSession{} (nil context / established / adapter)
//     passed directly to runNativeDuplex(handle, session). The :533
//     r == nil || session == nil guard passes (real registry, non-nil session),
//     :537-539 read the nil fields under session.mu, and :541 fires. No map
//     injection is needed — runNativeDuplex takes the session explicitly.
//   - :612 — finishNativeDuplex(handle, session, nil) (the duplex-completion
//     path runNativeDuplex uses at :558) calls finishDuplex(nil); the :612
//     err == nil guard fires and replaces nil with the unexpected-stop error.
//   - Both :541 and :612 leave the error in pumpErr, surfaced afterwards via
//     session.localPacketTerminationError() (reads pumpErr under session.mu).
//     finishNativeDuplex then calls session.close() (:573), which is zero-value
//     safe (nil receiver guard at :714; nil cancel / handshake / established /
//     adapter / localPackets all skipped; zeroNativeLocalPacketQueue(nil) is a
//     nil-channel select-with-default no-op).
//
// These are plain Go methods on *nativeSessionRegistry / *nativeSession (NOT
// //export cgo wrappers — the cgo exports live in auroracore.go), so they run
// in-process under `go test ./mobile/auroracore/`. No network, no goroutine, no
// cgo call, no native session handles — each path returns before
// transport.RunPacketDuplex / issueWork, so this cannot trigger the
// TestNativeSessionFFIStopsOnCarrierCancellation handle-lifecycle flake. No
// nil-context literal is passed (the start seam receives the registry's own
// context.Background()-derived sessionContext; :146 fires before it is read) ->
// no SA1012 surface. In-package (package main, //go:build cgo) because
// newNativeSessionRegistry, nativeSessionRegistryOptions, nativeSession,
// nativeSessionHandshake, runNativeDuplex, finishNativeDuplex and
// localPacketTerminationError are all unexported. This file adds only TestXxx
// entry points and references existing in-package symbols + stdlib
// context/strings/testing/time and the client/handshake packages already
// imported by session_test.go, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
)

func TestNativeSessionBeginRejectsStarterReturningNoHandshake(t *testing.T) {
	// :146 deferred == nil (the err == nil path of begin): the injected starter
	// returns (nil, request, nil) — a nil handshake with no error. begin reaches
	// :146 before issueWork (:154) is ever called, so the provisioning fields are
	// irrelevant; the only requirement is a valid now so the :124 guard passes.
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{
		now: func() time.Time { return time.Unix(1700000000, 0) },
		start: func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
			return nil, handshake.ClientProofRequest{}, nil
		},
	})
	_, err := registry.begin(client.NativeProvisioning{
		IssuerURL:         "https://issuer.example",
		IssuerCarrierPath: "/assets/app.bin",
	})
	if err == nil {
		t.Fatal("begin err = nil, want non-nil (:146 should reject a nil deferred handshake)")
	}
	if !strings.Contains(err.Error(), "no handshake") {
		t.Fatalf("begin err = %q, want substring \"no handshake\" (:146)", err.Error())
	}
}

func TestNativeSessionRunNativeDuplexRejectsNilContextEstablishedAdapter(t *testing.T) {
	// :541 packetContext == nil || established == nil || adapter == nil: a
	// zero-value nativeSession has all three nil. runNativeDuplex reads them
	// under session.mu (:537-539), the :541 guard fires, and the session is routed
	// to finishNativeDuplex with "native duplex is unavailable" instead of entering
	// transport.RunPacketDuplex. The error is recorded in pumpErr and surfaced via
	// localPacketTerminationError. No map injection needed — runNativeDuplex takes
	// the session explicitly.
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{})
	session := &nativeSession{}
	registry.runNativeDuplex(1, session)
	err := session.localPacketTerminationError()
	if err == nil {
		t.Fatal("localPacketTerminationError = nil, want the :541 duplex-unavailable error recorded in pumpErr")
	}
	if !strings.Contains(err.Error(), "duplex is unavailable") {
		t.Fatalf("localPacketTerminationError = %q, want substring \"duplex is unavailable\" (:541)", err.Error())
	}
}

func TestNativeSessionFinishDuplexNilErrBecomesUnexpectedStop(t *testing.T) {
	// :612 err == nil (finishDuplex): the duplex pump stopped with no error (a
	// clean EOF). finishNativeDuplex(handle, session, nil) — the completion path
	// runNativeDuplex uses at :558 — calls finishDuplex(nil); the :612 guard fires
	// and replaces the nil err with "native duplex stopped unexpectedly" so pumpErr
	// is never empty for localPacketTerminationError to misreport.
	registry := newNativeSessionRegistry(nativeSessionRegistryOptions{})
	session := &nativeSession{}
	registry.finishNativeDuplex(1, session, nil)
	err := session.localPacketTerminationError()
	if err == nil {
		t.Fatal("localPacketTerminationError = nil, want the :612 unexpected-stop error recorded in pumpErr")
	}
	if !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("localPacketTerminationError = %q, want substring \"stopped unexpectedly\" (:612)", err.Error())
	}
}
