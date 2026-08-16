package platform

// Adversarial coverage for platform/platform.go.
//
// The happy ThinAdapter submit paths (OpenSession, SubmitTCPFlow,
// SubmitUDPDatagram, SubmitDNSMessage, SubmitPacket, SubmitSocketEvent,
// ReadPacketOrFrame success, NotifyNetworkChange), the Profile/HasCryptoState/
// NewThinAdapter/cloneProfile/cloneFlowOpen/cloneExtensions/localModes/
// HasNoKernelLocalInterface paths, MockAdapter Start/SubmitPacket/ReadPacket/
// Events/NotifyNetworkChange/HasCryptoState, and ProfileFor for every real
// Kind are already covered by platform_test.go and are not re-asserted here
// except as anchors proving the error-case inputs are otherwise valid.
//
// This file covers the residual count-0 blocks, perturbing exactly one input
// per case so the branch under test is the one that fires:
//
//   - ProfileFor 62-63: the default case (a Kind outside the switch), which
//     yields PacketNone + NoEntitlementOnly and the SOCKS5/HTTPConnect-only
//     local-mode set (no DNS forwarder).
//   - SupportsLocalMode 73: the loop fall-through false return. Reached by a
//     profile whose LocalModes omits the queried mode (KindCI excludes the DNS
//     forwarder) and by an empty-mode query.
//   - ThinAdapter nil-core guards (OpenSession 158-160, CloseSession 164-167,
//     SubmitTCPFlow 172-174, SubmitUDPDatagram 179-181, SubmitDNSMessage
//     186-188, SubmitPacket 193-195, SubmitSocketEvent 200-202,
//     ReadPacketOrFrame 208-210, ExportRedactedDiagnostics 224-227):
//     NewThinAdapter(profile, nil) wires a nil CoreSink, so every method
//     short-circuits before delegating.
//   - CloseSession 168: the success return after delegating (CloseSession was
//     0% — no existing test called it).
//   - ReadPacketOrFrame 212-214: the `!ok` branch when the sink returns
//     (nil,false); plus the success return at 215 with a populated frame to
//     prove the not-ok input is otherwise valid.
//   - ExportRedactedDiagnostics 228: the delegated append return (was 0% — no
//     existing test called it).
//   - MockAdapter Name 263-265 (was 0%), Start 268-270 (empty SessionID),
//     SubmitPacket 276-278 (not started), ReadPacket 284-286 (empty queue).
//
// No dead-by-design blocks remain: every count-0 line is reachable by a
// caller-constructed input.
//
// Not duplicated: the ThinAdapter success delegation paths and the
// MockAdapter success paths are covered by platform_test.go and are not
// re-asserted here except as anchors.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). No new package-level helpers are introduced: the test
// reuses the in-package recordingCoreSink fixture and inlines all other
// constructs, so there is nothing for staticcheck U1000 to flag. No
// context.Context, no goroutines, no deprecated APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestProfileForDefaultAndSupportsLocalModeFalse(t *testing.T) {
	// The default case (62-63): an unknown Kind falls through to the same
	// shape as KindCI.
	prof := ProfileFor(Kind("unknown-kind"))
	if prof.PacketMode != PacketNone || !prof.NoEntitlementOnly || !prof.SupportsLocalProxy {
		t.Fatalf("default profile = %+v, want PacketNone+NoEntitlementOnly+SupportsLocalProxy", prof)
	}
	if prof.SupportsLocalMode(LocalDNSForwarder) {
		t.Fatal("default profile must not advertise the DNS forwarder (localModes(false))")
	}
	if !prof.HasNoKernelLocalInterface() {
		t.Fatal("default profile must still expose SOCKS5/HTTPConnect local interfaces")
	}

	// SupportsLocalMode 73: the false fall-through. KindCI's LocalModes is
	// [LocalSOCKS5, LocalHTTPConnect], so the DNS forwarder and any random
	// mode miss.
	ci := ProfileFor(KindCI)
	if ci.SupportsLocalMode(LocalDNSForwarder) {
		t.Fatal("KindCI must not advertise the DNS forwarder")
	}
	if ci.SupportsLocalMode("no-such-mode") {
		t.Fatal("SupportsLocalMode must return false for an absent mode")
	}

	// Anchor: a Linux profile (localModes(true)) DOES advertise the forwarder,
	// proving the KindCI/default misses above are because the mode is absent,
	// not because the query is broken.
	if !ProfileFor(KindLinux).SupportsLocalMode(LocalDNSForwarder) {
		t.Fatal("KindLinux must advertise the DNS forwarder")
	}
}

func TestThinAdapterNilCoreGuards(t *testing.T) {
	// NewThinAdapter(profile, nil) wires a nil CoreSink, so every method
	// short-circuits with the missing-core error (or nil/false/nil).
	a := NewThinAdapter(ProfileFor(KindLinux), nil)

	// The seven error-returning guards, asserted against the shared message.
	errCases := []struct {
		name string
		fn   func() error
	}{
		{"OpenSession", func() error { return a.OpenSession([]byte{1}) }},
		{"CloseSession", func() error { return a.CloseSession("s") }},
		{"SubmitTCPFlow", func() error { return a.SubmitTCPFlow(protocol.FlowOpen{}) }},
		{"SubmitUDPDatagram", func() error { return a.SubmitUDPDatagram(7, []byte{1}) }},
		{"SubmitDNSMessage", func() error { return a.SubmitDNSMessage(7, []byte{1}) }},
		{"SubmitPacket", func() error { return a.SubmitPacket([]byte{1}) }},
		{"SubmitSocketEvent", func() error { return a.SubmitSocketEvent(SocketEvent{Payload: []byte{1}}) }},
	}
	for _, c := range errCases {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn()
			if err == nil || !strings.Contains(err.Error(), "missing core sink") {
				t.Fatalf("%s err = %v, want missing core sink", c.name, err)
			}
		})
	}

	// ReadPacketOrFrame 208-210: nil core -> (nil, false).
	if data, ok := a.ReadPacketOrFrame(); data != nil || ok {
		t.Fatalf("ReadPacketOrFrame() = (%v, %v), want (nil, false) with nil core", data, ok)
	}

	// ExportRedactedDiagnostics 224-227: nil core -> nil.
	if out := a.ExportRedactedDiagnostics(); out != nil {
		t.Fatalf("ExportRedactedDiagnostics() = %v, want nil with nil core", out)
	}

	// NotifyNetworkChange is a no-op guard (no error path); assert it does
	// not panic with a nil core.
	a.NotifyNetworkChange(PathInfo{Interface: "eth0"})
}

func TestThinAdapterDelegatedSuccessPaths(t *testing.T) {
	// CloseSession 168 and ExportRedactedDiagnostics 228 were 0%: no existing
	// test called them. ReadPacketOrFrame 212-214 (!ok) and 215 (ok) need the
	// recordingCoreSink.
	sink := &recordingCoreSink{}
	a := NewThinAdapter(ProfileFor(KindLinux), sink)

	// CloseSession success (168): the sink returns nil.
	if err := a.CloseSession("session-1"); err != nil {
		t.Fatalf("CloseSession err = %v, want nil", err)
	}

	// ReadPacketOrFrame !ok (212-214): the sink's queue is empty.
	if data, ok := a.ReadPacketOrFrame(); data != nil || ok {
		t.Fatalf("ReadPacketOrFrame() = (%v, %v), want (nil, false) when sink empty", data, ok)
	}

	// ReadPacketOrFrame success (215): populate the sink and confirm a copy is
	// returned (the returned slice must not alias the sink's buffer).
	sink.nextPacketOrFrame = []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data, ok := a.ReadPacketOrFrame()
	if !ok || data == nil {
		t.Fatalf("ReadPacketOrFrame() = (%v, %v), want (frame, true)", data, ok)
	}
	if string(data) != "\xde\xad\xbe\xef" {
		t.Fatalf("ReadPacketOrFrame data = %x, want deadbeef", data)
	}
	// Mutating the returned copy must not touch the sink's recorded frame.
	data[0] = 0x00
	if sink.lastReturnedPacketOrFrame[0] == 0x00 {
		t.Fatal("ReadPacketOrFrame returned a slice aliasing the sink buffer; want a copy")
	}

	// ExportRedactedDiagnostics success (228): the sink returns nil, so the
	// delegated append yields nil but the delegation line executes.
	if out := a.ExportRedactedDiagnostics(); out != nil {
		t.Fatalf("ExportRedactedDiagnostics() = %v, want nil (sink returns nil)", out)
	}
}

func TestMockAdapterEdges(t *testing.T) {
	// Name 263-265 was 0%.
	mock := NewMockAdapter("cov-mock")
	if got := mock.Name(); got != "cov-mock" {
		t.Fatalf("Name() = %q, want cov-mock", got)
	}

	// Start 268-270: empty SessionID is rejected before started is set.
	if err := mock.Start(SessionConfig{}); err == nil || !strings.Contains(err.Error(), "missing session id") {
		t.Fatalf("Start({}) err = %v, want missing session id", err)
	}
	// Confirm the empty-id rejection did not flip started: a packet submit
	// must still fail as not-started (276-278).
	if err := mock.SubmitPacket([]byte{1}); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("SubmitPacket before Start err = %v, want not started", err)
	}

	// ReadPacket 284-286: empty queue -> (nil, false).
	if data, ok := mock.ReadPacket(); data != nil || ok {
		t.Fatalf("ReadPacket() = (%v, %v), want (nil, false) when queue empty", data, ok)
	}

	// Anchor: after a valid Start, SubmitPacket enqueues and ReadPacket drains
	// it, proving the not-started / empty-queue cases above are because of the
	// perturbed inputs, not a broken adapter.
	if err := mock.Start(SessionConfig{SessionID: "session-1"}); err != nil {
		t.Fatalf("Start valid err = %v, want nil", err)
	}
	if err := mock.SubmitPacket([]byte{1, 2, 3}); err != nil {
		t.Fatalf("SubmitPacket after Start err = %v, want nil", err)
	}
	if data, ok := mock.ReadPacket(); !ok || string(data) != "\x01\x02\x03" {
		t.Fatalf("ReadPacket() = (%v, %v), want (1,2,3, true)", data, ok)
	}
}
