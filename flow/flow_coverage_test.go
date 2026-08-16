package flow

// Adversarial coverage for the flow-management Manager, the UDP-confirm
// validators, and the FakeIPAllocator in flow/flow.go. The existing flow_test.go
// covers the happy open/confirm/datagram/close paths, the UDP FQDN-mode policy
// branches, the TTL/idle/realtime-age drop behaviour, and the half-close drain.
// The residual count-0 blocks are the rejection branches that the happy-path
// tests never drive: duplicate flow_id, unknown/non-UDP confirms, the
// ConfirmUDPFrameWithOptions and MarkLocalCloseFrame/MarkPeerCloseFrame happy
// returns, the Close method, the markClose ValidateFlowClose and unknown-flow
// branches, the applyUDPConfirmTTL now-clamp, the staleRealtimeDatagram
// non-stale return, and several FakeIPAllocator edges.
//
// This file covers them with crafted Manager state + inputs, perturbing exactly
// one condition per case so the branch under test is the one that fires. Each
// rejection asserts exactly one error substring so the failure is attributable
// to the perturbed field alone.
//
// Uncovered blocks (measured count 0 before this file):
//   - OpenWithOptions (107): duplicate flow_id 114.
//   - ConfirmUDPWithOptions (140): unknown flow_id 148, non-UDP 151.
//   - ConfirmUDPFrameWithOptions (171): happy return 176 (decode + confirm OK).
//   - applyUDPConfirmTTL (212): now < CreatedAtUnix clamp 217.
//   - AcceptDatagramWithOptions (236): !ok / non-UDP return 242.
//   - Close (259): unknown flow_id 263, delete 265, return 266.
//   - MarkLocalCloseFrame (277): decode-err 279, happy return 282.
//   - MarkPeerCloseFrame (285): happy return 290.
//   - markClose (308): ValidateFlowClose propagation 310, unknown flow_id 316.
//   - staleRealtimeDatagram (402): NowUnix <= SentAtUnix non-stale return 407.
//   - NewFakeIPAllocator (424): invalid-CIDR fallback 427.
//   - Assign (432): empty domain 435.
//   - AnswersForFakeIP (452): not-found 455.
//   - MappingForFakeIP (460): ParseIP nil 463.
//   - nextAvailableIPLocked (474): base nil 477, bits != 32 481.
//   - canonicalDomain (505): d == "." -> "" 508.
//
// Dead-by-design (documented, not covered):
//   - validateOpen (345) reserved flow_kind 352, IPv4 length 357, IPv6 length
//     361, domain canonical 365, reserved target_kind 368, binding/hash length
//     371. validateOpen calls protocol.ValidateFlowOpen(open) first (line 346)
//     and returns on its error. ValidateFlowOpen already accepts only flow_kind
//     in {0x01,0x02,0x03}, target_kind in {0x01,0x02,0x03}, enforces the IPv4
//     (4-byte) / IPv6 (16-byte) lengths, runs validateFlowOpenDomainTarget
//     (which rejects any host that canonicalDomain would mutate — whitespace,
//     upper-case, trailing dot — so a passing host equals its canonical form),
//     checks NameBindingID == 16 and DNSAnswerSetHash == 48, and validates the
//     UDPFQDNMode/LocalBindingMode/PriorityClass ranges. Once ValidateFlowOpen
//     returns nil, every one of validateOpen's own switch/length checks is
//     already satisfied, so the post-call branches (352/357/361/365/368/371)
//     are unreachable for any constructible FlowOpen. (The UDP-specific branches
//     374/378/380-382 are NOT duplicated by ValidateFlowOpen and are already
//     covered by flow_test.go.)
//   - decodeUDPTargetConfirmFrame (179) r.Err() return 189 and decodeFlowCloseFrame
//     (293) r.Err() return 303. Both call protocol.ValidateFlowManagementFrame
//     first; for the matching frame type it decodes the payload, validates the
//     struct, and returns r.Err() at frames.go:662 and the trailing-bytes check
//     at 665. If the payload is malformed the error surfaces from
//     ValidateFlowManagementFrame (line 184/298), so the subsequent fresh
//     reader + r.Err() re-check (189/303) re-decodes a payload that already
//     decoded cleanly and can never fail.
//
// Not duplicated: the validateOpen happy path, the UDP FQDN policy branches,
// the TTL/idle/realtime drop behaviour, half-close drain, and fake-IP
// assignment/reverse-lookup happy paths are already covered by flow_test.go
// and are not re-asserted here except where a table naturally includes them.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The two new helpers (flowCovIPv4UDPOpen,
// flowCovIPv4UDPConfirm) are each referenced by >=2 tests, so neither is U1000.
// The in-package fb() helper (flow_test.go) is reused for fixed byte slices. No
// context.Context, no deprecated APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// flowCovIPv4UDPOpen returns an IP-authoritative UDP FlowOpen baseline that
// passes both protocol.ValidateFlowOpen and validateOpen. Each test clones it
// and perturbs at most the FlowID. Referenced by >=2 tests, so not U1000.
func flowCovIPv4UDPOpen(flowID uint64) protocol.FlowOpen {
	return protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 7},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
		PriorityClass:    PriorityRealtime,
	}
}

// flowCovIPv4UDPConfirm returns a UDPTargetConfirm matching flowCovIPv4UDPOpen's
// IP-authoritative target so validateUDPConfirmAgainstFlow passes. Referenced
// by >=2 tests, so not U1000.
func flowCovIPv4UDPConfirm(flowID uint64) protocol.UDPTargetConfirm {
	return protocol.UDPTargetConfirm{
		FlowID:           flowID,
		TargetKind:       TargetKindIPv4,
		SelectedIP:       []byte{203, 0, 113, 7},
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0xbb, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	}
}

func TestOpenWithOptionsDuplicateFlowIDDecidesPerCondition(t *testing.T) {
	m := NewManager()
	open := flowCovIPv4UDPOpen(70)
	if err := m.Open(open); err != nil {
		t.Fatalf("first open: %v", err)
	}
	// Second open with the same FlowID: validateOpen passes, the duplicate
	// lookup at line 113 fires.
	err := m.Open(open)
	if err == nil || !strings.Contains(err.Error(), "duplicate flow_id 70") {
		t.Fatalf("duplicate open: err = %v, want %q", err, "duplicate flow_id 70")
	}
}

func TestConfirmUDPWithOptionsDecidesPerCondition(t *testing.T) {
	t.Run("unknown flow_id", func(t *testing.T) {
		m := NewManager()
		// Valid confirm for a flow that was never opened.
		err := m.ConfirmUDP(flowCovIPv4UDPConfirm(71))
		if err == nil || !strings.Contains(err.Error(), "unknown flow_id 71") {
			t.Fatalf("err = %v, want %q", err, "unknown flow_id 71")
		}
	})
	t.Run("non-UDP flow", func(t *testing.T) {
		m := NewManager()
		// A TCP flow: ConfirmUDP must reject it as a non-UDP flow before the
		// target-match check runs.
		if err := m.Open(protocol.FlowOpen{
			FlowOpenVersion:  registry.Version20,
			FlowID:           72,
			FlowKind:         FlowKindTCPStream,
			TargetKind:       TargetKindDomainName,
			TargetHost:       []byte("example.com"),
			TargetPort:       443,
			NameBindingID:    fb(0xaa, 16),
			DNSAnswerSetHash: fb(0xbb, 48),
			LocalBindingMode: LocalBindingExplicitProxyAPI,
			PriorityClass:    PriorityInteractive,
		}); err != nil {
			t.Fatal(err)
		}
		confirm := flowCovIPv4UDPConfirm(72)
		err := m.ConfirmUDP(confirm)
		if err == nil || !strings.Contains(err.Error(), "target confirmation on non-UDP flow") {
			t.Fatalf("err = %v, want %q", err, "target confirmation on non-UDP flow")
		}
	})
}

func TestConfirmUDPFrameWithOptionsHappyReturnDecidesPerCondition(t *testing.T) {
	m := NewManager()
	if err := m.OpenWithOptions(flowCovIPv4UDPOpen(73), FlowOptions{NowUnix: 100, TTLSeconds: 300, IdleTimeoutSeconds: 300}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.NewUDPTargetConfirmFrame(flowCovIPv4UDPConfirm(73))
	if err != nil {
		t.Fatal(err)
	}
	// Happy path: decode succeeds and ConfirmUDPWithOptions returns nil, so
	// ConfirmUDPFrameWithOptions returns nil at line 176.
	if err := m.ConfirmUDPFrameWithOptions(frame, UDPConfirmOptions{NowUnix: 110}); err != nil {
		t.Fatalf("confirm frame: %v", err)
	}
	state, ok := m.DemuxInbound(73)
	if !ok {
		t.Fatalf("confirmed flow was removed")
	}
	if state.ConfirmedPort != 443 || len(state.ConfirmedHost) != 4 {
		t.Fatalf("confirm did not record target: %+v", state)
	}
}

func TestApplyUDPConfirmTTLClampsBeforeAtCreationDecidesPerCondition(t *testing.T) {
	m := NewManager()
	if err := m.OpenWithOptions(flowCovIPv4UDPOpen(74), FlowOptions{NowUnix: 100, TTLSeconds: 300, IdleTimeoutSeconds: 300}); err != nil {
		t.Fatal(err)
	}
	// opts.NowUnix (50) < CreatedAtUnix (100) exercises the clamp at line 217.
	// The confirm carries TTLSeconds=60, so with the clamp
	// confirmedTTL = 100-100+60 = 60 < 300 and the flow TTL shortens to 60.
	// Without the clamp, 50-100 underflows to a huge value that would NOT be
	// < 300 and the TTL would stay 300 — so TTLSeconds==60 proves the clamp ran.
	if err := m.ConfirmUDPWithOptions(flowCovIPv4UDPConfirm(74), UDPConfirmOptions{NowUnix: 50}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	state, ok := m.DemuxInbound(74)
	if !ok {
		t.Fatalf("confirmed flow was removed")
	}
	if state.ConfirmedAtUnix != 50 {
		t.Fatalf("ConfirmedAtUnix = %d, want 50", state.ConfirmedAtUnix)
	}
	if state.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds = %d, want 60 (clamped-now shortening)", state.TTLSeconds)
	}
}

func TestAcceptDatagramWithOptionsUnknownFlowDecidesPerCondition(t *testing.T) {
	m := NewManager()
	// Unknown flow_id (and the non-UDP short-circuit): line 241 !ok -> 242.
	if _, ok := m.AcceptDatagram(75, 100); ok {
		t.Fatalf("unknown flow_id datagram was accepted")
	}
}

func TestCloseDecidesPerCondition(t *testing.T) {
	t.Run("unknown flow_id", func(t *testing.T) {
		m := NewManager()
		err := m.Close(protocol.FlowClose{FlowID: 999, CloseCode: protocol.CloseNormal})
		if err == nil || !strings.Contains(err.Error(), "unknown flow_id 999") {
			t.Fatalf("err = %v, want %q", err, "unknown flow_id 999")
		}
	})
	t.Run("known flow released", func(t *testing.T) {
		m := NewManager()
		if err := m.Open(flowCovIPv4UDPOpen(76)); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(protocol.FlowClose{FlowID: 76, CloseCode: protocol.CloseNormal}); err != nil {
			t.Fatalf("close: %v", err)
		}
		if _, ok := m.DemuxInbound(76); ok {
			t.Fatalf("closed flow remained tracked")
		}
	})
}

func TestMarkLocalCloseFrameDecidesPerCondition(t *testing.T) {
	t.Run("wrong frame type", func(t *testing.T) {
		m := NewManager()
		// A non-FLOW_CLOSE frame: decodeFlowCloseFrame rejects at line 295 and
		// MarkLocalCloseFrame surfaces it at line 279.
		err := m.MarkLocalCloseFrame(protocol.AuroraFrame{FrameType: registry.FrameFlowOpen}, CloseOptions{})
		if err == nil || !strings.Contains(err.Error(), "expected FLOW_CLOSE frame") {
			t.Fatalf("err = %v, want %q", err, "expected FLOW_CLOSE frame")
		}
	})
	t.Run("happy local half-close", func(t *testing.T) {
		m := NewManager()
		if err := m.Open(flowCovIPv4UDPOpen(77)); err != nil {
			t.Fatal(err)
		}
		frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 77, CloseCode: protocol.CloseNormal})
		if err != nil {
			t.Fatal(err)
		}
		// Happy path: decode succeeds and MarkLocalClose returns nil, so
		// MarkLocalCloseFrame returns nil at line 282.
		if err := m.MarkLocalCloseFrame(frame, CloseOptions{NowUnix: 100, DrainSeconds: 5}); err != nil {
			t.Fatalf("local close frame: %v", err)
		}
		state, ok := m.DemuxInbound(77)
		if !ok || !state.LocalClosed || state.PeerClosed {
			t.Fatalf("local half-close state mismatch: %+v ok=%v", state, ok)
		}
	})
}

func TestMarkPeerCloseFrameHappyReturnDecidesPerCondition(t *testing.T) {
	m := NewManager()
	if err := m.Open(flowCovIPv4UDPOpen(78)); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 78, CloseCode: protocol.CloseNormal})
	if err != nil {
		t.Fatal(err)
	}
	// Happy path: decode succeeds and MarkPeerClose returns nil, so
	// MarkPeerCloseFrame returns nil at line 290.
	if err := m.MarkPeerCloseFrame(frame, CloseOptions{NowUnix: 100, DrainSeconds: 5}); err != nil {
		t.Fatalf("peer close frame: %v", err)
	}
	state, ok := m.DemuxInbound(78)
	if !ok || state.LocalClosed || !state.PeerClosed {
		t.Fatalf("peer half-close state mismatch: %+v ok=%v", state, ok)
	}
}

func TestMarkCloseDecidesPerCondition(t *testing.T) {
	t.Run("invalid close code propagated", func(t *testing.T) {
		m := NewManager()
		// ValidateFlowClose runs before the flow lookup, so an unknown close
		// code surfaces at line 310 regardless of whether the flow exists.
		err := m.MarkLocalClose(protocol.FlowClose{FlowID: 1, CloseCode: 0xBAD}, CloseOptions{})
		if err == nil || !strings.Contains(err.Error(), "reserved flow close code") {
			t.Fatalf("err = %v, want %q", err, "reserved flow close code")
		}
	})
	t.Run("unknown flow_id", func(t *testing.T) {
		m := NewManager()
		// Structurally-valid close for a flow that was never opened.
		err := m.MarkLocalClose(protocol.FlowClose{FlowID: 999, CloseCode: protocol.CloseNormal}, CloseOptions{})
		if err == nil || !strings.Contains(err.Error(), "unknown flow_id 999") {
			t.Fatalf("err = %v, want %q", err, "unknown flow_id 999")
		}
	})
}

func TestStaleRealtimeDatagramNonStaleAtSentAtDecidesPerCondition(t *testing.T) {
	m := NewManager()
	if err := m.OpenWithOptions(flowCovIPv4UDPOpen(79), FlowOptions{NowUnix: 100, TTLSeconds: 300, IdleTimeoutSeconds: 300}); err != nil {
		t.Fatal(err)
	}
	// NowUnix == SentAtUnix: the realtime guard's second check (line 406,
	// NowUnix <= SentAtUnix) returns not-stale, so the datagram is accepted.
	// This is the boundary that the existing age-drop test (which exercises
	// the stale branch at 409) does not reach.
	if _, ok := m.AcceptDatagramWithOptions(79, DatagramOptions{NowUnix: 100, SentAtUnix: 100, MaxRealtimeAgeSeconds: 5}); !ok {
		t.Fatalf("datagram at SentAtUnix was dropped as stale")
	}
}

func TestFakeIPAllocatorEdgesDecidesPerCondition(t *testing.T) {
	t.Run("invalid CIDR falls back", func(t *testing.T) {
		// "not-a-cidr" fails ParseCIDR, so NewFakeIPAllocator falls back to the
		// 198.18.0.0/15 default (line 427). A subsequent Assign must succeed,
		// proving the allocator has a usable IPv4 network.
		a := NewFakeIPAllocator("not-a-cidr")
		if _, _, err := a.Assign("fallback.example", []string{"93.184.216.34"}); err != nil {
			t.Fatalf("fallback allocator Assign: %v", err)
		}
	})
	t.Run("empty domain rejected", func(t *testing.T) {
		a := NewFakeIPAllocator("198.18.0.0/15")
		_, _, err := a.Assign("", nil)
		if err == nil || !strings.Contains(err.Error(), "empty domain") {
			t.Fatalf("err = %v, want %q", err, "empty domain")
		}
	})
	t.Run("answers not found", func(t *testing.T) {
		a := NewFakeIPAllocator("198.18.0.0/15")
		// A valid IPv4 that was never assigned: MappingForFakeIP returns
		// ok=false at line 469, so AnswersForFakeIP returns false at line 455.
		if _, ok := a.AnswersForFakeIP("203.0.113.99"); ok {
			t.Fatalf("unassigned fake IP returned answers")
		}
	})
	t.Run("mapping rejects non-IP", func(t *testing.T) {
		a := NewFakeIPAllocator("198.18.0.0/15")
		// ParseIP returns nil -> To4() nil -> line 463 returns not-found.
		if _, ok := a.MappingForFakeIP("not-an-ip"); ok {
			t.Fatalf("non-IP string returned a mapping")
		}
	})
	t.Run("IPv6 network rejected (base nil)", func(t *testing.T) {
		// 2001:db8::/32 is IPv6 -> network.IP.To4() is nil -> line 477.
		a := NewFakeIPAllocator("2001:db8::/32")
		_, _, err := a.Assign("v6.example", []string{"93.184.216.34"})
		if err == nil || !strings.Contains(err.Error(), "fake IP network must be IPv4") {
			t.Fatalf("err = %v, want %q", err, "fake IP network must be IPv4")
		}
	})
	t.Run("IPv4-mapped network rejected (bits != 32)", func(t *testing.T) {
		// ::ffff:198.18.0.0/96 is IPv4-mapped: To4() is non-nil (0.0.0.0) but
		// Mask.Size() is (96, 128), so the base check passes and the bits!=32
		// check at line 481 fires. Distinct from the IPv6/base-nil case above.
		a := NewFakeIPAllocator("::ffff:198.18.0.0/96")
		_, _, err := a.Assign("mapped.example", []string{"93.184.216.34"})
		if err == nil || !strings.Contains(err.Error(), "fake IP network must be IPv4") {
			t.Fatalf("err = %v, want %q", err, "fake IP network must be IPv4")
		}
	})
}

func TestCanonicalDomainDotCollapsesToEmptyDecidesPerCondition(t *testing.T) {
	// ".." trims to a single "." which the d == "." guard (line 508) maps to "".
	// (A single "." trims all the way to "" and returns at line 510 instead, so
	// this is the only input that exercises the 508 branch.)
	if got := canonicalDomain(".."); got != "" {
		t.Fatalf("canonicalDomain(\"..\") = %q, want \"\"", got)
	}
	// Sanity: a normal canonical form is preserved.
	if got := canonicalDomain("Example.COM."); got != "example.com" {
		t.Fatalf("canonicalDomain(\"Example.COM.\") = %q, want \"example.com\"", got)
	}
}
