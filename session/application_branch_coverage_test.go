package session

// Adversarial white-box coverage for the pure validation/encoding helpers of
// session/application.go. application.go is the application-layer session: a
// mutex-guarded queue of encrypted packets, a packet receiver, rekey
// accounting, and the seal/open runtime. The runtime paths (QueueFrames,
// NextPacket, HandlePacket, queueBlock, the seal/read machinery, the drain
// timers) need a fully constructed Application with live crypto protectors and
// real packet buffers, so they are integration surfaces and are NOT targeted
// here. Every branch below lives in a package-level pure helper that the
// runtime delegates to — limit/rekey normalization, the high-priority frame
// classifier, the encoded-length estimator, and the int-overflow guard — or in
// the constructor's validation prefix, which returns BEFORE any crypto or
// channel is established. None of the covered paths construct a protector,
// touch the mutex, the clock's timer side, the network, or the filesystem.
//
// The :148 case reuses the package's existing manualApplicationClock stub
// (defined in key_update_test.go and compiled into the same test binary) so the
// constructor's nil-clock guard at 137 passes and the route-overflow guard at
// 148 is reached.
//
// Targets covered:
//
//   - newApplicationWithClock:137-139 — the `clock == nil` guard. The existing
//     suite always constructs via NewApplication (which injects the real
//     system clock), so the nil-clock return is unreached. A nil clock returns
//     before normalizeLimits runs.
//   - newApplicationWithClock:148-150 — the `cfg.RouteInstanceID > MaxVarint`
//     guard. The existing suite uses canonical route ids, so the overflow
//     return is unreached. A manualApplicationClock passes the nil-clock guard,
//     the zero Limits/Rekey normalize to defaults, then a route id of ^uint64
//     (0xFFFFFFFFFFFFFFFF, above wire.MaxVarint = 1<<62-1) hits the guard before
//     any suite/secret validation runs.
//   - normalizeLimits:673-675 — the `MaxQueuedBytes < 0 || > maxQueuedBytes`
//     guard. The existing suite passes a zero Limits (defaults) or fully-valid
//     Limits, so the negative-bytes return is unreached. A Limits with every
//     field nonzero, a valid packet count, and MaxQueuedBytes = -1 passes the
//     all-nonzero and packet-count guards then hits the bytes guard.
//   - normalizeRekeyPolicy:699-701 — the `MaxPackets > MaxVarint` guard. The
//     existing suite passes a zero RekeyPolicy (defaults) or fully-valid policy,
//     so the overflow return is unreached. A RekeyPolicy with a positive age,
//     nonzero byte/packet limits, and MaxPackets = ^uint64 passes the
//     all-positive guard then hits the canonical-range guard.
//   - isHighPriorityFrameBlock:582-584 — the `len(block.Frames) == 0` guard. The
//     existing suite classifies only non-empty blocks, so the empty-block
//     return is unreached. An empty FrameBlock returns false before the DNS-frame
//     loop runs. (A single-frame all-DNS block is also asserted to return true,
//     locking the function's positive semantics.)
//   - encodedFrameBlockLength:778-780 — the wire.VarintLen error propagation on
//     a frame's FrameType/FlowID/Flags. The existing suite encodes only
//     canonical frame fields, so the oversized-varint return is unreached. A
//     frame with FrameType = ^uint64 (> MaxVarint) makes VarintLen fail; the
//     frame carries an empty payload so the oversized-payload guard at 773
//     passes first (no large allocation).
//   - encodedPacketReservation:757-759 — the encodedFrameBlockLength error
//     propagation. The existing suite reserves for well-formed blocks, so the
//     propagation is unreached. The same oversized-FrameType frame makes
//     encodedFrameBlockLength fail and encodedPacketReservation surfaces it.
//   - checkedLengthAdd:799-801 — the int-overflow guard. The existing suite
//     never overflows the running encoded length, so the overflow return is
//     unreached. checkedLengthAdd(math.MaxInt, 1) overflows directly.
//
// Avoided (integration/runtime/memory-bound, NOT claimed):
//   - The Application runtime paths (212-603: queueBlock, seal/open, drain,
//     HandlePacket) need a constructed Application and real packets.
//   - newApplicationWithClock:156-158 — the AEADKeyLength error propagation. It
//     is only reachable with a suite that passes SuiteHashLength (152) but fails
//     AEADKeyLength, a suite-set gap that is not exercised by any existing
//     suite and is left for a dedicated suite-coverage pillar.
//   - encodedPacketReservation:760-762 (shadowed-by-773, which rejects an
//     oversized frame payload first), encodedFrameBlockLength:768
//     (VarintLen-can't-fail on a real frame count), and :773/:782/:787/:791
//     (oversized-payload needs a >=16 MiB allocation; the checkedLengthAdd
//     overflow inside the loop needs ~200 M frames — both memory-bound and not
//     feasible in a unit test).
//
// No new package-level helpers or types are introduced (only test functions and
// inline literals, plus the reused manualApplicationClock), so there is nothing
// for staticcheck U1000. No context.Context (no SA1012 surface), no goroutines,
// no cryptography, no real network or filesystem.

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestNewApplicationWithClockRejectsNilClock(t *testing.T) {
	// 137-139: a nil clock returns before normalizeLimits runs.
	if _, err := newApplicationWithClock(Config{}, nil); err == nil ||
		!strings.Contains(err.Error(), "nil application clock") {
		t.Fatalf("newApplicationWithClock(nil clock) err = %v, want substring \"nil application clock\"", err)
	}
}

func TestNewApplicationWithClockRejectsRouteInstanceOverflow(t *testing.T) {
	// 148-150: a manual clock passes the nil-clock guard, the zero Limits and
	// Rekey normalize to defaults, then a route id above wire.MaxVarint
	// (1<<62-1) hits the canonical-range guard before any suite/secret
	// validation runs.
	clock := newManualApplicationClock(time.Unix(0, 0))
	if _, err := newApplicationWithClock(Config{RouteInstanceID: ^uint64(0)}, clock); err == nil ||
		!strings.Contains(err.Error(), "route instance ID exceeds canonical range") {
		t.Fatalf("newApplicationWithClock(route overflow) err = %v, want substring \"route instance ID exceeds canonical range\"", err)
	}
}

func TestNormalizeLimitsRejectsNegativeMaxQueuedBytes(t *testing.T) {
	// 673-675: every field is nonzero (so the all-nonzero guard passes), the
	// packet count is valid (so the packet-count guard passes), then a negative
	// MaxQueuedBytes hits the bytes guard.
	limits := Limits{
		MaxQueuedPackets:       1,
		MaxQueuedBytes:         -1,
		ControlReservedPackets: 1,
		ControlReservedBytes:   1,
		ReplayWindow:           minReplayWindow,
	}
	if _, err := normalizeLimits(limits); err == nil ||
		!strings.Contains(err.Error(), "invalid maximum queued bytes") {
		t.Fatalf("normalizeLimits(negative bytes) err = %v, want substring \"invalid maximum queued bytes\"", err)
	}
}

func TestNormalizeRekeyPolicyRejectsPacketsOverflow(t *testing.T) {
	// 699-701: a positive age and nonzero byte/packet limits pass the
	// all-positive guard, then MaxPackets above wire.MaxVarint hits the
	// canonical-range guard.
	policy := RekeyPolicy{
		MaxAge:     time.Nanosecond,
		MaxBytes:   1,
		MaxPackets: ^uint64(0),
	}
	if _, err := normalizeRekeyPolicy(policy); err == nil ||
		!strings.Contains(err.Error(), "rekey packet limit exceeds canonical range") {
		t.Fatalf("normalizeRekeyPolicy(packets overflow) err = %v, want substring \"rekey packet limit exceeds canonical range\"", err)
	}
}

func TestIsHighPriorityFrameBlockHandlesEmptyAndAllDNS(t *testing.T) {
	// 582-584: an empty FrameBlock returns false before the DNS-frame loop runs.
	if isHighPriorityFrameBlock(protocol.FrameBlock{}) {
		t.Fatal("isHighPriorityFrameBlock(empty) = true, want false")
	}
	// Lock the positive semantics: a single-frame all-DNS block returns true.
	allDNS := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameDNSMessage,
	}}}
	if !isHighPriorityFrameBlock(allDNS) {
		t.Fatal("isHighPriorityFrameBlock(all-DNS) = false, want true")
	}
}

func TestEncodedFrameBlockLengthRejectsOversizedVarint(t *testing.T) {
	// 778-780: a frame with FrameType = ^uint64 (> wire.MaxVarint) makes
	// VarintLen fail. The empty payload keeps the oversized-payload guard at
	// 773 from triggering a large allocation.
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: ^uint64(0)}}}
	if _, err := encodedFrameBlockLength(block); err == nil {
		t.Fatal("encodedFrameBlockLength(oversized varint) err = nil, want VarintLen error")
	}
}

func TestEncodedPacketReservationPropagatesEncodingError(t *testing.T) {
	// 757-759: the same oversized-FrameType frame makes encodedFrameBlockLength
	// fail and encodedPacketReservation surfaces the error before the
	// plaintext-length guard at 760 runs.
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: ^uint64(0)}}}
	if _, err := encodedPacketReservation(block); err == nil {
		t.Fatal("encodedPacketReservation(oversized varint) err = nil, want propagated error")
	}
}

func TestCheckedLengthAddRejectsOverflow(t *testing.T) {
	// 799-801: adding 1 to math.MaxInt overflows the int accumulator directly.
	if _, err := checkedLengthAdd(math.MaxInt, 1); err == nil ||
		!strings.Contains(err.Error(), "encoded packet length overflow") {
		t.Fatalf("checkedLengthAdd(MaxInt, 1) err = %v, want substring \"encoded packet length overflow\"", err)
	}
}
