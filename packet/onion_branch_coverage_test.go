package packet

// Adversarial white-box coverage for the uncovered guard branches of
// packet/onion.go. onion.go is pure logic (only the protocol, registry, and
// wire packages plus fmt) — no cryptography operation, no network, no
// filesystem. Every guard below fires before any Seal/Encode is invoked, so
// the protectors are built as bare field-literal values (no key material
// needed); only the Seal-error stretch uses a real in-memory AEAD protector.
//
// Targets covered:
//
// Pure guards (no crypto operation):
//   - SealSplit2Onion:12-14 — the `entry == nil || exit == nil` guard. The
//     existing suite always passes two real protectors, so both the nil-entry
//     and nil-exit clauses are unreached.
//   - SealSplit2Onion:15-17 — the `forward.RouteInstanceID != exit.RouteInstanceID
//     || forward.HopIndex != exit.HopLayer` guard. The existing suite always
//     passes a forward that matches the exit layer (routeForwardForPacketTest
//     with the exit's route and hop), so the mismatch return is unreached. A
//     forward built for a different route instance (and, in a second case, a
//     matching route but a mismatched hop index) hits both clauses.
//   - SealSplit2BackwardOnion:43-45 — the nil-protector guard (the backward
//     wrapper validates before delegating to SealSplit2Onion).
//   - SealSplit2BackwardOnion:46-48 — the `entry.RouteInstanceID !=
//     exit.RouteInstanceID` guard. The existing backward suite uses matching
//     route instances.
//   - SealSplit2BackwardOnion:49-51 — the `entry.HopLayer != 0 || exit.HopLayer
//     != 1` guard. The existing backward suite uses hop 0/1.
//   - SealSplit2BackwardOnion:52-54 — the `entry.Direction != 1 ||
//     exit.Direction != 1` guard. The existing backward suite uses direction 1.
//   - DecodeForwardedPacket:59-61 — the `len(block.Frames) != 1` guard. The
//     existing suite always passes a single-frame block.
//   - DecodeForwardedPacket:63-65 — the `frame.FrameType != FrameRouteForward`
//     guard. The existing suite always passes a route-forward frame.
//   - decodeRouteForwardPayload:76-78 — the `r.Err() != nil` guard. The
//     existing DecodeForwardedPacket malformed-metadata test reaches the
//     later Validate error (82) via a well-formed-but-invalid payload, never
//     a structurally undecodable one, so the decode-error return is unreached.
//   - decodeRouteForwardPayload:79-81 — the `!r.EOF()` trailing-bytes guard.
//     The existing suite always passes a canonical payload with no trailing
//     bytes.
//
// Crypto-backed (deterministic in-memory AEAD):
//   - SealSplit2Onion:22-24 — the `exit.Seal(exitBlock)` error. The existing
//     malformed-forward tests fail at the Validate guard (18) before Seal, and
//     the round-trip tests pass a valid block, so the Seal-error propagation is
//     unreached. A forward that matches the exit layer and passes Validate,
//     paired with a malformed exit block (an unknown lab-only frame type that
//     Seal rejects — see TestProtectorRejectsUnknownLabOnlyFrameTypeBeforeSeal),
//     makes exit.Seal fail here.
//
// Dead-by-design / oversized-only (documented, NOT claimed):
//   - SealSplit2Onion:26-28 (protocol.Encode(inner)) and :31-33
//     (protocol.Encode(forward)) — the Encode error propagations. Line 29
//     overwrites the caller's forward.OpaqueNextHopPrelude with encodedInner,
//     so by the time Encode(forward) runs at 30 the prelude is a valid encoded
//     packet, and inner at 25 is a valid sealed packet. Encode only fails when
//     a payload exceeds the 0xffffff (16 MiB) opaque/encoded-length ceiling,
//     which a sealed packet or a validated forward never produces; reaching
//     either return requires a >16 MiB exit block. Multi-megabyte inputs are
//     out of scope for a lightweight deterministic unit test, so these are left
//     to the oversized-payload domain.
//
// routeForwardForPacketTest (packet_test.go:2344) and the field-literal
// Protector idiom are reused; no new package-level helpers or types are
// introduced (only test functions), so there is nothing for staticcheck U1000.
// No context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestSealSplit2OnionRequiresBothProtectors(t *testing.T) {
	// 12-14: the nil guard fires before any field of the forward or block is
	// inspected, so a zero-value forward/block and a bare non-nil protector for
	// the other side suffice.
	zeroBlock := protocol.FrameBlock{}
	zeroForward := protocol.RouteForwardFrame{}
	if _, err := SealSplit2Onion(zeroBlock, nil, &Protector{}, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "split-2 protectors are required") {
		t.Fatalf("SealSplit2Onion(nil entry) err = %v, want substring \"split-2 protectors are required\"", err)
	}
	if _, err := SealSplit2Onion(zeroBlock, &Protector{}, nil, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "split-2 protectors are required") {
		t.Fatalf("SealSplit2Onion(nil exit) err = %v, want substring \"split-2 protectors are required\"", err)
	}
}

func TestSealSplit2OnionRejectsRouteForwardMetadataMismatch(t *testing.T) {
	// 15-17: a forward whose route instance differs from the exit's hits the
	// first clause; a forward whose route matches but whose hop index differs
	// hits the second. No Seal is invoked (the guard precedes it), so the
	// protectors carry only the fields the guard inspects.
	exit := &Protector{RouteInstanceID: 7, HopLayer: 1}
	zeroBlock := protocol.FrameBlock{}
	if _, err := SealSplit2Onion(zeroBlock, &Protector{}, exit, routeForwardForPacketTest(t, 8, 1)); err == nil ||
		!strings.Contains(err.Error(), "route-forward metadata does not match exit layer") {
		t.Fatalf("route-instance mismatch err = %v, want substring \"route-forward metadata does not match exit layer\"", err)
	}
	// Matching route instance (7) but a hop index (9) that differs from the
	// exit's hop layer (1) hits the second clause.
	if _, err := SealSplit2Onion(zeroBlock, &Protector{}, exit, routeForwardForPacketTest(t, 7, 9)); err == nil ||
		!strings.Contains(err.Error(), "route-forward metadata does not match exit layer") {
		t.Fatalf("hop-index mismatch err = %v, want substring \"route-forward metadata does not match exit layer\"", err)
	}
}

func TestSealSplit2OnionSurfacesExitSealError(t *testing.T) {
	// 22-24: a forward that matches the exit layer and passes Validate, paired
	// with a malformed exit block (an unknown lab-only frame type Seal rejects
	// — see TestProtectorRejectsUnknownLabOnlyFrameTypeBeforeSeal), makes
	// exit.Seal fail at 22 before entry is ever touched.
	entry := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 7, HopLayer: 0, Direction: 0, Key: bytesOf(0x31, 32), StaticIV: bytesOf(0x32, 12)}
	exit := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 7, HopLayer: 1, Direction: 0, Key: bytesOf(0x41, 32), StaticIV: bytesOf(0x42, 12)}
	malformedExitBlock := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: 0x7f00}}}
	_, err := SealSplit2Onion(malformedExitBlock, entry, exit, routeForwardForPacketTest(t, 7, 1))
	if err == nil {
		t.Fatal("SealSplit2Onion accepted a malformed exit block, want exit.Seal error")
	}
	if exit.NextPacket != 0 {
		t.Fatalf("failed exit.Seal advanced exit counter to %d, want 0", exit.NextPacket)
	}
}

func TestSealSplit2BackwardOnionRequiresBothProtectors(t *testing.T) {
	// 43-45: the backward wrapper's own nil guard fires before delegation.
	zeroBlock := protocol.FrameBlock{}
	zeroForward := protocol.RouteForwardFrame{}
	if _, err := SealSplit2BackwardOnion(zeroBlock, nil, &Protector{}, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "split-2 protectors are required") {
		t.Fatalf("SealSplit2BackwardOnion(nil entry) err = %v, want substring \"split-2 protectors are required\"", err)
	}
	if _, err := SealSplit2BackwardOnion(zeroBlock, &Protector{}, nil, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "split-2 protectors are required") {
		t.Fatalf("SealSplit2BackwardOnion(nil exit) err = %v, want substring \"split-2 protectors are required\"", err)
	}
}

func TestSealSplit2BackwardOnionRejectsDifferentRouteInstances(t *testing.T) {
	// 46-48: non-nil protectors with differing route instances hit the route
	// guard before the hop/direction guards.
	zeroBlock := protocol.FrameBlock{}
	zeroForward := protocol.RouteForwardFrame{}
	entry := &Protector{RouteInstanceID: 7}
	exit := &Protector{RouteInstanceID: 8}
	if _, err := SealSplit2BackwardOnion(zeroBlock, entry, exit, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "different route instances") {
		t.Fatalf("different route instances err = %v, want substring \"different route instances\"", err)
	}
}

func TestSealSplit2BackwardOnionRejectsWrongHopLayers(t *testing.T) {
	// 49-51: matching route instances but entry.HopLayer != 0 hits the hop
	// guard.
	zeroBlock := protocol.FrameBlock{}
	zeroForward := protocol.RouteForwardFrame{}
	entry := &Protector{RouteInstanceID: 7, HopLayer: 2}
	exit := &Protector{RouteInstanceID: 7, HopLayer: 1}
	if _, err := SealSplit2BackwardOnion(zeroBlock, entry, exit, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "must be entry hop 0 and exit hop 1") {
		t.Fatalf("wrong hop layers err = %v, want substring \"must be entry hop 0 and exit hop 1\"", err)
	}
}

func TestSealSplit2BackwardOnionRejectsWrongDirection(t *testing.T) {
	// 52-54: matching route instances and hop 0/1 but entry.Direction != 1
	// hits the direction guard.
	zeroBlock := protocol.FrameBlock{}
	zeroForward := protocol.RouteForwardFrame{}
	entry := &Protector{RouteInstanceID: 7, HopLayer: 0, Direction: 0}
	exit := &Protector{RouteInstanceID: 7, HopLayer: 1, Direction: 1}
	if _, err := SealSplit2BackwardOnion(zeroBlock, entry, exit, zeroForward); err == nil ||
		!strings.Contains(err.Error(), "must use backward direction") {
		t.Fatalf("wrong direction err = %v, want substring \"must use backward direction\"", err)
	}
}

func TestDecodeForwardedPacketRequiresSingleFrame(t *testing.T) {
	// 59-61: zero frames and two frames both hit the count guard.
	if _, err := DecodeForwardedPacket(protocol.FrameBlock{}); err == nil ||
		!strings.Contains(err.Error(), "must contain one frame") {
		t.Fatalf("zero-frame err = %v, want substring \"must contain one frame\"", err)
	}
	twoFrames := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		{FrameType: registry.FrameRouteForward},
		{FrameType: registry.FrameRouteForward},
	}}
	if _, err := DecodeForwardedPacket(twoFrames); err == nil ||
		!strings.Contains(err.Error(), "must contain one frame") {
		t.Fatalf("two-frame err = %v, want substring \"must contain one frame\"", err)
	}
}

func TestDecodeForwardedPacketRequiresRouteForwardFrameType(t *testing.T) {
	// 63-65: a single frame of the wrong type hits the frame-type guard.
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	if _, err := DecodeForwardedPacket(block); err == nil ||
		!strings.Contains(err.Error(), "frame is not route-forward") {
		t.Fatalf("wrong frame type err = %v, want substring \"frame is not route-forward\"", err)
	}
}

func TestDecodeRouteForwardPayloadRejectsUndecodableBytes(t *testing.T) {
	// 76-78: a payload too short to yield a canonical RouteForwardFrame makes
	// the wire reader set r.Err(), which decodeRouteForwardPayload surfaces.
	// White-box direct call (the helper is unexported).
	if _, err := decodeRouteForwardPayload([]byte{0xff}); err == nil {
		t.Fatal("decodeRouteForwardPayload(short) err = nil, want a decode error")
	}
}

func TestDecodeRouteForwardPayloadRejectsTrailingBytes(t *testing.T) {
	// 79-81: a canonical RouteForwardFrame encoding followed by an extra byte
	// decodes cleanly (r.Err() nil) but leaves the reader not at EOF, so the
	// trailing-bytes guard fires.
	payload, err := protocol.Encode(routeForwardForPacketTest(t, 8, 1))
	if err != nil {
		t.Fatalf("Encode(forward): %v", err)
	}
	withTrailer := append(append([]byte(nil), payload...), 0x00)
	if _, err := decodeRouteForwardPayload(withTrailer); err == nil ||
		!strings.Contains(err.Error(), "trailing route-forward payload bytes") {
		t.Fatalf("decodeRouteForwardPayload(trailing) err = %v, want substring \"trailing route-forward payload bytes\"", err)
	}
}
