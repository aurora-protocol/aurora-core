package session

// Adversarial white-box coverage for the pure-helper surface of
// session/key_update.go. key_update.go orchestrates the session-layer key
// update (rekey) on top of an Application: InitiateKeyUpdate prepares and
// queues a write-side update, and handleKeyControlsLocked consumes
// update/ack frames on the read side. Those two runtime paths need a fully
// constructed Application with live crypto protectors and real packet buffers,
// so they are integration surfaces and are NOT targeted here. The uncovered
// branches below all live in the package-level pure helpers that the runtime
// paths delegate to — deterministic wire decoders, a control-frame scanner, a
// reservation estimator, and a nil-safe queued-packet destructor — none of
// which touch the Application, the mutexes, the clock, the network, or the
// filesystem.
//
// Targets covered:
//
//   - queuedPacket.Destroy:25-27 — the `p == nil` guard. The existing suite
//     always destroys a constructed queuedPacket, so the nil-receiver no-op is
//     unreached. A nil *queuedPacket returns before zeroBytes runs.
//   - decodeKeyUpdate:431-433 — the wire.Reader error propagation. The existing
//     suite decodes only well-formed key updates, so the short-read
//     propagation is unreached. An empty/nil payload makes DecodeKeyUpdate's
//     first ReadVarint hit EOF, so r.Err() is set and decodeKeyUpdate surfaces
//     it. (The exact Go/wire error string is version-dependent, so assert
//     non-nil.)
//   - decodeKeyUpdate:434-436 — the trailing-bytes guard. The existing suite
//     decodes exactly-framed updates, so the "trailing key update payload
//     bytes" return is unreached. A complete KeyUpdate encoding followed by a
//     single extra byte decodes fully (r.Err() is nil) but leaves r.EOF()
//     false, so the guard fires.
//   - decodeKeyUpdateACK:443-445 — the symmetric wire.Reader error propagation
//     for the acknowledgement decoder, reached with an empty payload.
//   - decodeKeyUpdateACK:446-448 — the symmetric trailing-bytes guard, reached
//     with a complete KeyUpdateACK encoding plus a trailing byte.
//   - keyUpdateReservation:464-466 — the `state.KeyPhase == 255` guard. The
//     existing suite reserves for live key states below the phase ceiling, so
//     the "KEY_UPDATE key phase exhausted" return is unreached. A
//     packet.DirectionState with KeyPhase 255 hits it before any frame block is
//     encoded, so no Application is needed.
//   - scanKeyControls:383-385 — the `block == nil` guard. The existing suite
//     always passes a real frame block, so the "missing frame block" return is
//     unreached.
//   - scanKeyControls:396-399 — the decodeKeyUpdate error propagation. The
//     existing suite scans only well-formed update frames, so the propagation
//     is unreached. A KeyUpdate-typed frame with a truncated payload makes
//     decodeKeyUpdate fail and scanKeyControls surfaces it (after Destroying the
//     partial controls).
//   - scanKeyControls:408-411 — the symmetric decodeKeyUpdateACK error
//     propagation, reached with a KeyUpdateAck-typed frame carrying a
//     truncated payload.
//
// Dead-by-design (documented, NOT claimed):
//   - keyUpdateFrameBlock:454-456, keyUpdateReservation:477-479, and
//     keyUpdateACKFrameBlock:486-488 — the protocol.Encode errors. Encode of a
//     KeyUpdate/KeyUpdateACK fails only on an oversized field; every field is a
//     varint, a single byte, or an Opaque16 (bounded to 64 KiB, far below the
//     16 MiB oversized threshold), so the encoder cannot fail for these
//     structs. Encode-can't-fail (the same family as the protocol Encode
//     helpers left uncovered across the codebase). keyUpdateReservation:477 is
//     additionally shadowed: the only caller path reaches it after the
//     KeyPhase==255 guard (464) passes, so the constructed block's fields are
//     all bounded and Encode cannot fail.
//
// No new package-level helpers or types are introduced (only test functions and
// inline literals), so there is nothing for staticcheck U1000. No context.Context
// (no SA1012 surface), no goroutines, no cryptography, no real network or
// filesystem.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestQueuedPacketDestroyNilReceiverIsSafe(t *testing.T) {
	// 25-27: a nil *queuedPacket returns before zeroBytes runs.
	var p *queuedPacket
	p.Destroy()
}

func TestDecodeKeyUpdateRejectsTruncatedAndTrailing(t *testing.T) {
	// 431-433: an empty payload makes DecodeKeyUpdate's first ReadVarint hit
	// EOF, so r.Err() is set and decodeKeyUpdate surfaces it. The exact wire
	// error string is version-dependent, so assert non-nil.
	if _, err := decodeKeyUpdate(nil); err == nil {
		t.Fatal("decodeKeyUpdate(nil) err = nil, want short-read error")
	}

	// 434-436: a complete KeyUpdate encoding plus a trailing byte decodes fully
	// (r.Err() is nil) but leaves r.EOF() false, so the trailing-bytes guard
	// fires with our own message.
	encoded, err := protocol.Encode(protocol.KeyUpdate{})
	if err != nil {
		t.Fatalf("protocol.Encode(KeyUpdate{}): %v", err)
	}
	if _, err := decodeKeyUpdate(append(encoded, 0xFF)); err == nil ||
		!strings.Contains(err.Error(), "trailing key update payload bytes") {
		t.Fatalf("decodeKeyUpdate(trailing) err = %v, want substring \"trailing key update payload bytes\"", err)
	}
}

func TestDecodeKeyUpdateACKRejectsTruncatedAndTrailing(t *testing.T) {
	// 443-445: the symmetric wire.Reader error propagation for the
	// acknowledgement decoder, reached with an empty payload.
	if _, err := decodeKeyUpdateACK(nil); err == nil {
		t.Fatal("decodeKeyUpdateACK(nil) err = nil, want short-read error")
	}

	// 446-448: the symmetric trailing-bytes guard, reached with a complete
	// KeyUpdateACK encoding plus a trailing byte.
	encoded, err := protocol.Encode(protocol.KeyUpdateACK{})
	if err != nil {
		t.Fatalf("protocol.Encode(KeyUpdateACK{}): %v", err)
	}
	if _, err := decodeKeyUpdateACK(append(encoded, 0xFF)); err == nil ||
		!strings.Contains(err.Error(), "trailing key update acknowledgement payload bytes") {
		t.Fatalf("decodeKeyUpdateACK(trailing) err = %v, want substring \"trailing key update acknowledgement payload bytes\"", err)
	}
}

func TestKeyUpdateReservationRejectsExhaustedPhase(t *testing.T) {
	// 464-466: a DirectionState at the phase ceiling (KeyPhase 255) hits the
	// guard before any frame block is encoded, so no Application is needed.
	_, err := keyUpdateReservation(packet.DirectionState{KeyPhase: 255}, 0)
	if err == nil ||
		!strings.Contains(err.Error(), "KEY_UPDATE key phase exhausted") {
		t.Fatalf("keyUpdateReservation(KeyPhase 255) err = %v, want substring \"KEY_UPDATE key phase exhausted\"", err)
	}
}

func TestScanKeyControlsRejectsNilBlockAndMalformedFrames(t *testing.T) {
	// 383-385: a nil frame block fails the guard before Frames is dereferenced.
	if _, err := scanKeyControls(nil); err == nil ||
		!strings.Contains(err.Error(), "missing frame block") {
		t.Fatalf("scanKeyControls(nil) err = %v, want substring \"missing frame block\"", err)
	}

	// 396-399: a KeyUpdate-typed frame with a truncated payload makes
	// decodeKeyUpdate fail and scanKeyControls surfaces the error (after
	// Destroying the partial controls). The wire error is version-dependent,
	// so assert non-nil.
	if _, err := scanKeyControls(&protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{{
			FrameType: registry.FrameKeyUpdate,
			Payload:   []byte{0x01},
		}},
	}); err == nil {
		t.Fatal("scanKeyControls(truncated KeyUpdate) err = nil, want decode error")
	}

	// 408-411: the symmetric propagation for a KeyUpdateAck-typed frame with a
	// truncated payload.
	if _, err := scanKeyControls(&protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{{
			FrameType: registry.FrameKeyUpdateAck,
			Payload:   []byte{0x01},
		}},
	}); err == nil {
		t.Fatal("scanKeyControls(truncated KeyUpdateAck) err = nil, want decode error")
	}
}
