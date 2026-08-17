package evidence

// Adversarial white-box coverage for the four count-0 validation guards of
// (*sessionEvidenceState).handle in evidence/session.go (309-337):
//
//	func (s *sessionEvidenceState) handle(_ context.Context, block protocol.FrameBlock) error {
//	    if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameStreamData { // 310
//	        return fmt.Errorf("session evidence: unexpected frame block")              // 311-312
//	    }
//	    frame := block.Frames[0]
//	    if frame.FlowID == 0 || frame.FlowID > uint64(s.options.Messages) || len(frame.Payload) != s.options.PayloadBytes { // 314
//	        return fmt.Errorf("session evidence: invalid received message")          // 315-316
//	    }
//	    id := int(frame.FlowID - 1)
//	    for _, value := range frame.Payload {                                            // 318
//	        if value != byte(id) {                                                        // 319
//	            return fmt.Errorf("session evidence: received payload mismatch")         // 320-321
//	        }
//	    }
//	    now := time.Now()
//	    s.mu.Lock()
//	    if s.seen[id] || s.sentAt[id].IsZero() {                                           // 325
//	        s.mu.Unlock()
//	        return fmt.Errorf("session evidence: duplicate or unsent message")          // 327-328
//	    }
//	    ...
//	}
//
// handle is the receiver side of the session evidence harness: RunSession pumps a
// full client/relay duplex where every queued message is well-formed, sent first,
// and received exactly once, so every handle call takes the happy path at 333-336
// and the four rejection guards at 310/314/319/325 stayed count-0 — even though each
// is plainly reachable for a hand-built frame block.
//
// handle is unexported and its ctx parameter is ignored (named _), so the guards are
// driven in-package by constructing a fresh sessionEvidenceState (via the
// unexported newSessionEvidenceState) and calling handle directly with crafted
// blocks. No network, no pipe, no goroutine. Each guard fires before any field that
// the happy path needs (310 fires before s.options is read; 314 reads only
// s.options.Messages/PayloadBytes; 319 reads only the payload; 325 reads s.seen and
// s.sentAt which a fresh state leaves zero-valued), so a freshly-constructed state is
// sufficient.
//
//   - 310 — "unexpected frame block": a block with the wrong frame count (zero or
//     two+ frames) or a single non-FrameStreamData frame. Two distinct shapes prove
//     both halves of the || (len != 1 and FrameType != FrameStreamData).
//   - 314 — "invalid received message": three distinct shapes prove all three
//     halves of the || — FlowID == 0, FlowID > Messages, and len(Payload) !=
//     PayloadBytes.
//   - 319 — "received payload mismatch": a FrameStreamData frame whose FlowID is
//     in range and whose payload length matches PayloadBytes, but whose payload
//     byte differs from byte(id) (id = FlowID - 1). The contrast is the 325 case
//     below: the same frame with a *matching* payload passes 319 and falls through
//     to 325 — the different error string proves 319 ran rather than 325.
//   - 325 — "duplicate or unsent message": a FrameStreamData frame with a matching
//     payload (so 314 and 319 pass) but whose sentAt[id] was never recorded
//     (sentAt[id].IsZero() on a fresh state). This both locks 319's contrast and
//     covers the unsent branch of the 325 ||; s.seen[id] stays false on a fresh
//     state so the duplicate branch of the || is provably not the trigger.

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestSessionEvidenceHandleRejectsUnexpectedFrameBlock(t *testing.T) {
	// 310: handle rejects a block that is not exactly one FrameStreamData frame.
	// Both halves of the || are exercised: a zero-frame block (len != 1) and a
	// single frame of the wrong type (FrameType != FrameStreamData). 310 fires
	// before s.options is read, so a state with Messages:1/PayloadBytes:1 is fine
	// (and consistent with the other cases).
	s := newSessionEvidenceState(SessionOptions{Messages: 1, PayloadBytes: 1})

	cases := []struct {
		name  string
		block protocol.FrameBlock
	}{
		{"zero frames", protocol.FrameBlock{}},
		{"two frames", protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte{0x00}},
			{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte{0x00}},
		}}},
		{"wrong frame type", protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			{FrameType: registry.FrameFlowOpen, FlowID: 1, Payload: []byte{0x00}},
		}}},
	}
	for _, tc := range cases {
		err := s.handle(context.Background(), tc.block)
		if err == nil {
			t.Fatalf("%s: handle err = nil, want non-nil (:310 should reject)", tc.name)
		}
		if !strings.Contains(err.Error(), "unexpected frame block") {
			t.Fatalf("%s: handle err = %q, want it to contain \"unexpected frame block\" (:310)", tc.name, err.Error())
		}
	}
}

func TestSessionEvidenceHandleRejectsInvalidReceivedMessage(t *testing.T) {
	// 314: handle rejects a single FrameStreamData frame whose FlowID is out of
	// range or whose payload length does not match PayloadBytes. Three cases prove
	// all three halves of the ||: FlowID == 0, FlowID > Messages, and len(Payload)
	// != PayloadBytes. Messages:1/PayloadBytes:1 makes the in-range FlowID 1 and
	// the matching payload a single byte, so each violation is minimal.
	s := newSessionEvidenceState(SessionOptions{Messages: 1, PayloadBytes: 1})

	cases := []struct {
		name  string
		block protocol.FrameBlock
	}{
		{"flow id zero", protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			{FrameType: registry.FrameStreamData, FlowID: 0, Payload: []byte{0x00}},
		}}},
		{"flow id above messages", protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			{FrameType: registry.FrameStreamData, FlowID: 99, Payload: []byte{0x00}},
		}}},
		{"payload length mismatch", protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte{0x00, 0x00}},
		}}},
	}
	for _, tc := range cases {
		err := s.handle(context.Background(), tc.block)
		if err == nil {
			t.Fatalf("%s: handle err = nil, want non-nil (:314 should reject)", tc.name)
		}
		if !strings.Contains(err.Error(), "invalid received message") {
			t.Fatalf("%s: handle err = %q, want it to contain \"invalid received message\" (:314)", tc.name, err.Error())
		}
	}
}

func TestSessionEvidenceHandleRejectsPayloadMismatch(t *testing.T) {
	// 319: a FrameStreamData frame whose FlowID is in range (1, with Messages:1
	// so 1 > Messages is false) and whose payload length matches PayloadBytes (1),
	// but whose single payload byte (0xff) differs from byte(id) where id =
	// FlowID - 1 = 0, i.e. byte(0) = 0x00. The 318 loop body runs once, the 319
	// condition is true, and handle returns "received payload mismatch".
	s := newSessionEvidenceState(SessionOptions{Messages: 1, PayloadBytes: 1})
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte{0xff}},
	}}

	err := s.handle(context.Background(), block)
	if err == nil {
		t.Fatal("handle(mismatched payload) err = nil, want non-nil (:319 should reject)")
	}
	if !strings.Contains(err.Error(), "received payload mismatch") {
		t.Fatalf("handle(mismatched payload) err = %q, want it to contain \"received payload mismatch\" (:319)", err.Error())
	}
}

func TestSessionEvidenceHandleRejectsUnsentMessage(t *testing.T) {
	// 325: a FrameStreamData frame whose FlowID is in range and whose payload
	// matches byte(id) (so 314 and 319 both pass), but whose sentAt[id] was never
	// recorded. On a fresh state s.sentAt[0] is the zero time, so
	// s.sentAt[id].IsZero() is true and the 325 || fires — via the unsent half,
	// not the duplicate half (s.seen[0] is still false on a fresh state). This is
	// also the 319 contrast: a matching payload clears 319 and falls through to
	// 325, so the "duplicate or unsent message" error (not "received payload
	// mismatch") proves 319 passed rather than fired.
	s := newSessionEvidenceState(SessionOptions{Messages: 1, PayloadBytes: 1})
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte{0x00}},
	}}

	err := s.handle(context.Background(), block)
	if err == nil {
		t.Fatal("handle(unsent matching message) err = nil, want non-nil (:325 should reject)")
	}
	if !strings.Contains(err.Error(), "duplicate or unsent message") {
		t.Fatalf("handle(unsent matching message) err = %q, want it to contain \"duplicate or unsent message\" (:325)", err.Error())
	}
	if strings.Contains(err.Error(), "received payload mismatch") {
		t.Fatalf("handle(unsent matching message) err = %q, must NOT be the 319 mismatch (the payload matches, so 319 passes)", err.Error())
	}
}
