package session

// Adversarial white-box branch coverage for three count-0 input-validation guards
// across Application.queueBlock / Application.handlePacket (session/application.go):
//
//	func (a *Application) queueBlock(ctx, block, control, highPriority) error {
//	    if ctx == nil { ... }                                                       // :470 (covered)
//	    if err := ctx.Err(); err != nil { return err }                              // :473 <-- body COUNT 0
//	    ...
//	    if err := protocol.ValidateFrameBlockForDirection(block, writeDirection); err != nil { // :484 <-- body COUNT 0
//	        return err
//	    }
//
//	func (a *Application) handlePacket(ctx, now, encoded, owned) ([]FrameBlock, error) {
//	    if ctx == nil { ... }                                                       // :350 (covered)
//	    if err := a.terminalError(); err != nil { return nil, err }                 // :353 (terminal==nil on &Application{})
//	    if err := ctx.Err(); err != nil { return nil, err }                         // :356 <-- body COUNT 0
//	    ...
//
// queueBlock is unexported (in-package call); handlePacket is reached via the EXPORTED
// HandlePacket wrapper. All three guards fire BEFORE any crypto/state work:
//   - :473 is the first statement after the nil-ctx guard (before a.mu is locked).
//   - :484 is a pure protocol-struct check over the block (after reading a.write.Direction).
//   - :356 follows a.terminalError() which returns nil for a zero-value Application.
// So the tests are fully deterministic: no goroutine, no network, no cgo, no crypto, no
// build tag, no t.Skip.
//
// A zero-value &Application{} is safe for all three guards:
//   - :473 fires before any a.* field is dereferenced (first a.* access is a.mu.Lock() at :476).
//   - :484 dereferences a.mu (zero sync.Mutex is usable), a.terminal (nil -> :477 not taken),
//     a.write.Direction (zero value 0) — all safe.
//   - :356 dereferences a.terminalError() which reads a.terminal (nil -> returns nil) on
//     &Application{}; the encoded argument is irrelevant because :356 returns before :359.
//
// The existing nil_context_branch_coverage_test.go covers :470/:350 (nil ctx) and
// key_update_and_packet_input_validation_branch_coverage_test.go covers :44/:359 — none
// touch :473/:484/:356. The happy-path tests (newApplicationPair + valid block/packet with
// context.Background()) cover the :473/:484/:356 CONDITION lines but never the err BODIES.
//
// Not-claimed siblings: :488 (encodedPacketReservation err — needs a valid block whose
// encoded plaintext exceeds maxPacketCiphertextBytes; validate-after-validate domination or
// HEAVY oversized block), :491/:511/:534/:377 (later ctx.Err() checks — need the context to
// error MID-call after the first check passed; concurrency/timing, not deterministic),
// :477/:374/:497 (a.terminal != nil — need a terminal set via failLocked first; stateful).
//
// The per-line coverage flips (:473/:484/:356 body 0->1) are the rigorous proof.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestApplicationRejectsCancelledContextAndInvalidFrameBlock(t *testing.T) {
	a := &Application{}

	// :473 — pre-cancelled context on queueBlock. queueBlock checks ctx.Err() at :473
	// (the first statement after the :470 nil-ctx guard), before a.mu is locked. A
	// cancelled context returns context.Canceled, so :473 returns it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.queueBlock(ctx, protocol.FrameBlock{}, false, false); err == nil {
		t.Fatal("queueBlock(cancelledCtx) err = nil, want non-nil ctx.Err() (:473)")
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("queueBlock(cancelledCtx) err = %v, want errors.Is context.Canceled (:473)", err)
	}

	// :484 — invalid FrameBlock for the write direction. &Application{} has
	// write.Direction = 0 (zero value) and terminal == nil, so queueBlock reaches
	// ValidateFrameBlockForDirection(block, 0). A frame with an unknown reserved
	// FrameType (0x20; valid registry frame types are 0x01..0x11) fails ValidateFrameType
	// inside ValidateFrameBlock, so :484 returns the err before any sealing/state work.
	// context.Background() has ctx.Err()==nil so :473 is not taken.
	invalidBlock := protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{{FrameType: 0x20}},
	}
	if err := a.queueBlock(context.Background(), invalidBlock, false, false); err == nil {
		t.Fatal("queueBlock(invalidBlock) err = nil, want ValidateFrameBlockForDirection err (:484)")
	} else if !strings.Contains(err.Error(), "unknown reserved frame type") {
		t.Fatalf("queueBlock(invalidBlock) err = %v, want substring %q (:484)", err, "unknown reserved frame type")
	}

	// :356 — pre-cancelled context on the EXPORTED HandlePacket. handlePacket checks
	// ctx.Err() at :356 after a.terminalError() (nil for &Application{}, so :353 passes),
	// before the empty-packet (:359) and limit (:362) checks. A cancelled context returns
	// context.Canceled, so :356 returns it. The encoded argument is irrelevant.
	cancelledPacketCtx, cancelPacket := context.WithCancel(context.Background())
	cancelPacket()
	if _, err := a.HandlePacket(cancelledPacketCtx, time.Now(), nil); err == nil {
		t.Fatal("HandlePacket(cancelledCtx) err = nil, want non-nil ctx.Err() (:356)")
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("HandlePacket(cancelledCtx) err = %v, want errors.Is context.Canceled (:356)", err)
	}
}
