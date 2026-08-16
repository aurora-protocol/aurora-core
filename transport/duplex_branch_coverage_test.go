package transport

// Adversarial white-box coverage for the uncovered branches of
// transport/duplex.go. duplex.go imports only context, errors, fmt, io, time,
// and the protocol package; the branches below are exercised either through
// direct white-box calls of the unexported pump/handle/close helpers (single
// goroutine, fully deterministic) or through one RunPacketDuplex run that
// uses the package's existing in-memory carriers and a custom endpoint. No
// real network, no filesystem, no cryptography.
//
// Targets covered:
//
// Direct white-box (single goroutine, deterministic):
//   - handlePacketRecord:134-136 — the `ctx.Err() != nil` guard at the top of
//     handlePacketRecord. The existing suite drives handlePacketRecord only
//     with a live pump context (the read pump's pumpCtx), so the early
//     cancelled-context return is unreached. A directly cancelled context
//     reaches it before the endpoint is ever consulted.
//   - handlePacketRecord:146-149 — the `err != nil` branch after
//     HandlePacket/HandleOwnedPacket returns an error, which destroys the
//     partial blocks and propagates the error. The existing suite's
//     duplexTestEndpoint.HandlePacket always returns a nil error, and the
//     owned test endpoint returns nil blocks, so the error-destroy path is
//     unreached. A non-owned endpoint whose HandlePacket returns blocks plus
//     an error reaches it; the returned blocks are zeroed in place, which the
//     test observes through a retained payload reference.
//   - handlePacketRecord:152-154 — the `ctx.Err() != nil` guard inside the
//     per-block delivery loop. The existing suite never cancels the context
//     between a successful handle and the block loop, so the mid-loop abort is
//     unreached. A handle that returns blocks and cancels its own context
//     makes the first iteration's guard fire before the handler runs.
//   - runPacketWritePump:170-172 — the `ctx.Err() != nil` guard before the
//     carrier write. The existing suite cancels via the parent context (which
//     unblocks NextPacket at 164 before this guard) or serves a failing write
//     (which skips the guard), so the post-NextPacket cancelled-context return
//     is unreached. An endpoint whose NextPacket returns a packet and cancels
//     its own context reaches it before writer.Write is touched.
//   - classifyCarrierWriteError:192-194 — the unwrap branch for
//     ErrEmptyRecord/ErrRecordTooLarge. The existing write suite only feeds a
//     generic error (which hits the wrap branch at 195), so the unwrap branch
//     is unreached. A direct call with each record sentinel returns it
//     unwrapped (NOT wrapped in ErrCarrierWrite).
//   - closePacketDuplex:201-203 — the `err != nil && first == nil` recording
//     branch. The existing carriers' Close all return nil, so the first-error
//     recording is unreached. A direct call with a read carrier whose Close
//     returns an error records and returns it.
//
// RunPacketDuplex (goroutine, deterministic):
//   - RunPacketDuplex:95-97 — the `endpoint.Err() == nil` sub-branch of the
//     endpointDone select case, which substitutes errPacketEndpointFinished.
//     The existing endpoint-close test uses duplexTestEndpoint whose Err()
//     returns session.ErrClosed, so the nil-Err sub-branch is unreached. A
//     custom endpoint whose Done() channel closes while Err() stays nil hits
//     it. The done channel is kept SEPARATE from the NextPacket close path so
//     that closing Done does not also unblock the write pump (which would race
//     the select); the pumps stay blocked until the select commits to the
//     endpointDone case, then cancel()/closePacketDuplex unblocks them.
//
// Dead-by-design (documented, NOT claimed):
//   - RunPacketDuplex:71-73 (NewRecordReader error) and :75-77
//     (NewRecordWriter error). NewRecordReader/Writer fail only via
//     normalizeRecordMaximum (their line 39/70) or isNilLike (43/74). By the
//     time RunPacketDuplex reaches them, normalizeRecordMaximum has already
//     succeeded at 67 (otherwise 68 returned) and isNilLike(readCarrier)/
//     isNilLike(writeCarrier) have already passed at 51/54, so neither
//     constructor can fail here. Shadowed-by-earlier-check.
//   - RunPacketDuplex:117 — `return cleanupErr`. Both pumps are infinite loops
//     that return only on a non-nil error (runPacketReadPump returns
//     classifyCarrierReadError or a handle error, neither nil; runPacketWritePump
//     returns a NextPacket/write/context error, never nil), so a result on the
//     results channel is always non-nil. The other two select cases also set a
//     non-nil triggerErr (ctx.Err() for ctx.Done; endpoint.Err() or
//     errPacketEndpointFinished for endpointDone). triggerErr is therefore
//     always non-nil and 114 returns first; 117 is unreachable.
//
// Race-dependent (documented, NOT claimed):
//   - RunPacketDuplex:100-102 — the results-channel select case with a
//     concurrent cancellation (`if ctx.Err() != nil` after collecting a pump
//     result). When ctx is cancelled, ctx.Done() is ready and `select`
//     randomizes between ctx.Done() and results; there is no input that makes
//     ctx.Err() non-nil while keeping ctx.Done() unready, so the results case
//     cannot be forced to win deterministically. Leaving to concurrency fuzz.
//
// The four new endpoint/carrier types are each referenced by at least one test
// (and their methods satisfy the PacketEndpoint / io.ReadCloser interfaces
// used by the code under test), so there is nothing for staticcheck U1000. No
// literal nil context.Context is passed (no SA1012 surface).

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// nilErrDuplexEndpoint is a PacketEndpoint whose Done channel can be closed
// independently of its Close path. Err() always returns nil, so the
// endpointDone select case in RunPacketDuplex substitutes
// errPacketEndpointFinished. signalDone closes the done channel WITHOUT
// unblocking NextPacket, so the write pump stays blocked and the select
// commits to the endpointDone case deterministically (no race with a pump
// result). Close closes the NextPacket close path, used by closePacketDuplex.
type nilErrDuplexEndpoint struct {
	done       chan struct{}
	closed     chan struct{}
	doneOnce   sync.Once
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func newNilErrDuplexEndpoint() *nilErrDuplexEndpoint {
	return &nilErrDuplexEndpoint{done: make(chan struct{}), closed: make(chan struct{})}
}

func (e *nilErrDuplexEndpoint) signalDone() { e.doneOnce.Do(func() { close(e.done) }) }

func (e *nilErrDuplexEndpoint) NextPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.closed:
		return nil, errors.New("transport: nil-err endpoint closed")
	}
}

func (e *nilErrDuplexEndpoint) HandlePacket(context.Context, time.Time, []byte) ([]protocol.FrameBlock, error) {
	return nil, nil
}

func (e *nilErrDuplexEndpoint) Done() <-chan struct{} { return e.done }
func (e *nilErrDuplexEndpoint) Err() error            { return nil }
func (e *nilErrDuplexEndpoint) Close() error {
	e.closeCalls.Add(1)
	e.closeOnce.Do(func() { close(e.closed) })
	return nil
}

// errorHandleEndpoint is a non-owned PacketEndpoint (it has no
// HandleOwnedPacket method, so handlePacketRecord takes the public HandlePacket
// path) whose HandlePacket returns blocks plus a non-nil error, reaching the
// 146-149 destroy-and-return branch. The retained payload reference lets the
// test observe destroyDuplexFrameBlocks zeroing the block in place.
type errorHandleEndpoint struct {
	blocks []protocol.FrameBlock
	err    error
}

func (e *errorHandleEndpoint) NextPacket(context.Context) ([]byte, error) { return nil, nil }
func (e *errorHandleEndpoint) HandlePacket(context.Context, time.Time, []byte) ([]protocol.FrameBlock, error) {
	return e.blocks, e.err
}
func (e *errorHandleEndpoint) Done() <-chan struct{} { return nil }
func (e *errorHandleEndpoint) Err() error            { return nil }
func (e *errorHandleEndpoint) Close() error          { return nil }

// cancellingNextEndpoint's NextPacket returns a packet and cancels its own
// context, so runPacketWritePump reaches the 170-172 cancelled-context guard
// after a successful NextPacket but before writer.Write.
type cancellingNextEndpoint struct {
	cancel context.CancelFunc
}

func (e *cancellingNextEndpoint) NextPacket(context.Context) ([]byte, error) {
	e.cancel()
	return []byte("post-cancel packet"), nil
}
func (e *cancellingNextEndpoint) HandlePacket(context.Context, time.Time, []byte) ([]protocol.FrameBlock, error) {
	return nil, nil
}
func (e *cancellingNextEndpoint) Done() <-chan struct{} { return nil }
func (e *cancellingNextEndpoint) Err() error            { return nil }
func (e *cancellingNextEndpoint) Close() error          { return nil }

// errCloseReadCloser is an io.ReadCloser whose Close returns a configured
// error, used to reach closePacketDuplex's first-error recording branch.
type errCloseReadCloser struct{ err error }

func (errCloseReadCloser) Read([]byte) (int, error) { return 0, nil }
func (c errCloseReadCloser) Close() error           { return c.err }

func TestRunPacketDuplexReportsFinishedWhenEndpointDoneHasNoError(t *testing.T) {
	// 95-97: the endpointDone case fires while Err() is nil, so RunPacketDuplex
	// substitutes errPacketEndpointFinished. done is closed independently of
	// the NextPacket close path, so the write pump stays blocked and the select
	// commits to endpointDone deterministically.
	reader := newBlockingReadCloser()
	writer := &discardWriteCloser{}
	endpoint := newNilErrDuplexEndpoint()
	result := make(chan error, 1)
	go func() {
		result <- RunPacketDuplex(context.Background(), reader, writer, endpoint, discardFrameBlock, 64)
	}()
	awaitSignal(t, reader.started, "reader start")
	endpoint.signalDone()

	if err := awaitDuplexResult(t, result); !errors.Is(err, errPacketEndpointFinished) {
		t.Fatalf("RunPacketDuplex endpointDone-nil-err error = %v, want errPacketEndpointFinished", err)
	}
	requireDuplexClosedOnce(t, reader.closeCalls.Load(), writer.closeCalls.Load(), endpoint.closeCalls.Load())
}

func TestHandlePacketRecordRejectsCancelledContext(t *testing.T) {
	// 134-136: a cancelled context returns before the endpoint is consulted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handlePacketRecord(ctx, newDuplexTestEndpoint(), discardFrameBlock, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("handlePacketRecord(cancelled) err = %v, want context.Canceled", err)
	}
}

func TestHandlePacketRecordDestroysBlocksOnHandleError(t *testing.T) {
	// 146-149: a non-owned endpoint whose HandlePacket returns blocks plus an
	// error triggers the destroy-and-return path. The retained payload is
	// zeroed in place by destroyDuplexFrameBlocks.
	payload := []byte{1, 2, 3, 4}
	endpoint := &errorHandleEndpoint{
		blocks: []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{{
			FrameType: registry.FramePadding,
			Payload:   payload,
		}}}},
		err: errors.New("handle failed"),
	}
	err := handlePacketRecord(context.Background(), endpoint, discardFrameBlock, []byte("x"))
	if !errors.Is(err, endpoint.err) {
		t.Fatalf("handlePacketRecord(handle err) err = %v, want %v", err, endpoint.err)
	}
	for i, v := range payload {
		if v != 0 {
			t.Fatalf("payload[%d] = %d after handle error, want 0 (block not destroyed)", i, v)
		}
	}
}

func TestHandlePacketRecordAbortsBlockLoopOnMidHandleCancellation(t *testing.T) {
	// 152-154: a handle that returns blocks and cancels its own context makes
	// the first block-loop iteration's ctx guard fire before the handler runs.
	// 134 passes (ctx live when checked), so the cancellation must happen inside
	// the handle to land between 134 and 152.
	ctx, cancel := context.WithCancel(context.Background())
	endpoint := newDuplexTestEndpoint()
	endpoint.handle = func([]byte) []protocol.FrameBlock {
		cancel()
		return []protocol.FrameBlock{
			{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: []byte("a")}}},
			{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding, Payload: []byte("b")}}},
		}
	}
	if err := handlePacketRecord(ctx, endpoint, discardFrameBlock, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("handlePacketRecord(mid-cancel) err = %v, want context.Canceled", err)
	}
}

func TestRunPacketWritePumpAbortsBeforeWriteOnCancelledContext(t *testing.T) {
	// 170-172: NextPacket returns a packet and cancels its own context, so the
	// pre-write ctx guard fires before writer.Write is ever called. A real
	// RecordWriter is required by the signature, but its Write is never reached
	// (the guard returns first), so a discard-backed writer suffices.
	ctx, cancel := context.WithCancel(context.Background())
	writer, err := NewRecordWriter(&discardWriteCloser{}, 64)
	if err != nil {
		t.Fatalf("NewRecordWriter: %v", err)
	}
	endpoint := &cancellingNextEndpoint{cancel: cancel}
	if err := runPacketWritePump(ctx, writer, endpoint); !errors.Is(err, context.Canceled) {
		t.Fatalf("runPacketWritePump(cancelled after NextPacket) err = %v, want context.Canceled", err)
	}
}

func TestClassifyCarrierWriteErrorUnwrapsRecordSentinels(t *testing.T) {
	// 192-194: ErrEmptyRecord and ErrRecordTooLarge are returned unwrapped (not
	// wrapped in ErrCarrierWrite); any other error is wrapped (the covered
	// branch, asserted here as a contract anchor).
	for _, sentinel := range []error{ErrEmptyRecord, ErrRecordTooLarge} {
		got := classifyCarrierWriteError(sentinel)
		if !errors.Is(got, sentinel) {
			t.Fatalf("classifyCarrierWriteError(%v) = %v, want %v unwrapped", sentinel, got, sentinel)
		}
		if errors.Is(got, ErrCarrierWrite) {
			t.Fatalf("classifyCarrierWriteError(%v) = %v wrapped record sentinel in ErrCarrierWrite", sentinel, got)
		}
	}
	wrapped := classifyCarrierWriteError(errors.New("boom"))
	if !errors.Is(wrapped, ErrCarrierWrite) {
		t.Fatalf("classifyCarrierWriteError(generic) = %v, want wrapped in ErrCarrierWrite", wrapped)
	}
	if errors.Is(wrapped, ErrEmptyRecord) || errors.Is(wrapped, ErrRecordTooLarge) {
		t.Fatalf("classifyCarrierWriteError(generic) = %v, wrongly unwrapped a non-record error", wrapped)
	}
}

func TestClosePacketDuplexRecordsFirstCloseError(t *testing.T) {
	// 201-203: a carrier whose Close returns an error is the first failing
	// close (endpoint and writer close cleanly), so closePacketDuplex records
	// and surfaces it.
	readErr := errors.New("read carrier closed badly")
	err := closePacketDuplex(errCloseReadCloser{err: readErr}, &discardWriteCloser{}, newDuplexTestEndpoint())
	if !errors.Is(err, readErr) {
		t.Fatalf("closePacketDuplex err = %v, want %v", err, readErr)
	}
}
