package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/session"
)

type recordingEgress struct {
	events     []ExitFrameEvent
	frames     map[uint64][]protocol.AuroraFrame
	err        error
	closeCalls int
}

func (e *recordingEgress) HandleEvent(_ context.Context, event ExitFrameEvent) ([]protocol.AuroraFrame, error) {
	e.events = append(e.events, event)
	return append([]protocol.AuroraFrame(nil), e.frames[event.FlowID]...), e.err
}

func (e *recordingEgress) Close() error {
	e.closeCalls++
	return nil
}

type recordingFrameSink struct {
	blocks    []protocol.FrameBlock
	responses []error
	err       error
	calls     int
}

type blockingBackpressureSink struct {
	called chan struct{}
}

func (s *blockingBackpressureSink) QueueFrames(context.Context, protocol.FrameBlock) error {
	select {
	case s.called <- struct{}{}:
	default:
	}
	return session.ErrBackpressure
}

func (s *recordingFrameSink) QueueFrames(_ context.Context, block protocol.FrameBlock) error {
	s.calls++
	if len(s.responses) >= s.calls && s.responses[s.calls-1] != nil {
		return s.responses[s.calls-1]
	}
	if s.err != nil {
		return s.err
	}
	s.blocks = append(s.blocks, block)
	return nil
}

func TestExitSessionRejectsMalformedBlockBeforeEgress(t *testing.T) {
	egress := &recordingEgress{}
	sink := &recordingFrameSink{}
	session, err := NewExitSession(egress, sink, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	err = session.HandleFrameBlock(context.Background(), protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{{FrameType: 0x01, FlowID: 1}},
	})
	if err == nil {
		t.Fatal("HandleFrameBlock accepted an empty data frame")
	}
	if len(egress.events) != 0 {
		t.Fatalf("egress received %d events after validation failure", len(egress.events))
	}
	if len(sink.blocks) != 0 {
		t.Fatalf("sink received %d blocks after validation failure", len(sink.blocks))
	}
}

func TestExitSessionRetriesQueueBackpressure(t *testing.T) {
	egress := &recordingEgress{}
	sink := &recordingFrameSink{responses: []error{session.ErrBackpressure}}
	exitSession, err := NewExitSession(egress, sink, ExitSessionOptions{
		QueueRetryInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })

	open := relayUDPFlowOpen(41, []byte{93, 184, 216, 34})
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{
		Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)},
	}); err != nil {
		t.Fatalf("HandleFrameBlock failed: %v", err)
	}
	if sink.calls != 2 {
		t.Fatalf("QueueFrames calls = %d, want 2", sink.calls)
	}
	if len(sink.blocks) != 1 || len(sink.blocks[0].Frames) != 1 {
		t.Fatalf("queued blocks = %#v, want one UDP confirmation", sink.blocks)
	}
}

func TestNewExitSessionRejectsInvalidDependenciesAndRetry(t *testing.T) {
	validEgress := &recordingEgress{}
	validSink := &recordingFrameSink{}
	tests := []struct {
		name   string
		egress Egress
		sink   FrameSink
		opts   ExitSessionOptions
	}{
		{name: "nil egress", sink: validSink},
		{name: "typed nil egress", egress: (*recordingEgress)(nil), sink: validSink},
		{name: "nil sink", egress: validEgress},
		{name: "typed nil sink", egress: validEgress, sink: (*recordingFrameSink)(nil)},
		{name: "negative retry", egress: validEgress, sink: validSink, opts: ExitSessionOptions{QueueRetryInterval: -time.Millisecond}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := NewExitSession(test.egress, test.sink, test.opts); err == nil {
				_ = got.Close()
				t.Fatal("NewExitSession accepted invalid input")
			}
		})
	}
}

func TestExitSessionCloseIsIdempotentAndTerminal(t *testing.T) {
	egress := &recordingEgress{}
	exitSession, err := NewExitSession(egress, &recordingFrameSink{}, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	if err := exitSession.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := exitSession.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if egress.closeCalls != 1 {
		t.Fatalf("egress Close calls = %d, want 1", egress.closeCalls)
	}

	err = exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{})
	if !errors.Is(err, ErrExitSessionClosed) {
		t.Fatalf("HandleFrameBlock after Close error = %v, want ErrExitSessionClosed", err)
	}
}

func TestExitSessionCloseInterruptsBackpressure(t *testing.T) {
	sink := &blockingBackpressureSink{called: make(chan struct{}, 1)}
	exitSession, err := NewExitSession(&recordingEgress{}, sink, ExitSessionOptions{
		QueueRetryInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	open := relayUDPFlowOpen(42, []byte{93, 184, 216, 34})
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}
	handleResult := make(chan error, 1)
	go func() {
		handleResult <- exitSession.HandleFrameBlock(ctx, block)
	}()
	select {
	case <-sink.called:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("QueueFrames was not called")
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- exitSession.Close() }()
	var closeTimedOut bool
	select {
	case err := <-closeResult:
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		closeTimedOut = true
		cancel()
		<-closeResult
	}
	if err := <-handleResult; !errors.Is(err, ErrExitSessionClosed) {
		t.Errorf("HandleFrameBlock error = %v, want ErrExitSessionClosed", err)
	}
	if closeTimedOut {
		t.Fatal("Close did not interrupt queue backpressure")
	}
}

func TestExitSessionPreservesImmediateResponseOrder(t *testing.T) {
	closeFrame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
		FlowID:    51,
		CloseCode: protocol.CloseTargetUnreachable,
	})
	if err != nil {
		t.Fatalf("NewFlowCloseFrame failed: %v", err)
	}
	egress := &recordingEgress{frames: map[uint64][]protocol.AuroraFrame{51: {closeFrame}}}
	sink := &recordingFrameSink{}
	exitSession, err := NewExitSession(egress, sink, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })

	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		flowOpenFrame(t, relayTCPFlowOpen(51, "example.com")),
		flowOpenFrame(t, relayUDPFlowOpen(52, []byte{93, 184, 216, 34})),
	}}
	if err := exitSession.HandleFrameBlock(context.Background(), block); err != nil {
		t.Fatalf("HandleFrameBlock failed: %v", err)
	}
	if len(sink.blocks) != 1 || len(sink.blocks[0].Frames) != 2 {
		t.Fatalf("queued blocks = %#v, want one two-frame block", sink.blocks)
	}
	got := sink.blocks[0].Frames
	if got[0].FlowID != 51 || got[1].FlowID != 52 {
		t.Fatalf("response flow order = [%d %d], want [51 52]", got[0].FlowID, got[1].FlowID)
	}
}

func TestExitSessionRejectsCanceledContextBeforeMutation(t *testing.T) {
	egress := &recordingEgress{}
	exitSession, err := NewExitSession(egress, &recordingFrameSink{}, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		flowOpenFrame(t, relayTCPFlowOpen(61, "example.com")),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exitSession.HandleFrameBlock(ctx, block); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled HandleFrameBlock error = %v, want context.Canceled", err)
	}
	if len(egress.events) != 0 {
		t.Fatalf("egress received %d events from canceled call", len(egress.events))
	}
	if err := exitSession.HandleFrameBlock(context.Background(), block); err != nil {
		t.Fatalf("fresh HandleFrameBlock failed after canceled call: %v", err)
	}
}

func TestExitSessionReturnsEgressErrorWithoutQueueing(t *testing.T) {
	want := errors.New("egress unavailable")
	egress := &recordingEgress{err: want}
	sink := &recordingFrameSink{}
	exitSession, err := NewExitSession(egress, sink, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{
		flowOpenFrame(t, relayTCPFlowOpen(62, "example.com")),
	}}
	if err := exitSession.HandleFrameBlock(context.Background(), block); !errors.Is(err, want) {
		t.Fatalf("HandleFrameBlock error = %v, want egress error", err)
	}
	if sink.calls != 0 {
		t.Fatalf("QueueFrames calls = %d after egress failure, want 0", sink.calls)
	}
}

func TestExitSessionReturnsTerminalSinkErrorWithoutRetry(t *testing.T) {
	want := errors.New("sink unavailable")
	sink := &recordingFrameSink{err: want}
	exitSession, err := NewExitSession(&recordingEgress{}, sink, ExitSessionOptions{})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() { _ = exitSession.Close() })
	open := relayUDPFlowOpen(63, []byte{93, 184, 216, 34})
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}
	if err := exitSession.HandleFrameBlock(context.Background(), block); !errors.Is(err, want) {
		t.Fatalf("HandleFrameBlock error = %v, want sink error", err)
	}
	if sink.calls != 1 {
		t.Fatalf("QueueFrames calls = %d, want 1", sink.calls)
	}
}
