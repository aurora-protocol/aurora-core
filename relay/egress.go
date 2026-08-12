package relay

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/session"
)

const defaultExitQueueRetryInterval = 5 * time.Millisecond

const maximumExitQueueRetryInterval = time.Second

var ErrExitSessionClosed = errors.New("relay: exit session closed")

// FrameSink queues validated backward frames for the authenticated session.
type FrameSink interface {
	QueueFrames(context.Context, protocol.FrameBlock) error
}

// Egress consumes only events emitted by ExitFlowHandler.
type Egress interface {
	HandleEvent(context.Context, ExitFrameEvent) ([]protocol.AuroraFrame, error)
	Close() error
}

type ExitSessionOptions struct {
	Policy             ExitPolicy
	RateLimit          ExitRateLimit
	UDPConfirmTTL      uint32
	QueueRetryInterval time.Duration
}

// ExitSession serializes validation, destination I/O, and immediate responses.
type ExitSession struct {
	mu        sync.Mutex
	closeOnce sync.Once
	closing   chan struct{}
	validator *ExitFlowHandler
	egress    Egress
	sink      FrameSink
	retry     time.Duration
	closed    bool
	closeErr  error
}

func NewExitSession(egress Egress, sink FrameSink, options ExitSessionOptions) (*ExitSession, error) {
	if isNilExitDependency(egress) {
		return nil, fmt.Errorf("relay: egress is required")
	}
	if isNilExitDependency(sink) {
		return nil, fmt.Errorf("relay: frame sink is required")
	}
	validator := NewExitFlowHandler(options.Policy)
	if options.RateLimit != (ExitRateLimit{}) {
		validator.RateLimit = options.RateLimit
	}
	if options.UDPConfirmTTL != 0 {
		validator.UDPConfirmTTLSeconds = options.UDPConfirmTTL
	}
	retry := options.QueueRetryInterval
	if retry == 0 {
		retry = defaultExitQueueRetryInterval
	}
	if retry < 0 || retry > maximumExitQueueRetryInterval {
		return nil, fmt.Errorf("relay: queue retry interval is invalid")
	}
	return &ExitSession{
		closing:   make(chan struct{}),
		validator: validator,
		egress:    egress,
		sink:      sink,
		retry:     retry,
	}, nil
}

func (s *ExitSession) HandleFrameBlock(ctx context.Context, block protocol.FrameBlock) error {
	if ctx == nil {
		return fmt.Errorf("relay: nil exit session context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closing:
		return ErrExitSessionClosed
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := s.validator.HandleFrameBlock(block, uint64(time.Now().Unix()))
	if err != nil {
		return err
	}
	var outbound []protocol.AuroraFrame
	for _, event := range result.Events {
		if err := ctx.Err(); err != nil {
			return err
		}
		frames, err := s.egress.HandleEvent(ctx, event)
		if err != nil {
			return err
		}
		outbound = appendAuroraFrames(outbound, event.immediateFrames)
		outbound = appendAuroraFrames(outbound, frames)
	}
	if len(outbound) == 0 {
		return nil
	}
	return s.queueFrames(ctx, protocol.FrameBlock{Frames: outbound})
}

func (s *ExitSession) queueFrames(ctx context.Context, block protocol.FrameBlock) error {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		err := s.sink.QueueFrames(ctx, block)
		if !errors.Is(err, session.ErrBackpressure) {
			return err
		}
		if timer == nil {
			timer = time.NewTimer(s.retry)
		} else {
			timer.Reset(s.retry)
		}
		select {
		case <-s.closing:
			timer.Stop()
			return ErrExitSessionClosed
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *ExitSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { close(s.closing) })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.closeErr = s.egress.Close()
	return s.closeErr
}

func isNilExitDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
