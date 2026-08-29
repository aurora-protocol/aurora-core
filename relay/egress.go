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

// Egress consumes only events emitted by ExitFlowHandler. Close must safely interrupt an in-flight HandleEvent call.
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
	session := &ExitSession{
		closing:   make(chan struct{}),
		validator: validator,
		egress:    egress,
		sink:      sink,
		retry:     retry,
	}
	if observable, ok := egress.(flowCloseObservableEgress); ok {
		observable.SetFlowCloseObserver(session.observeLocalClose)
	}
	return session, nil
}

// flowCloseObservableEgress reports the FLOW_CLOSE frames its read pumps send
// so the validator can drain and purge flows the relay closed on its own.
type flowCloseObservableEgress interface {
	SetFlowCloseObserver(func(flowID, closeCode uint64))
}

func (s *ExitSession) observeLocalClose(flowID, closeCode uint64) {
	s.validator.markLocalClose(flowID, closeCode, uint64(time.Now().Unix()))
}

// recoverFlowFailure maps an egress failure that concerns only one flow to the
// frames that close that flow towards the client. It reports false for
// failures that must still terminate the session (lifecycle, contract, and
// context errors).
func (s *ExitSession) recoverFlowFailure(event ExitFrameEvent, err error, now uint64) ([]protocol.AuroraFrame, bool, error) {
	switch event.Kind {
	case ExitEventFlowOpened:
		code, ok := exitFlowOpenFailureCloseCode(err)
		if !ok {
			return nil, false, nil
		}
		frame, frameErr := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: event.FlowID, CloseCode: code})
		if frameErr != nil {
			return nil, false, frameErr
		}
		s.validator.markLocalClose(event.FlowID, code, now)
		return []protocol.AuroraFrame{frame}, true, nil
	case ExitEventStreamData, ExitEventDatagramData:
		// The egress already closed the flow (its pump sends the FLOW_CLOSE) or
		// the flow raced a relay-side close; the frame is simply dropped.
		if errors.Is(err, ErrExitFlowUnknown) || errors.Is(err, ErrExitWriteFailed) || errors.Is(err, ErrExitDatagramLarge) {
			return nil, true, nil
		}
	case ExitEventDNSMessage:
		if errors.Is(err, ErrExitDNSMessageInvalid) {
			return nil, true, nil
		}
	case ExitEventFlowClosed:
		if errors.Is(err, ErrExitCloseFailed) {
			return nil, true, nil
		}
	}
	return nil, false, nil
}

func exitFlowOpenFailureCloseCode(err error) (uint64, bool) {
	switch {
	case errors.Is(err, ErrExitDialFailed), errors.Is(err, ErrExitResolveFailed):
		return protocol.CloseTargetUnreachable, true
	case errors.Is(err, ErrExitPolicyDenied):
		return protocol.ClosePolicyDenied, true
	case errors.Is(err, ErrExitFlowLimit), errors.Is(err, ErrExitDuplicateFlow):
		// A flow ID the egress still holds is a resource condition, not a
		// protocol violation: a TCP flow the client half-closed keeps its
		// socket (and its ID) until the destination stops sending, which
		// outlives the validator's much shorter close drain.
		return protocol.CloseResourceLimit, true
	case errors.Is(err, ErrExitTargetInvalid):
		return protocol.CloseMalformedFlow, true
	default:
		return 0, false
	}
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
	now := uint64(time.Now().Unix())
	result, err := s.validator.HandleFrameBlock(block, now)
	if err != nil {
		return err
	}
	for _, event := range result.Events {
		if err := ctx.Err(); err != nil {
			return err
		}
		outbound := appendAuroraFrames(nil, event.immediateFrames)
		if event.Kind != ExitEventFlowRefused {
			frames, err := s.egress.HandleEvent(ctx, event)
			if err != nil {
				closeFrames, recovered, recoverErr := s.recoverFlowFailure(event, err, now)
				if recoverErr != nil {
					return recoverErr
				}
				if !recovered {
					return err
				}
				// A refused open supersedes any confirmation queued for it.
				outbound = appendAuroraFrames(nil, closeFrames)
			} else {
				outbound = appendAuroraFrames(outbound, frames)
			}
		}
		if len(outbound) != 0 {
			if err := s.queueFrames(ctx, protocol.FrameBlock{Frames: outbound}); err != nil {
				return err
			}
		}
	}
	return nil
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
	s.closeOnce.Do(func() {
		close(s.closing)
		s.closeErr = s.egress.Close()
	})
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
