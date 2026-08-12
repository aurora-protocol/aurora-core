package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
)

const (
	defaultSocketEgressFlows         = 256
	maximumSocketEgressFlows         = 4096
	defaultSocketEgressBufferedBytes = 16 << 20
	maximumSocketEgressBufferedBytes = 64 << 20
	defaultTCPReadBufferBytes        = 32 << 10
	maximumTCPReadBufferBytes        = 1 << 20
	defaultMaxUDPDatagramBytes       = 65535
	maximumUDPDatagramBytes          = 65535
	defaultSocketDialTimeout         = 10 * time.Second
	defaultSocketWriteTimeout        = 10 * time.Second
	defaultSocketIdleTimeout         = 2 * time.Minute
	maximumSocketOperationTimeout    = time.Minute
	maximumSocketIdleTimeout         = 24 * time.Hour
	defaultSocketResolvedTTLSeconds  = 300
	maximumSocketResolvedTTLSeconds  = 86400
	minimumSocketReadBufferBytes     = 1024
	minimumSocketUDPDatagramBytes    = 512
)

var (
	ErrSocketEgressClosed = errors.New("relay: socket egress closed")
	ErrExitPolicyDenied   = errors.New("relay: exit policy denied target")
	ErrExitFlowLimit      = errors.New("relay: exit flow limit exceeded")
	ErrExitDuplicateFlow  = errors.New("relay: duplicate exit flow")
	ErrExitTargetInvalid  = errors.New("relay: invalid exit target")
	ErrExitResolveFailed  = errors.New("relay: exit target resolution failed")
	ErrExitDialFailed     = errors.New("relay: exit target dial failed")
	ErrExitCloseFailed    = errors.New("relay: exit socket close failed")
	ErrExitEventInvalid   = errors.New("relay: invalid exit event")
)

type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type SocketEgressLimits struct {
	MaxFlows            int
	MaxBufferedBytes    int
	TCPReadBufferBytes  int
	MaxUDPDatagramBytes int
	DialTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	QueueRetryInterval  time.Duration
	ResolvedTTLSeconds  uint32
}

type SocketEgressOptions struct {
	Sink     FrameSink
	Policy   ExitPolicy
	Dialer   ContextDialer
	Resolver IPResolver
	Limits   SocketEgressLimits
}

type SocketEgress struct {
	ctx      context.Context
	cancel   context.CancelFunc
	sink     FrameSink
	policy   ExitPolicy
	dialer   ContextDialer
	resolver IPResolver
	limits   SocketEgressLimits

	mu        sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	flows     map[uint64]*socketFlow
	buffered  int
	closed    bool
	closeErr  error
	wg        sync.WaitGroup
}

type socketFlow struct {
	conn        net.Conn
	bufferBytes int
}

func NewSocketEgress(ctx context.Context, options SocketEgressOptions) (*SocketEgress, error) {
	if ctx == nil {
		return nil, fmt.Errorf("relay: nil socket egress context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isNilExitDependency(options.Sink) {
		return nil, fmt.Errorf("relay: socket egress frame sink is required")
	}
	if isNilExitDependency(options.Dialer) {
		return nil, fmt.Errorf("relay: socket egress dialer is required")
	}
	if isNilExitDependency(options.Resolver) {
		return nil, fmt.Errorf("relay: socket egress resolver is required")
	}
	limits, err := normalizeSocketEgressLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	lifecycleCtx, cancel := context.WithCancel(ctx)
	return &SocketEgress{
		ctx:      lifecycleCtx,
		cancel:   cancel,
		sink:     options.Sink,
		policy:   options.Policy,
		dialer:   options.Dialer,
		resolver: options.Resolver,
		limits:   limits,
		done:     make(chan struct{}),
		flows:    make(map[uint64]*socketFlow),
	}, nil
}

func (e *SocketEgress) HandleEvent(ctx context.Context, event ExitFrameEvent) ([]protocol.AuroraFrame, error) {
	if ctx == nil {
		return nil, fmt.Errorf("relay: nil socket egress event context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.beginOperation(); err != nil {
		return nil, err
	}
	defer e.wg.Done()
	if event.Kind != ExitEventFlowOpened || event.FlowID == 0 || event.Flow.FlowID != event.FlowID {
		return nil, ErrExitEventInvalid
	}
	flow, err := e.reserveFlow(event.Flow)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			e.releaseFlow(event.FlowID, flow)
		}
	}()

	opCtx, stop := e.operationContext(ctx, e.limits.DialTimeout)
	defer stop()
	target, err := e.selectTarget(opCtx, event.Flow)
	if err != nil {
		return nil, err
	}
	conn, err := e.dialer.DialContext(opCtx, target.network, target.address)
	if err != nil || isNilExitDependency(conn) {
		if lifecycleErr := e.lifecycleError(ctx); lifecycleErr != nil {
			return nil, lifecycleErr
		}
		return nil, ErrExitDialFailed
	}
	if err := e.installFlow(event.FlowID, flow, conn, ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	keep = true
	return nil, nil
}

func (e *SocketEgress) beginOperation() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return ErrSocketEgressClosed
	}
	e.wg.Add(1)
	return nil
}

type selectedSocketTarget struct {
	network string
	address string
}

func (e *SocketEgress) selectTarget(ctx context.Context, flow coreflow.FlowState) (selectedSocketTarget, error) {
	if flow.TargetPort == 0 {
		return selectedSocketTarget{}, ErrExitTargetInvalid
	}
	var addr netip.Addr
	switch flow.TargetKind {
	case coreflow.TargetKindIPv4, coreflow.TargetKindIPv6:
		var ok bool
		addr, ok = addrFromFlowTarget(flow.TargetKind, flow.TargetHost)
		if !ok {
			return selectedSocketTarget{}, ErrExitTargetInvalid
		}
		if !e.policy.AllowIP(addr.String()) {
			return selectedSocketTarget{}, ErrExitPolicyDenied
		}
	case coreflow.TargetKindDomainName:
		domain := string(flow.TargetHost)
		if !e.policy.AllowDomain(domain) {
			return selectedSocketTarget{}, ErrExitPolicyDenied
		}
		if flow.Kind == coreflow.FlowKindUDPAssociation && flow.UDPFQDNMode != coreflow.UDPFQDNRelayResolvedFlowBound {
			return selectedSocketTarget{}, ErrExitTargetInvalid
		}
		answers, err := e.resolver.LookupNetIP(ctx, "ip", domain)
		if err != nil {
			if lifecycleErr := e.lifecycleError(ctx); lifecycleErr != nil {
				return selectedSocketTarget{}, lifecycleErr
			}
			return selectedSocketTarget{}, ErrExitResolveFailed
		}
		allowed := make(map[netip.Addr]struct{}, len(answers))
		for _, answer := range answers {
			answer = answer.Unmap()
			if !answer.IsValid() || answer.Zone() != "" || (!answer.Is4() && !answer.Is6()) {
				return selectedSocketTarget{}, ErrExitResolveFailed
			}
			if !e.policy.AllowIP(answer.String()) {
				return selectedSocketTarget{}, ErrExitPolicyDenied
			}
			allowed[answer] = struct{}{}
		}
		if len(allowed) == 0 {
			return selectedSocketTarget{}, ErrExitResolveFailed
		}
		ordered := make([]netip.Addr, 0, len(allowed))
		for answer := range allowed {
			ordered = append(ordered, answer)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].Compare(ordered[j]) < 0 })
		addr = ordered[0]
	default:
		return selectedSocketTarget{}, ErrExitTargetInvalid
	}

	network := "tcp6"
	if flow.Kind == coreflow.FlowKindUDPAssociation {
		network = "udp6"
	} else if flow.Kind != coreflow.FlowKindTCPStream {
		return selectedSocketTarget{}, ErrExitTargetInvalid
	}
	if addr.Is4() {
		if flow.Kind == coreflow.FlowKindUDPAssociation {
			network = "udp4"
		} else {
			network = "tcp4"
		}
	}
	return selectedSocketTarget{
		network: network,
		address: net.JoinHostPort(addr.String(), strconv.Itoa(int(flow.TargetPort))),
	}, nil
}

func (e *SocketEgress) reserveFlow(state coreflow.FlowState) (*socketFlow, error) {
	var bufferBytes int
	switch state.Kind {
	case coreflow.FlowKindTCPStream:
		bufferBytes = e.limits.TCPReadBufferBytes
	case coreflow.FlowKindUDPAssociation:
		bufferBytes = e.limits.MaxUDPDatagramBytes + 1
	default:
		return nil, ErrExitTargetInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return nil, ErrSocketEgressClosed
	}
	if _, ok := e.flows[state.FlowID]; ok {
		return nil, ErrExitDuplicateFlow
	}
	if len(e.flows) >= e.limits.MaxFlows || bufferBytes > e.limits.MaxBufferedBytes-e.buffered {
		return nil, ErrExitFlowLimit
	}
	flow := &socketFlow{bufferBytes: bufferBytes}
	e.flows[state.FlowID] = flow
	e.buffered += bufferBytes
	return flow, nil
}

func (e *SocketEgress) installFlow(flowID uint64, flow *socketFlow, conn net.Conn, ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return ErrSocketEgressClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.flows[flowID] != flow {
		return ErrSocketEgressClosed
	}
	flow.conn = conn
	return nil
}

func (e *SocketEgress) releaseFlow(flowID uint64, flow *socketFlow) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.flows[flowID] != flow {
		return
	}
	delete(e.flows, flowID)
	e.buffered -= flow.bufferBytes
}

func (e *SocketEgress) operationContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	stop := context.AfterFunc(e.ctx, cancel)
	return opCtx, func() {
		stop()
		cancel()
	}
}

func (e *SocketEgress) lifecycleError(ctx context.Context) error {
	if e.ctx.Err() != nil {
		return ErrSocketEgressClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func normalizeSocketEgressLimits(limits SocketEgressLimits) (SocketEgressLimits, error) {
	if limits == (SocketEgressLimits{}) {
		return SocketEgressLimits{
			MaxFlows:            defaultSocketEgressFlows,
			MaxBufferedBytes:    defaultSocketEgressBufferedBytes,
			TCPReadBufferBytes:  defaultTCPReadBufferBytes,
			MaxUDPDatagramBytes: defaultMaxUDPDatagramBytes,
			DialTimeout:         defaultSocketDialTimeout,
			WriteTimeout:        defaultSocketWriteTimeout,
			IdleTimeout:         defaultSocketIdleTimeout,
			QueueRetryInterval:  defaultExitQueueRetryInterval,
			ResolvedTTLSeconds:  defaultSocketResolvedTTLSeconds,
		}, nil
	}
	if limits.MaxFlows <= 0 || limits.MaxFlows > maximumSocketEgressFlows {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid socket egress flow limit")
	}
	if limits.MaxBufferedBytes <= 0 || limits.MaxBufferedBytes > maximumSocketEgressBufferedBytes {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid socket egress buffer limit")
	}
	if limits.TCPReadBufferBytes < minimumSocketReadBufferBytes || limits.TCPReadBufferBytes > maximumTCPReadBufferBytes {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid TCP read buffer limit")
	}
	if limits.MaxUDPDatagramBytes < minimumSocketUDPDatagramBytes || limits.MaxUDPDatagramBytes > maximumUDPDatagramBytes {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid UDP datagram limit")
	}
	if limits.MaxBufferedBytes < limits.TCPReadBufferBytes || limits.MaxBufferedBytes < limits.MaxUDPDatagramBytes+1 {
		return SocketEgressLimits{}, fmt.Errorf("relay: socket egress buffer limit cannot hold one flow")
	}
	if limits.DialTimeout <= 0 || limits.DialTimeout > maximumSocketOperationTimeout {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid socket dial timeout")
	}
	if limits.WriteTimeout <= 0 || limits.WriteTimeout > maximumSocketOperationTimeout {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid socket write timeout")
	}
	if limits.IdleTimeout <= 0 || limits.IdleTimeout > maximumSocketIdleTimeout {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid socket idle timeout")
	}
	if limits.QueueRetryInterval <= 0 || limits.QueueRetryInterval > maximumExitQueueRetryInterval {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid socket queue retry interval")
	}
	if limits.ResolvedTTLSeconds == 0 || limits.ResolvedTTLSeconds > maximumSocketResolvedTTLSeconds {
		return SocketEgressLimits{}, fmt.Errorf("relay: invalid resolved target TTL")
	}
	return limits, nil
}

func (e *SocketEgress) Close() error {
	if e == nil {
		return nil
	}
	e.cancel()
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		flows := e.flows
		e.flows = make(map[uint64]*socketFlow)
		e.buffered = 0
		e.mu.Unlock()
		var closeErr error
		for _, flow := range flows {
			if flow != nil && !isNilExitDependency(flow.conn) {
				if err := flow.conn.Close(); err != nil && closeErr == nil {
					closeErr = ErrExitCloseFailed
				}
			}
		}
		e.wg.Wait()
		e.mu.Lock()
		e.closeErr = closeErr
		e.mu.Unlock()
		close(e.done)
	})
	<-e.done
	e.mu.Lock()
	err := e.closeErr
	e.mu.Unlock()
	return err
}
