package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/session"
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
	ErrExitFlowUnknown    = errors.New("relay: unknown exit flow")
	ErrExitWriteFailed    = errors.New("relay: exit socket write failed")
	ErrExitDatagramLarge  = errors.New("relay: exit datagram exceeds limit")
)

type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// DNSMessageResolver resolves one complete DNS message without exposing resolver transport details to a session.
type DNSMessageResolver interface {
	ExchangeDNS(context.Context, []byte) ([]byte, error)
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
	Sink        FrameSink
	Policy      ExitPolicy
	Dialer      ContextDialer
	Resolver    IPResolver
	DNSResolver DNSMessageResolver
	Limits      SocketEgressLimits
}

// ValidateSocketEgressLimits checks whether limits can be used to construct an egress.
func ValidateSocketEgressLimits(limits SocketEgressLimits) error {
	_, err := normalizeSocketEgressLimits(limits)
	return err
}

type SocketEgress struct {
	ctx         context.Context
	cancel      context.CancelFunc
	sink        FrameSink
	policy      ExitPolicy
	dialer      ContextDialer
	resolver    IPResolver
	dnsResolver DNSMessageResolver
	limits      SocketEgressLimits

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
	kind        uint8
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	doneOnce    sync.Once
	pumpStarted bool
	writeMu     sync.Mutex
	closeOnce   sync.Once
	peerClosed  bool
	expiresAt   time.Time
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
		ctx:         lifecycleCtx,
		cancel:      cancel,
		sink:        options.Sink,
		policy:      options.Policy,
		dialer:      options.Dialer,
		resolver:    options.Resolver,
		dnsResolver: options.DNSResolver,
		limits:      limits,
		done:        make(chan struct{}),
		flows:       make(map[uint64]*socketFlow),
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
	if event.FlowID == 0 {
		return nil, ErrExitEventInvalid
	}
	if event.Kind == ExitEventDNSMessage {
		return e.handleDNSMessage(ctx, event)
	}
	if event.Flow.FlowID != event.FlowID {
		return nil, ErrExitEventInvalid
	}
	switch event.Kind {
	case ExitEventFlowOpened:
		return e.handleFlowOpened(ctx, event)
	case ExitEventStreamData:
		if event.Flow.Kind == coreflow.FlowKindUDPAssociation {
			return nil, e.handleUDPData(ctx, event)
		}
		return nil, e.handleTCPData(ctx, event)
	case ExitEventDatagramData:
		return nil, e.handleUDPData(ctx, event)
	case ExitEventFlowClosed:
		return nil, e.handleFlowClosed(event)
	default:
		return nil, ErrExitEventInvalid
	}
}

func (e *SocketEgress) handleFlowOpened(ctx context.Context, event ExitFrameEvent) ([]protocol.AuroraFrame, error) {
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
	if err := e.installFlow(event.FlowID, flow, conn, target, ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if flow.kind == coreflow.FlowKindTCPStream {
		if err := e.startTCPReadPump(event.FlowID, flow); err != nil {
			_ = conn.Close()
			return nil, err
		}
	} else if flow.kind == coreflow.FlowKindUDPAssociation {
		if err := e.startUDPReadPump(event.FlowID, flow); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	keep = true
	if flow.kind == coreflow.FlowKindUDPAssociation && target.resolved {
		confirm, err := e.resolvedUDPConfirm(event.Flow, target)
		if err != nil {
			e.closeFlow(event.FlowID, flow)
			return nil, err
		}
		return []protocol.AuroraFrame{confirm}, nil
	}
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
	network  string
	address  string
	addr     netip.Addr
	answers  []netip.Addr
	resolved bool
}

func (e *SocketEgress) selectTarget(ctx context.Context, flow coreflow.FlowState) (selectedSocketTarget, error) {
	if flow.TargetPort == 0 {
		return selectedSocketTarget{}, ErrExitTargetInvalid
	}
	var addr netip.Addr
	var ordered []netip.Addr
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
		ordered = make([]netip.Addr, 0, len(allowed))
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
		network:  network,
		address:  net.JoinHostPort(addr.String(), strconv.Itoa(int(flow.TargetPort))),
		addr:     addr,
		answers:  ordered,
		resolved: flow.TargetKind == coreflow.TargetKindDomainName,
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
	flowCtx, cancel := context.WithCancel(e.ctx)
	flow := &socketFlow{
		bufferBytes: bufferBytes,
		kind:        state.Kind,
		ctx:         flowCtx,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
	e.flows[state.FlowID] = flow
	e.buffered += bufferBytes
	return flow, nil
}

func (e *SocketEgress) handleTCPData(ctx context.Context, event ExitFrameEvent) error {
	flow, err := e.activeFlow(event.FlowID, coreflow.FlowKindTCPStream)
	if err != nil {
		return err
	}
	flow.writeMu.Lock()
	defer flow.writeMu.Unlock()
	if flow.peerClosed {
		return ErrExitFlowUnknown
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(e.limits.WriteTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := flow.conn.SetWriteDeadline(deadline); err != nil {
		e.closeFlow(event.FlowID, flow)
		return ErrExitWriteFailed
	}
	interruptCaller := interruptSocketWriteOnDone(ctx, flow.conn)
	err = writeSocketBytes(flow.conn, event.Data)
	interruptCaller()
	_ = flow.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		e.closeFlow(event.FlowID, flow)
		if lifecycleErr := e.lifecycleError(ctx); lifecycleErr != nil {
			return lifecycleErr
		}
		return ErrExitWriteFailed
	}
	_ = flow.conn.SetReadDeadline(time.Now().Add(e.limits.IdleTimeout))
	return nil
}

func (e *SocketEgress) handleUDPData(ctx context.Context, event ExitFrameEvent) error {
	flow, err := e.activeFlow(event.FlowID, coreflow.FlowKindUDPAssociation)
	if err != nil {
		return err
	}
	if len(event.Data) > e.limits.MaxUDPDatagramBytes {
		e.closeFlow(event.FlowID, flow)
		return ErrExitDatagramLarge
	}
	flow.writeMu.Lock()
	defer flow.writeMu.Unlock()
	if flow.peerClosed {
		return ErrExitFlowUnknown
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !flow.expiresAt.IsZero() && !time.Now().Before(flow.expiresAt) {
		e.closeFlow(event.FlowID, flow)
		return ErrExitFlowUnknown
	}
	deadline := time.Now().Add(e.limits.WriteTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := flow.conn.SetWriteDeadline(deadline); err != nil {
		e.closeFlow(event.FlowID, flow)
		return ErrExitWriteFailed
	}
	interruptCaller := interruptSocketWriteOnDone(ctx, flow.conn)
	n, err := flow.conn.Write(event.Data)
	interruptCaller()
	_ = flow.conn.SetWriteDeadline(time.Time{})
	if err != nil || n != len(event.Data) {
		e.closeFlow(event.FlowID, flow)
		if lifecycleErr := e.lifecycleError(ctx); lifecycleErr != nil {
			return lifecycleErr
		}
		return ErrExitWriteFailed
	}
	_ = flow.conn.SetReadDeadline(e.nextReadDeadline(flow))
	return nil
}

func (e *SocketEgress) resolvedUDPConfirm(state coreflow.FlowState, target selectedSocketTarget) (protocol.AuroraFrame, error) {
	answers := make([]string, 0, len(target.answers))
	for _, answer := range target.answers {
		answers = append(answers, answer.String())
	}
	targetKind := coreflow.TargetKindIPv6
	selected := target.addr.As16()
	if target.addr.Is4() {
		targetKind = coreflow.TargetKindIPv4
		selected4 := target.addr.As4()
		return protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
			FlowID:           state.FlowID,
			TargetKind:       targetKind,
			SelectedIP:       append([]byte(nil), selected4[:]...),
			SelectedPort:     state.TargetPort,
			DNSAnswerSetHash: coreflow.DNSAnswerSetHash(answers),
			TTLSeconds:       e.limits.ResolvedTTLSeconds,
			ResolutionSource: protocol.UDPResolutionRelaySystemDNS,
		})
	}
	return protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           state.FlowID,
		TargetKind:       targetKind,
		SelectedIP:       append([]byte(nil), selected[:]...),
		SelectedPort:     state.TargetPort,
		DNSAnswerSetHash: coreflow.DNSAnswerSetHash(answers),
		TTLSeconds:       e.limits.ResolvedTTLSeconds,
		ResolutionSource: protocol.UDPResolutionRelaySystemDNS,
	})
}

func (e *SocketEgress) nextReadDeadline(flow *socketFlow) time.Time {
	deadline := time.Now().Add(e.limits.IdleTimeout)
	if !flow.expiresAt.IsZero() && flow.expiresAt.Before(deadline) {
		return flow.expiresAt
	}
	return deadline
}

func interruptSocketWriteOnDone(ctx context.Context, conn net.Conn) func() {
	if ctx == nil || ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetWriteDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

type socketCloseWriter interface {
	CloseWrite() error
}

func (e *SocketEgress) handleFlowClosed(event ExitFrameEvent) error {
	if event.Close.FlowID != event.FlowID {
		return ErrExitEventInvalid
	}
	e.mu.Lock()
	flow := e.flows[event.FlowID]
	e.mu.Unlock()
	if flow == nil {
		return nil
	}
	if event.Close.CloseCode != protocol.CloseNormal || flow.kind != coreflow.FlowKindTCPStream {
		e.closeFlow(event.FlowID, flow)
		return nil
	}
	flow.writeMu.Lock()
	if flow.peerClosed {
		flow.writeMu.Unlock()
		return nil
	}
	flow.peerClosed = true
	closeWriter, ok := flow.conn.(socketCloseWriter)
	if !ok || isNilExitDependency(flow.conn) {
		flow.writeMu.Unlock()
		e.closeFlow(event.FlowID, flow)
		return nil
	}
	err := closeWriter.CloseWrite()
	flow.writeMu.Unlock()
	if err != nil {
		e.closeFlow(event.FlowID, flow)
		return ErrExitCloseFailed
	}
	return nil
}

func writeSocketBytes(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (e *SocketEgress) activeFlow(flowID uint64, kind uint8) (*socketFlow, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return nil, ErrSocketEgressClosed
	}
	flow := e.flows[flowID]
	if flow == nil || flow.conn == nil || flow.kind != kind {
		return nil, ErrExitFlowUnknown
	}
	return flow, nil
}

func (e *SocketEgress) startTCPReadPump(flowID uint64, flow *socketFlow) error {
	e.mu.Lock()
	if e.closed || e.ctx.Err() != nil || e.flows[flowID] != flow {
		e.mu.Unlock()
		return ErrSocketEgressClosed
	}
	e.wg.Add(1)
	flow.pumpStarted = true
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer flow.finish()
		e.runTCPReadPump(flowID, flow)
	}()
	return nil
}

func (e *SocketEgress) startUDPReadPump(flowID uint64, flow *socketFlow) error {
	e.mu.Lock()
	if e.closed || e.ctx.Err() != nil || e.flows[flowID] != flow {
		e.mu.Unlock()
		return ErrSocketEgressClosed
	}
	e.wg.Add(1)
	flow.pumpStarted = true
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer flow.finish()
		e.runUDPReadPump(flowID, flow)
	}()
	return nil
}

func (e *SocketEgress) runTCPReadPump(flowID uint64, flow *socketFlow) {
	defer e.closeFlow(flowID, flow)
	buffer := make([]byte, flow.bufferBytes)
	for {
		if err := flow.ctx.Err(); err != nil {
			return
		}
		if err := flow.conn.SetReadDeadline(time.Now().Add(e.limits.IdleTimeout)); err != nil {
			e.queueTCPFlowClose(flow, flowID, protocol.CloseResetByPeer)
			return
		}
		n, err := flow.conn.Read(buffer)
		if n > 0 {
			frame, frameErr := protocol.NewStreamDataFrame(flowID, buffer[:n], 0)
			if frameErr != nil || e.queueSocketFrames(flow.ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}) != nil {
				return
			}
		}
		if err != nil {
			code := protocol.CloseResetByPeer
			if errors.Is(err, io.EOF) {
				code = protocol.CloseNormal
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				code = protocol.CloseIdleTimeout
			}
			e.queueTCPFlowClose(flow, flowID, code)
			return
		}
		if n == 0 {
			e.queueTCPFlowClose(flow, flowID, protocol.CloseResetByPeer)
			return
		}
	}
}

func (e *SocketEgress) runUDPReadPump(flowID uint64, flow *socketFlow) {
	defer e.closeFlow(flowID, flow)
	buffer := make([]byte, flow.bufferBytes)
	for {
		if err := flow.ctx.Err(); err != nil {
			return
		}
		if err := flow.conn.SetReadDeadline(e.nextReadDeadline(flow)); err != nil {
			e.queueFlowClose(flow, flowID, protocol.CloseResetByPeer)
			return
		}
		n, err := flow.conn.Read(buffer)
		if n > e.limits.MaxUDPDatagramBytes {
			e.queueFlowClose(flow, flowID, protocol.CloseResourceLimit)
			return
		}
		if n > 0 {
			frame, frameErr := protocol.NewDatagramDataFrame(flowID, buffer[:n], 0)
			if frameErr != nil || e.queueSocketFrames(flow.ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}) != nil {
				return
			}
		}
		if err != nil {
			code := protocol.CloseResetByPeer
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				code = protocol.CloseIdleTimeout
			}
			e.queueFlowClose(flow, flowID, code)
			return
		}
		if n == 0 {
			e.queueFlowClose(flow, flowID, protocol.CloseResetByPeer)
			return
		}
	}
}

func (e *SocketEgress) queueTCPFlowClose(flow *socketFlow, flowID, code uint64) {
	e.queueFlowClose(flow, flowID, code)
}

func (e *SocketEgress) queueFlowClose(flow *socketFlow, flowID, code uint64) {
	frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: flowID, CloseCode: code})
	if err != nil {
		return
	}
	_ = e.queueSocketFrames(flow.ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
}

func (e *SocketEgress) queueSocketFrames(ctx context.Context, block protocol.FrameBlock) error {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		err := e.sink.QueueFrames(ctx, block)
		if !errors.Is(err, session.ErrBackpressure) {
			return err
		}
		if timer == nil {
			timer = time.NewTimer(e.limits.QueueRetryInterval)
		} else {
			timer.Reset(e.limits.QueueRetryInterval)
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (e *SocketEgress) closeFlow(flowID uint64, flow *socketFlow) {
	if flow == nil {
		return
	}
	flow.cancel()
	flow.closeOnce.Do(func() {
		if !isNilExitDependency(flow.conn) {
			if err := flow.conn.Close(); err != nil {
				e.recordCloseFailure()
			}
		}
	})
	e.releaseFlow(flowID, flow)
}

func (e *SocketEgress) recordCloseFailure() {
	e.mu.Lock()
	if e.closed && e.closeErr == nil {
		e.closeErr = ErrExitCloseFailed
	}
	e.mu.Unlock()
}

func (f *socketFlow) finish() {
	if f == nil {
		return
	}
	f.doneOnce.Do(func() { close(f.done) })
}

func (e *SocketEgress) installFlow(flowID uint64, flow *socketFlow, conn net.Conn, target selectedSocketTarget, ctx context.Context) error {
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
	context.AfterFunc(flow.ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	if target.resolved {
		flow.expiresAt = time.Now().Add(time.Duration(e.limits.ResolvedTTLSeconds) * time.Second)
	}
	return nil
}

func (e *SocketEgress) releaseFlow(flowID uint64, flow *socketFlow) {
	e.mu.Lock()
	if e.flows[flowID] != flow {
		e.mu.Unlock()
		return
	}
	delete(e.flows, flowID)
	e.buffered -= flow.bufferBytes
	pumpStarted := flow.pumpStarted
	e.mu.Unlock()
	flow.cancel()
	if !pumpStarted {
		flow.finish()
	}
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
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		flows := e.flows
		e.flows = make(map[uint64]*socketFlow)
		e.buffered = 0
		e.mu.Unlock()
		e.cancel()
		for _, flow := range flows {
			if flow != nil {
				flow.cancel()
			}
			if flow != nil && !isNilExitDependency(flow.conn) {
				var err error
				flow.closeOnce.Do(func() { err = flow.conn.Close() })
				if err != nil {
					e.recordCloseFailure()
				}
			}
		}
		e.wg.Wait()
		for _, flow := range flows {
			if flow != nil && !flow.pumpStarted {
				flow.finish()
			}
		}
		close(e.done)
	})
	<-e.done
	e.mu.Lock()
	err := e.closeErr
	e.mu.Unlock()
	return err
}
