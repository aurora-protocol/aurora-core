package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
)

const (
	defaultTCPProxyMaxFlows          = 256
	maximumTCPProxyMaxFlows          = 4096
	defaultTCPProxyReadBufferBytes   = 32 << 10
	minimumTCPProxyReadBufferBytes   = 1024
	maximumTCPProxyReadBufferBytes   = 1 << 20
	defaultTCPProxyPendingWriteBytes = 1 << 20
	maximumTCPProxyPendingWriteBytes = 16 << 20
	tcpProxyWriteQueueLength         = 16
)

var (
	ErrTCPProxyClosed       = errors.New("client: TCP proxy runtime is closed")
	ErrTCPProxyFlowLimit    = errors.New("client: TCP proxy flow limit reached")
	ErrTCPProxyBackpressure = errors.New("client: TCP proxy local write backpressure")
)

type TCPProxyRuntimeOptions struct {
	MaxFlows             int
	ReadBufferBytes      int
	MaxPendingWriteBytes int
}

// TCPProxyRuntime maps local HTTP CONNECT and SOCKS5 TCP connections to one encrypted proxy-flow session.
type TCPProxyRuntime struct {
	application *session.Application
	proxy       *LocalProxy
	options     TCPProxyRuntimeOptions

	mu         sync.Mutex
	flows      map[uint64]*tcpProxyFlow
	pending    map[net.Conn]struct{}
	listeners  map[net.Listener]struct{}
	nextFlowID uint64
	closed     bool
	closeErr   error
	done       chan struct{}
	closeOnce  sync.Once
}

type tcpProxyFlow struct {
	id   uint64
	conn net.Conn

	mu             sync.Mutex
	writes         chan []byte
	done           chan struct{}
	closeOnce      sync.Once
	pendingWrites  int
	localCloseSent bool
}

type socks5RequestError struct {
	err   error
	reply byte
}

func (e *socks5RequestError) Error() string { return e.err.Error() }

func (e *socks5RequestError) Unwrap() error { return e.err }

func NewTCPProxyRuntime(application *session.Application, options TCPProxyRuntimeOptions) (*TCPProxyRuntime, error) {
	if application == nil {
		return nil, fmt.Errorf("client: TCP proxy application is required")
	}
	normalized, err := normalizeTCPProxyRuntimeOptions(options)
	if err != nil {
		return nil, err
	}
	return &TCPProxyRuntime{
		application: application,
		proxy:       NewLocalProxy(),
		options:     normalized,
		flows:       make(map[uint64]*tcpProxyFlow),
		pending:     make(map[net.Conn]struct{}),
		listeners:   make(map[net.Listener]struct{}),
		nextFlowID:  1,
		done:        make(chan struct{}),
	}, nil
}

func normalizeTCPProxyRuntimeOptions(options TCPProxyRuntimeOptions) (TCPProxyRuntimeOptions, error) {
	if options.MaxFlows == 0 {
		options.MaxFlows = defaultTCPProxyMaxFlows
	}
	if options.ReadBufferBytes == 0 {
		options.ReadBufferBytes = defaultTCPProxyReadBufferBytes
	}
	if options.MaxPendingWriteBytes == 0 {
		options.MaxPendingWriteBytes = defaultTCPProxyPendingWriteBytes
	}
	if options.MaxFlows < 1 || options.MaxFlows > maximumTCPProxyMaxFlows {
		return TCPProxyRuntimeOptions{}, fmt.Errorf("client: TCP proxy flow limit is invalid")
	}
	if options.ReadBufferBytes < minimumTCPProxyReadBufferBytes || options.ReadBufferBytes > maximumTCPProxyReadBufferBytes {
		return TCPProxyRuntimeOptions{}, fmt.Errorf("client: TCP proxy read buffer size is invalid")
	}
	if options.MaxPendingWriteBytes < minimumTCPProxyReadBufferBytes || options.MaxPendingWriteBytes > maximumTCPProxyPendingWriteBytes {
		return TCPProxyRuntimeOptions{}, fmt.Errorf("client: TCP proxy pending write limit is invalid")
	}
	return options, nil
}

// ValidateTCPProxyRuntimeOptions verifies local resource limits before a session is available.
func ValidateTCPProxyRuntimeOptions(options TCPProxyRuntimeOptions) error {
	_, err := normalizeTCPProxyRuntimeOptions(options)
	return err
}

// Serve accepts local proxy connections until the context is canceled, the listener fails, or Close is called.
func (r *TCPProxyRuntime) Serve(ctx context.Context, listener net.Listener) error {
	if r == nil {
		return fmt.Errorf("client: nil TCP proxy runtime")
	}
	if ctx == nil {
		return fmt.Errorf("client: nil TCP proxy serve context")
	}
	if listener == nil {
		return fmt.Errorf("client: nil TCP proxy listener")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.addListener(listener); err != nil {
		return err
	}
	defer r.removeListener(listener)

	stopListener := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-r.done:
			_ = listener.Close()
		case <-stopListener:
		}
	}()
	defer close(stopListener)

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || r.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		go func() {
			_ = r.serveConnection(ctx, connection)
		}()
	}
}

// HandleFrameBlock dispatches authenticated backward proxy-flow frames to their local TCP connection.
func (r *TCPProxyRuntime) HandleFrameBlock(ctx context.Context, block protocol.FrameBlock) error {
	if r == nil {
		return fmt.Errorf("client: nil TCP proxy runtime")
	}
	if ctx == nil {
		return fmt.Errorf("client: nil TCP proxy frame context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := protocol.ValidateFrameBlock(block); err != nil {
		return fmt.Errorf("client: invalid TCP proxy relay frame block: %w", err)
	}
	for _, frame := range block.Frames {
		switch frame.FrameType {
		case registry.FrameStreamData:
			if err := r.enqueueLocalWrite(frame.FlowID, frame.Payload); err != nil {
				return err
			}
		case registry.FrameFlowClose:
			if err := r.handlePeerFlowClose(frame); err != nil {
				return err
			}
		default:
			return fmt.Errorf("client: TCP proxy runtime received unsupported relay frame 0x%x", frame.FrameType)
		}
	}
	return nil
}

// Close closes listeners, pending handshakes, mapped local sockets, and the portable proxy flow state.
func (r *TCPProxyRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.done)
		listeners := make([]net.Listener, 0, len(r.listeners))
		for listener := range r.listeners {
			listeners = append(listeners, listener)
		}
		pending := make([]net.Conn, 0, len(r.pending))
		for connection := range r.pending {
			pending = append(pending, connection)
		}
		flows := make([]*tcpProxyFlow, 0, len(r.flows))
		for flowID, flow := range r.flows {
			delete(r.flows, flowID)
			flows = append(flows, flow)
		}
		r.pending = make(map[net.Conn]struct{})
		r.listeners = make(map[net.Listener]struct{})
		r.mu.Unlock()

		var closeErrors []error
		for _, listener := range listeners {
			closeErrors = appendTCPProxyCloseError(closeErrors, listener.Close())
		}
		for _, connection := range pending {
			closeErrors = appendTCPProxyCloseError(closeErrors, connection.Close())
		}
		for _, flow := range flows {
			_ = r.proxy.Close(flow.id)
			closeErrors = appendTCPProxyCloseError(closeErrors, flow.close())
		}
		r.closeErr = errors.Join(closeErrors...)
	})
	return r.closeErr
}

func (r *TCPProxyRuntime) serveConnection(ctx context.Context, connection net.Conn) (err error) {
	if r == nil {
		return fmt.Errorf("client: nil TCP proxy runtime")
	}
	if ctx == nil {
		_ = connection.Close()
		return fmt.Errorf("client: nil TCP proxy connection context")
	}
	if connection == nil {
		return fmt.Errorf("client: nil TCP proxy connection")
	}
	if err := r.addPending(connection); err != nil {
		_ = connection.Close()
		return err
	}
	flowOpened := false
	defer func() {
		if !flowOpened || err != nil {
			r.removePending(connection)
			_ = connection.Close()
		}
	}()

	reader := bufio.NewReaderSize(connection, r.options.ReadBufferBytes)
	host, port, response, err := r.readLocalRequest(reader, connection)
	if err != nil {
		var socksError *socks5RequestError
		if errors.As(err, &socksError) {
			failure := socks5FailureResponse(socksError.reply)
			_, writeErr := connection.Write(failure)
			zeroTCPProxyBytes(failure)
			if writeErr != nil {
				return errors.Join(err, writeErr)
			}
		}
		return err
	}
	flow, err := r.openFlow(ctx, connection, host, port)
	if err != nil {
		return err
	}
	flowOpened = true
	if _, err := connection.Write(response); err != nil {
		r.abortFlow(flow.id)
		return err
	}
	if err := r.readLocalFlow(ctx, reader, flow); err != nil {
		r.abortFlow(flow.id)
		return err
	}
	return nil
}

func (r *TCPProxyRuntime) readLocalRequest(reader *bufio.Reader, connection net.Conn) (string, uint16, []byte, error) {
	first, err := reader.Peek(1)
	if err != nil {
		return "", 0, nil, err
	}
	if first[0] == socksVersion5 {
		return readTCPProxySOCKS5Request(reader, connection)
	}
	return readTCPProxyHTTPConnectRequest(reader, r.options.ReadBufferBytes)
}

func readTCPProxyHTTPConnectRequest(reader *bufio.Reader, maximum int) (string, uint16, []byte, error) {
	raw, err := readTCPProxyHeader(reader, maximum)
	if err != nil {
		return "", 0, nil, err
	}
	defer zeroTCPProxyBytes(raw)
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "", 0, nil, fmt.Errorf("client: invalid HTTP CONNECT request: %w", err)
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	if request.Method != http.MethodConnect {
		return "", 0, nil, fmt.Errorf("client: HTTP local interface requires CONNECT")
	}
	host, port, err := parseAuthority(request.Host)
	if err != nil {
		return "", 0, nil, err
	}
	return host, port, append([]byte(nil), httpConnectEstablished...), nil
}

func readTCPProxyHeader(reader *bufio.Reader, maximum int) ([]byte, error) {
	if maximum < minimumTCPProxyReadBufferBytes {
		return nil, fmt.Errorf("client: TCP proxy header limit is invalid")
	}
	var raw []byte
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				return nil, fmt.Errorf("client: TCP proxy request header exceeds limit")
			}
			return nil, err
		}
		if len(raw)+len(line) > maximum {
			return nil, fmt.Errorf("client: TCP proxy request header exceeds limit")
		}
		raw = append(raw, line...)
		if bytes.Equal(line, []byte("\r\n")) {
			return raw, nil
		}
	}
}

func readTCPProxySOCKS5Request(reader *bufio.Reader, connection net.Conn) (string, uint16, []byte, error) {
	greetingPrefix := make([]byte, 2)
	if _, err := io.ReadFull(reader, greetingPrefix); err != nil {
		return "", 0, nil, err
	}
	greeting := append([]byte(nil), greetingPrefix...)
	defer zeroTCPProxyBytes(greeting)
	if greetingPrefix[0] != socksVersion5 {
		return "", 0, nil, fmt.Errorf("client: invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(greetingPrefix[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return "", 0, nil, err
	}
	greeting = append(greeting, methods...)
	zeroTCPProxyBytes(methods)
	greetingResponse, greetingErr := HandleSOCKS5Greeting(greeting)
	if len(greetingResponse) != 0 {
		if _, err := connection.Write(greetingResponse); err != nil {
			return "", 0, nil, err
		}
	}
	if greetingErr != nil {
		return "", 0, nil, greetingErr
	}

	requestPrefix := make([]byte, 4)
	if _, err := io.ReadFull(reader, requestPrefix); err != nil {
		return "", 0, nil, err
	}
	request := append([]byte(nil), requestPrefix...)
	defer zeroTCPProxyBytes(request)
	if requestPrefix[0] != socksVersion5 || requestPrefix[2] != 0 {
		return "", 0, nil, newSOCKS5RequestError(fmt.Errorf("client: invalid SOCKS5 request"), socksReplyGeneralFailure)
	}
	if requestPrefix[1] != socksCommandConnect {
		return "", 0, nil, newSOCKS5RequestError(fmt.Errorf("client: unsupported SOCKS5 command 0x%x", requestPrefix[1]), socksReplyCommandUnsupported)
	}
	if requestPrefix[3] != socksATYPIPv4 && requestPrefix[3] != socksATYPDomain && requestPrefix[3] != socksATYPIPv6 {
		return "", 0, nil, newSOCKS5RequestError(fmt.Errorf("client: unsupported SOCKS5 address type 0x%x", requestPrefix[3]), socksReplyAddressUnsupported)
	}
	remaining, err := tcpProxySOCKS5AddressBytes(reader, requestPrefix[3])
	if err != nil {
		return "", 0, nil, newSOCKS5RequestError(err, socksReplyGeneralFailure)
	}
	request = append(request, remaining...)
	zeroTCPProxyBytes(remaining)
	host, port, end, err := parseSOCKS5Request(request, socksCommandConnect)
	if err != nil {
		return "", 0, nil, newSOCKS5RequestError(err, socksReplyGeneralFailure)
	}
	if end != len(request) {
		return "", 0, nil, newSOCKS5RequestError(fmt.Errorf("client: trailing SOCKS5 CONNECT bytes"), socksReplyGeneralFailure)
	}
	return host, port, append([]byte(nil), socksSuccessResponse...), nil
}

func newSOCKS5RequestError(err error, reply byte) error {
	return &socks5RequestError{err: err, reply: reply}
}

func tcpProxySOCKS5AddressBytes(reader *bufio.Reader, addressType byte) ([]byte, error) {
	switch addressType {
	case socksATYPIPv4:
		return tcpProxyReadExact(reader, 6)
	case socksATYPIPv6:
		return tcpProxyReadExact(reader, 18)
	case socksATYPDomain:
		length, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return nil, fmt.Errorf("client: SOCKS5 domain target is empty")
		}
		remaining, err := tcpProxyReadExact(reader, int(length)+2)
		if err != nil {
			return nil, err
		}
		return append([]byte{length}, remaining...), nil
	default:
		return nil, fmt.Errorf("client: unsupported SOCKS5 address type 0x%x", addressType)
	}
}

func tcpProxyReadExact(reader *bufio.Reader, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("client: invalid SOCKS5 address length")
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		zeroTCPProxyBytes(value)
		return nil, err
	}
	return value, nil
}

func (r *TCPProxyRuntime) openFlow(ctx context.Context, connection net.Conn, host string, port uint16) (*tcpProxyFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrTCPProxyClosed
	}
	if len(r.flows) >= r.options.MaxFlows {
		r.mu.Unlock()
		return nil, ErrTCPProxyFlowLimit
	}
	flowID, err := r.allocateFlowIDLocked()
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	flow := &tcpProxyFlow{
		id:     flowID,
		conn:   connection,
		writes: make(chan []byte, tcpProxyWriteQueueLength),
		done:   make(chan struct{}),
	}
	r.flows[flowID] = flow
	delete(r.pending, connection)
	r.mu.Unlock()

	open, err := r.proxy.OpenTCPFrame(flowID, host, port)
	if err == nil {
		err = r.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{open}})
	}
	zeroTCPProxyBytes(open.Payload)
	if err != nil {
		r.abortFlow(flowID)
		return nil, err
	}
	go r.runLocalWritePump(flow)
	return flow, nil
}

func (r *TCPProxyRuntime) allocateFlowIDLocked() (uint64, error) {
	for attempts := 0; attempts <= r.options.MaxFlows; attempts++ {
		flowID := r.nextFlowID
		r.nextFlowID++
		if r.nextFlowID == 0 {
			r.nextFlowID = 1
		}
		if flowID != 0 && r.flows[flowID] == nil {
			return flowID, nil
		}
	}
	return 0, fmt.Errorf("client: TCP proxy flow identifiers are exhausted")
}

func (r *TCPProxyRuntime) readLocalFlow(ctx context.Context, reader *bufio.Reader, flow *tcpProxyFlow) error {
	if flow == nil {
		return fmt.Errorf("client: TCP proxy flow is unavailable")
	}
	buffer := make([]byte, r.options.ReadBufferBytes)
	defer zeroTCPProxyBytes(buffer)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			frame, frameErr := r.proxy.SendTCP(flow.id, buffer[:count], 0)
			if frameErr == nil {
				frameErr = r.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
			}
			zeroTCPProxyBytes(frame.Payload)
			if frameErr != nil {
				return frameErr
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return r.sendLocalFlowClose(ctx, flow)
		}
		return err
	}
}

func (r *TCPProxyRuntime) sendLocalFlowClose(ctx context.Context, flow *tcpProxyFlow) error {
	if flow == nil {
		return nil
	}
	flow.mu.Lock()
	if flow.localCloseSent {
		flow.mu.Unlock()
		return nil
	}
	flow.localCloseSent = true
	flow.mu.Unlock()

	frame, err := r.proxy.GracefulCloseFrame(flow.id, 0, nil, uint64(time.Now().Unix()), 0)
	if err == nil {
		err = r.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
	}
	zeroTCPProxyBytes(frame.Payload)
	return err
}

func (r *TCPProxyRuntime) enqueueLocalWrite(flowID uint64, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("client: TCP proxy relay data is empty")
	}
	flow := r.flow(flowID)
	if flow == nil {
		return fmt.Errorf("client: TCP proxy relay data targets an unknown flow")
	}
	owned := append([]byte(nil), payload...)
	flow.mu.Lock()
	select {
	case <-flow.done:
		flow.mu.Unlock()
		zeroTCPProxyBytes(owned)
		return fmt.Errorf("client: TCP proxy flow is closed")
	default:
	}
	if flow.pendingWrites+len(owned) > r.options.MaxPendingWriteBytes {
		flow.mu.Unlock()
		zeroTCPProxyBytes(owned)
		return ErrTCPProxyBackpressure
	}
	select {
	case flow.writes <- owned:
		flow.pendingWrites += len(owned)
		flow.mu.Unlock()
		return nil
	default:
		flow.mu.Unlock()
		zeroTCPProxyBytes(owned)
		return ErrTCPProxyBackpressure
	}
}

func (r *TCPProxyRuntime) runLocalWritePump(flow *tcpProxyFlow) {
	for {
		select {
		case <-flow.done:
			return
		case payload := <-flow.writes:
			if payload == nil {
				continue
			}
			_, err := flow.conn.Write(payload)
			zeroTCPProxyBytes(payload)
			flow.mu.Lock()
			flow.pendingWrites -= len(payload)
			flow.mu.Unlock()
			if err != nil {
				r.abortFlow(flow.id)
				return
			}
		}
	}
}

func (r *TCPProxyRuntime) handlePeerFlowClose(frame protocol.AuroraFrame) error {
	if r.flow(frame.FlowID) == nil {
		return fmt.Errorf("client: TCP proxy relay close targets an unknown flow")
	}
	if err := r.proxy.ReceiveFlowCloseFrame(frame, uint64(time.Now().Unix()), 0); err != nil {
		return err
	}
	flow := r.detachFlow(frame.FlowID)
	_ = r.proxy.Close(frame.FlowID)
	if flow == nil {
		return nil
	}
	return flow.close()
}

func (r *TCPProxyRuntime) abortFlow(flowID uint64) {
	flow := r.detachFlow(flowID)
	if flow == nil {
		return
	}
	_ = r.proxy.Close(flowID)
	_ = flow.close()
}

func (r *TCPProxyRuntime) detachFlow(flowID uint64) *tcpProxyFlow {
	r.mu.Lock()
	flow := r.flows[flowID]
	delete(r.flows, flowID)
	r.mu.Unlock()
	return flow
}

func (r *TCPProxyRuntime) flow(flowID uint64) *tcpProxyFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flows[flowID]
}

func (f *tcpProxyFlow) close() error {
	if f == nil {
		return nil
	}
	var closeErr error
	f.closeOnce.Do(func() {
		f.mu.Lock()
		close(f.done)
		f.mu.Unlock()
		closeErr = f.conn.Close()
		for {
			select {
			case payload := <-f.writes:
				zeroTCPProxyBytes(payload)
			default:
				return
			}
		}
	})
	return closeErr
}

func (r *TCPProxyRuntime) addPending(connection net.Conn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrTCPProxyClosed
	}
	r.pending[connection] = struct{}{}
	return nil
}

func (r *TCPProxyRuntime) removePending(connection net.Conn) {
	r.mu.Lock()
	delete(r.pending, connection)
	r.mu.Unlock()
}

func (r *TCPProxyRuntime) addListener(listener net.Listener) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrTCPProxyClosed
	}
	r.listeners[listener] = struct{}{}
	return nil
}

func (r *TCPProxyRuntime) removeListener(listener net.Listener) {
	r.mu.Lock()
	delete(r.listeners, listener)
	r.mu.Unlock()
}

func (r *TCPProxyRuntime) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func appendTCPProxyCloseError(values []error, err error) []error {
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return append(values, err)
	}
	return values
}

func zeroTCPProxyBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
