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

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
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
	maximumSOCKS5UDPDatagramBytes    = 65535
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

// TCPProxyRuntime maps local HTTP CONNECT and SOCKS5 TCP or UDP associations to one encrypted proxy-flow session.
type TCPProxyRuntime struct {
	application *session.Application
	proxy       *LocalProxy
	options     TCPProxyRuntimeOptions

	mu         sync.Mutex
	flows      map[uint64]*tcpProxyFlow
	udpFlows   map[uint64]*udpProxyFlow
	udpLinks   map[*udpProxyAssociation]struct{}
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
	draining       bool
}

type udpProxyTarget struct {
	kind uint8
	host string
	port uint16
}

type udpProxyAssociation struct {
	connection *net.UDPConn
	peerIP     net.IP
	peerPort   int

	mu        sync.Mutex
	peer      *net.UDPAddr
	writeMu   sync.Mutex
	closed    bool
	closeOnce sync.Once
}

type udpProxyFlow struct {
	id          uint64
	association *udpProxyAssociation
	target      udpProxyTarget

	mu          sync.Mutex
	confirmed   bool
	replyTarget udpProxyTarget
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
		udpFlows:    make(map[uint64]*udpProxyFlow),
		udpLinks:    make(map[*udpProxyAssociation]struct{}),
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

// HandleFrameBlock dispatches authenticated backward proxy-flow frames to their local TCP connection or UDP association.
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
			if r.flow(frame.FlowID) != nil {
				if err := r.enqueueLocalWrite(frame.FlowID, frame.Payload); err != nil {
					return err
				}
				continue
			}
			if err := r.enqueueUDPWrite(frame); err != nil {
				return err
			}
		case registry.FrameDatagramData:
			if err := r.enqueueUDPWrite(frame); err != nil {
				return err
			}
		case registry.FrameUDPTargetConfirm:
			if err := r.handleUDPTargetConfirm(frame); err != nil {
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
		udpFlows := make([]*udpProxyFlow, 0, len(r.udpFlows))
		for flowID, flow := range r.udpFlows {
			delete(r.udpFlows, flowID)
			udpFlows = append(udpFlows, flow)
		}
		udpLinks := make([]*udpProxyAssociation, 0, len(r.udpLinks))
		for association := range r.udpLinks {
			udpLinks = append(udpLinks, association)
		}
		r.pending = make(map[net.Conn]struct{})
		r.listeners = make(map[net.Listener]struct{})
		r.udpLinks = make(map[*udpProxyAssociation]struct{})
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
		for _, flow := range udpFlows {
			_ = r.proxy.Close(flow.id)
		}
		for _, association := range udpLinks {
			closeErrors = appendTCPProxyCloseError(closeErrors, association.close())
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
	request, err := r.readLocalRequest(reader, connection)
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
	if request.command == socksCommandUDP {
		return r.serveSOCKS5UDPAssociation(ctx, reader, connection, request.host, request.port)
	}
	flow, err := r.openFlow(ctx, connection, request.host, request.port)
	if err != nil {
		return err
	}
	flowOpened = true
	if _, err := connection.Write(request.response); err != nil {
		r.abortFlow(flow.id)
		return err
	}
	if err := r.readLocalFlow(ctx, reader, flow); err != nil {
		r.abortFlow(flow.id)
		return err
	}
	return nil
}

type localProxyRequest struct {
	command  byte
	host     string
	port     uint16
	response []byte
}

func (r *TCPProxyRuntime) readLocalRequest(reader *bufio.Reader, connection net.Conn) (localProxyRequest, error) {
	first, err := reader.Peek(1)
	if err != nil {
		return localProxyRequest{}, err
	}
	if first[0] == socksVersion5 {
		return readTCPProxySOCKS5Request(reader, connection)
	}
	return readTCPProxyHTTPConnectRequest(reader, r.options.ReadBufferBytes)
}

func readTCPProxyHTTPConnectRequest(reader *bufio.Reader, maximum int) (localProxyRequest, error) {
	raw, err := readTCPProxyHeader(reader, maximum)
	if err != nil {
		return localProxyRequest{}, err
	}
	defer zeroTCPProxyBytes(raw)
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return localProxyRequest{}, fmt.Errorf("client: invalid HTTP CONNECT request: %w", err)
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	if request.Method != http.MethodConnect {
		return localProxyRequest{}, fmt.Errorf("client: HTTP local interface requires CONNECT")
	}
	host, port, err := parseAuthority(request.Host)
	if err != nil {
		return localProxyRequest{}, err
	}
	return localProxyRequest{command: socksCommandConnect, host: host, port: port, response: append([]byte(nil), httpConnectEstablished...)}, nil
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

func readTCPProxySOCKS5Request(reader *bufio.Reader, connection net.Conn) (localProxyRequest, error) {
	greetingPrefix := make([]byte, 2)
	if _, err := io.ReadFull(reader, greetingPrefix); err != nil {
		return localProxyRequest{}, err
	}
	greeting := append([]byte(nil), greetingPrefix...)
	defer zeroTCPProxyBytes(greeting)
	if greetingPrefix[0] != socksVersion5 {
		return localProxyRequest{}, fmt.Errorf("client: invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(greetingPrefix[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return localProxyRequest{}, err
	}
	greeting = append(greeting, methods...)
	zeroTCPProxyBytes(methods)
	greetingResponse, greetingErr := HandleSOCKS5Greeting(greeting)
	if len(greetingResponse) != 0 {
		if _, err := connection.Write(greetingResponse); err != nil {
			return localProxyRequest{}, err
		}
	}
	if greetingErr != nil {
		return localProxyRequest{}, greetingErr
	}

	requestPrefix := make([]byte, 4)
	if _, err := io.ReadFull(reader, requestPrefix); err != nil {
		return localProxyRequest{}, err
	}
	request := append([]byte(nil), requestPrefix...)
	defer zeroTCPProxyBytes(request)
	if requestPrefix[0] != socksVersion5 || requestPrefix[2] != 0 {
		return localProxyRequest{}, newSOCKS5RequestError(fmt.Errorf("client: invalid SOCKS5 request"), socksReplyGeneralFailure)
	}
	if requestPrefix[1] != socksCommandConnect && requestPrefix[1] != socksCommandUDP {
		return localProxyRequest{}, newSOCKS5RequestError(fmt.Errorf("client: unsupported SOCKS5 command 0x%x", requestPrefix[1]), socksReplyCommandUnsupported)
	}
	if requestPrefix[3] != socksATYPIPv4 && requestPrefix[3] != socksATYPDomain && requestPrefix[3] != socksATYPIPv6 {
		return localProxyRequest{}, newSOCKS5RequestError(fmt.Errorf("client: unsupported SOCKS5 address type 0x%x", requestPrefix[3]), socksReplyAddressUnsupported)
	}
	remaining, err := tcpProxySOCKS5AddressBytes(reader, requestPrefix[3])
	if err != nil {
		return localProxyRequest{}, newSOCKS5RequestError(err, socksReplyGeneralFailure)
	}
	request = append(request, remaining...)
	zeroTCPProxyBytes(remaining)
	host, port, end, err := parseSOCKS5RequestWithOptions(request, requestPrefix[1], requestPrefix[1] == socksCommandUDP)
	if err != nil {
		return localProxyRequest{}, newSOCKS5RequestError(err, socksReplyGeneralFailure)
	}
	if end != len(request) {
		return localProxyRequest{}, newSOCKS5RequestError(fmt.Errorf("client: trailing SOCKS5 request bytes"), socksReplyGeneralFailure)
	}
	response := []byte(nil)
	if requestPrefix[1] == socksCommandConnect {
		response = append([]byte(nil), socksSuccessResponse...)
	}
	return localProxyRequest{command: requestPrefix[1], host: host, port: port, response: response}, nil
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
	if len(r.flows)+len(r.udpFlows) >= r.options.MaxFlows {
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
		if flowID != 0 && r.flows[flowID] == nil && r.udpFlows[flowID] == nil {
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

func (r *TCPProxyRuntime) serveSOCKS5UDPAssociation(ctx context.Context, reader *bufio.Reader, control net.Conn, host string, port uint16) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	peerIP, peerPort, err := socksUDPAssociationPeer(host, port, control.RemoteAddr())
	if err != nil {
		return newSOCKS5RequestError(err, socksReplyGeneralFailure)
	}
	udpNetwork, udpAddress, err := socksUDPAssociationListenConfig(control.LocalAddr())
	if err != nil {
		return newSOCKS5RequestError(err, socksReplyGeneralFailure)
	}
	udpConnection, err := net.ListenUDP(udpNetwork, udpAddress)
	if err != nil {
		return newSOCKS5RequestError(fmt.Errorf("client: listen SOCKS5 UDP association: %w", err), socksReplyGeneralFailure)
	}
	association := &udpProxyAssociation{connection: udpConnection, peerIP: peerIP, peerPort: peerPort}
	if err := r.addUDPAssociation(association); err != nil {
		_ = association.close()
		return err
	}
	defer r.removeUDPAssociation(association)
	defer association.close()

	address := udpConnection.LocalAddr().(*net.UDPAddr)
	response, err := socks5BindResponse(address.IP.String(), uint16(address.Port))
	if err != nil {
		return err
	}
	if _, err := control.Write(response); err != nil {
		return err
	}
	zeroTCPProxyBytes(response)

	result := make(chan error, 1)
	go func() { result <- r.readSOCKS5UDPAssociation(ctx, association) }()
	controlResult := make(chan error, 1)
	go func() {
		_, err := reader.ReadByte()
		controlResult <- err
	}()
	select {
	case err := <-result:
		return err
	case err := <-controlResult:
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return nil
	case <-r.done:
		return nil
	}
}

func socksUDPAssociationPeer(host string, port uint16, controlPeer net.Addr) (net.IP, int, error) {
	peer, ok := controlPeer.(*net.TCPAddr)
	if !ok || peer.IP == nil {
		return nil, 0, fmt.Errorf("client: SOCKS5 UDP control peer is unavailable")
	}
	controlIP := peer.IP.To16()
	if controlIP == nil {
		return nil, 0, fmt.Errorf("client: SOCKS5 UDP control peer is invalid")
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		requested := net.ParseIP(host)
		if requested == nil || !requested.Equal(controlIP) {
			return nil, 0, fmt.Errorf("client: SOCKS5 UDP association peer does not match control connection")
		}
	}
	return append(net.IP(nil), controlIP...), int(port), nil
}

func socksUDPAssociationListenConfig(controlLocal net.Addr) (string, *net.UDPAddr, error) {
	local, ok := controlLocal.(*net.TCPAddr)
	if !ok || local.IP == nil {
		return "", nil, fmt.Errorf("client: SOCKS5 UDP control listener is unavailable")
	}
	if ip4 := local.IP.To4(); ip4 != nil {
		return "udp4", &net.UDPAddr{IP: append(net.IP(nil), ip4...)}, nil
	}
	if ip6 := local.IP.To16(); ip6 != nil {
		return "udp6", &net.UDPAddr{IP: append(net.IP(nil), ip6...), Zone: local.Zone}, nil
	}
	return "", nil, fmt.Errorf("client: SOCKS5 UDP control listener is invalid")
}

func (r *TCPProxyRuntime) readSOCKS5UDPAssociation(ctx context.Context, association *udpProxyAssociation) error {
	buffer := make([]byte, maximumSOCKS5UDPDatagramBytes)
	defer zeroTCPProxyBytes(buffer)
	for {
		count, peer, err := association.connection.ReadFromUDP(buffer)
		if count > 0 {
			if !association.acceptPeer(peer) {
				continue
			}
			if err := r.queueSOCKS5UDPDatagram(ctx, association, buffer[:count]); err != nil {
				return err
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, net.ErrClosed) || ctx.Err() != nil || r.isClosed() {
			return nil
		}
		return fmt.Errorf("client: read SOCKS5 UDP association: %w", err)
	}
}

func (r *TCPProxyRuntime) queueSOCKS5UDPDatagram(ctx context.Context, association *udpProxyAssociation, packet []byte) error {
	host, port, _, err := parseSOCKS5UDPHeader(packet)
	if err != nil {
		return err
	}
	targetKind, targetHost, err := localTarget(host)
	if err != nil {
		return err
	}
	canonicalHost := string(targetHost)
	if targetKind == flow.TargetKindIPv4 || targetKind == flow.TargetKindIPv6 {
		canonicalHost = net.IP(targetHost).String()
	}
	if canonicalHost == "" {
		return fmt.Errorf("client: SOCKS5 UDP target is invalid")
	}
	target := udpProxyTarget{kind: targetKind, host: canonicalHost, port: port}
	flow, opened, err := r.udpFlowForTarget(association, target)
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	frames, err := r.proxy.HandleSOCKS5UDPDatagramFrames(flow.id, packet, now, transport.UDPOverStreamFallback)
	if err != nil {
		if opened {
			r.removeUDPFlow(flow.id)
		}
		return err
	}
	if err := r.application.QueueFrames(ctx, protocol.FrameBlock{Frames: frames}); err != nil {
		for index := range frames {
			zeroTCPProxyBytes(frames[index].Payload)
		}
		if opened {
			r.removeUDPFlow(flow.id)
		}
		if errors.Is(err, session.ErrBackpressure) {
			return nil
		}
		return err
	}
	for index := range frames {
		zeroTCPProxyBytes(frames[index].Payload)
	}
	return nil
}

func (r *TCPProxyRuntime) udpFlowForTarget(association *udpProxyAssociation, target udpProxyTarget) (*udpProxyFlow, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, false, ErrTCPProxyClosed
	}
	for _, flow := range r.udpFlows {
		if flow.association == association && flow.target == target {
			return flow, false, nil
		}
	}
	if len(r.flows)+len(r.udpFlows) >= r.options.MaxFlows {
		return nil, false, ErrTCPProxyFlowLimit
	}
	flowID, err := r.allocateFlowIDLocked()
	if err != nil {
		return nil, false, err
	}
	flow := &udpProxyFlow{id: flowID, association: association, target: target}
	r.udpFlows[flowID] = flow
	return flow, true, nil
}

func (r *TCPProxyRuntime) handleUDPTargetConfirm(frame protocol.AuroraFrame) error {
	flow := r.udpFlow(frame.FlowID)
	if flow == nil {
		return fmt.Errorf("client: UDP target confirm targets an unknown flow")
	}
	if err := r.proxy.ReceiveUDPTargetConfirmFrameAt(frame, uint64(time.Now().Unix())); err != nil {
		return err
	}
	reader := wire.NewReader(frame.Payload)
	confirm := protocol.DecodeUDPTargetConfirm(reader)
	if reader.Err() != nil || !reader.EOF() {
		return fmt.Errorf("client: UDP target confirmation is malformed")
	}
	confirmedHost := net.IP(confirm.SelectedIP).String()
	if confirmedHost == "" {
		return fmt.Errorf("client: UDP target confirmation has an invalid selected IP")
	}
	flow.mu.Lock()
	flow.confirmed = true
	flow.replyTarget = udpProxyTarget{kind: confirm.TargetKind, host: confirmedHost, port: confirm.SelectedPort}
	flow.mu.Unlock()
	return nil
}

func (r *TCPProxyRuntime) enqueueUDPWrite(frame protocol.AuroraFrame) error {
	if len(frame.Payload) == 0 {
		return fmt.Errorf("client: UDP proxy relay data is empty")
	}
	flow := r.udpFlow(frame.FlowID)
	if flow == nil {
		return fmt.Errorf("client: UDP proxy relay data targets an unknown flow")
	}
	flow.mu.Lock()
	confirmed := flow.confirmed
	target := flow.replyTarget
	flow.mu.Unlock()
	if !confirmed || target.host == "" || target.port == 0 {
		return fmt.Errorf("client: UDP proxy relay data arrived before target confirmation")
	}
	packet, err := socks5UDPDatagram(target.host, target.port, frame.Payload)
	if err != nil {
		return err
	}
	defer zeroTCPProxyBytes(packet)
	return flow.association.write(packet)
}

func socks5UDPDatagram(host string, port uint16, payload []byte) ([]byte, error) {
	targetKind, targetHost, err := localTarget(host)
	if err != nil {
		return nil, err
	}
	packet := []byte{0, 0, 0}
	switch targetKind {
	case flow.TargetKindIPv4:
		packet = append(packet, socksATYPIPv4)
	case flow.TargetKindIPv6:
		packet = append(packet, socksATYPIPv6)
	case flow.TargetKindDomainName:
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("client: SOCKS5 UDP domain is too long")
		}
		packet = append(packet, socksATYPDomain, byte(len(targetHost)))
	default:
		return nil, fmt.Errorf("client: SOCKS5 UDP target is invalid")
	}
	packet = append(packet, targetHost...)
	packet = append(packet, byte(port>>8), byte(port))
	return append(packet, payload...), nil
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
	if flow.draining {
		flow.mu.Unlock()
		zeroTCPProxyBytes(owned)
		return fmt.Errorf("client: TCP proxy flow is closed")
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
			drainComplete := flow.draining && flow.pendingWrites == 0
			flow.mu.Unlock()
			if err != nil {
				r.abortFlow(flow.id)
				return
			}
			if drainComplete {
				_ = flow.close()
				return
			}
		}
	}
}

func (r *TCPProxyRuntime) handlePeerFlowClose(frame protocol.AuroraFrame) error {
	if r.flow(frame.FlowID) == nil {
		if r.udpFlow(frame.FlowID) == nil {
			return fmt.Errorf("client: proxy relay close targets an unknown flow")
		}
		if err := r.proxy.ReceiveFlowCloseFrame(frame, uint64(time.Now().Unix()), 0); err != nil {
			return err
		}
		r.removeUDPFlow(frame.FlowID)
		return nil
	}
	if err := r.proxy.ReceiveFlowCloseFrame(frame, uint64(time.Now().Unix()), 0); err != nil {
		return err
	}
	flow := r.detachFlow(frame.FlowID)
	_ = r.proxy.Close(frame.FlowID)
	if flow == nil {
		return nil
	}
	return flow.drainAndClose()
}

func (r *TCPProxyRuntime) abortFlow(flowID uint64) {
	flow := r.detachFlow(flowID)
	if flow == nil {
		return
	}
	_ = r.proxy.Close(flowID)
	_ = flow.close()
}

func (r *TCPProxyRuntime) udpFlow(flowID uint64) *udpProxyFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.udpFlows[flowID]
}

func (r *TCPProxyRuntime) removeUDPFlow(flowID uint64) {
	r.mu.Lock()
	flow := r.udpFlows[flowID]
	delete(r.udpFlows, flowID)
	r.mu.Unlock()
	if flow != nil {
		_ = r.proxy.Close(flowID)
	}
}

func (r *TCPProxyRuntime) addUDPAssociation(association *udpProxyAssociation) error {
	if association == nil {
		return fmt.Errorf("client: SOCKS5 UDP association is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrTCPProxyClosed
	}
	if len(r.udpLinks) >= r.options.MaxFlows {
		return ErrTCPProxyFlowLimit
	}
	r.udpLinks[association] = struct{}{}
	return nil
}

func (r *TCPProxyRuntime) removeUDPAssociation(association *udpProxyAssociation) {
	if association == nil {
		return
	}
	r.mu.Lock()
	notifyPeer := !r.closed
	delete(r.udpLinks, association)
	flowIDs := make([]uint64, 0)
	for flowID, flow := range r.udpFlows {
		if flow.association == association {
			delete(r.udpFlows, flowID)
			flowIDs = append(flowIDs, flowID)
		}
	}
	r.mu.Unlock()
	for _, flowID := range flowIDs {
		frame, err := r.proxy.CloseFrame(flowID, 0, nil)
		if err != nil {
			_ = r.proxy.Close(flowID)
			continue
		}
		if notifyPeer {
			_ = r.application.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}})
		}
		zeroTCPProxyBytes(frame.Payload)
	}
}

func (a *udpProxyAssociation) acceptPeer(peer *net.UDPAddr) bool {
	if a == nil || peer == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	if a.peer != nil {
		return a.peer.IP.Equal(peer.IP) && a.peer.Port == peer.Port
	}
	if a.peerIP != nil && !a.peerIP.Equal(peer.IP) {
		return false
	}
	if a.peerPort != 0 && a.peerPort != peer.Port {
		return false
	}
	a.peer = &net.UDPAddr{IP: append(net.IP(nil), peer.IP...), Port: peer.Port, Zone: peer.Zone}
	return true
}

func (a *udpProxyAssociation) write(packet []byte) error {
	if a == nil || len(packet) == 0 {
		return fmt.Errorf("client: SOCKS5 UDP response is invalid")
	}
	a.mu.Lock()
	if a.closed || a.peer == nil {
		a.mu.Unlock()
		return fmt.Errorf("client: SOCKS5 UDP association peer is unavailable")
	}
	peer := &net.UDPAddr{IP: append(net.IP(nil), a.peer.IP...), Port: a.peer.Port, Zone: a.peer.Zone}
	a.mu.Unlock()
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	count, err := a.connection.WriteToUDP(packet, peer)
	if err != nil {
		return fmt.Errorf("client: write SOCKS5 UDP response: %w", err)
	}
	if count != len(packet) {
		return io.ErrShortWrite
	}
	return nil
}

func (a *udpProxyAssociation) close() error {
	if a == nil {
		return nil
	}
	var closeErr error
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.peer = nil
		a.mu.Unlock()
		closeErr = a.connection.Close()
	})
	return closeErr
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

func (f *tcpProxyFlow) drainAndClose() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	select {
	case <-f.done:
		f.mu.Unlock()
		return nil
	default:
	}
	f.draining = true
	drainComplete := f.pendingWrites == 0
	f.mu.Unlock()
	if drainComplete {
		return f.close()
	}
	return nil
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
