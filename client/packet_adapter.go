package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
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
	defaultPacketAdapterFlows        = 256
	maximumPacketAdapterFlows        = 4096
	defaultPacketAdapterPacketBytes  = 65535
	minimumPacketAdapterPacketBytes  = 128
	maximumPacketAdapterPacketBytes  = 65535
	defaultPacketAdapterLocalPackets = 256
	maximumPacketAdapterLocalPackets = 4096
	defaultPacketAdapterDNSLifetime  = 15 * time.Second
	// Matches the relay's UDP target-confirm TTL: an association idle for
	// longer than that is already unusable, so the adapter must not keep
	// mirroring it against the flow limit.
	defaultPacketAdapterUDPIdleLifetime      = 300 * time.Second
	maximumPacketAdapterDNSMessageBytes      = 4096
	defaultPacketAdapterIPv4FragmentLifetime = 15 * time.Second
	maximumPacketAdapterIPv4FragmentSets     = 32
	maximumPacketAdapterIPv4Fragments        = 128
	defaultPacketAdapterIPv6FragmentLifetime = 15 * time.Second
	maximumPacketAdapterIPv6FragmentSets     = 32
	maximumPacketAdapterIPv6Fragments        = 128
	packetAdapterTCP                         = 6
	packetAdapterUDP                         = 17
	packetAdapterDNSPort                     = 53
	packetAdapterIPv6HopByHop                = 0
	packetAdapterIPv6Fragment                = 44
	packetAdapterIPv6Destination             = 60
	maximumPacketAdapterIPv6Options          = 2
	tcpFlagFIN                               = 0x01
	tcpFlagSYN                               = 0x02
	tcpFlagRST                               = 0x04
	tcpFlagPSH                               = 0x08
	tcpFlagACK                               = 0x10
	tcpFlagECE                               = 0x40
	tcpFlagCWR                               = 0x80
	// tcpSYNIgnoredFlags are the SYN companion flags the adapter tolerates. A
	// kernel with ECN enabled sets ECE|CWR on every outgoing SYN; the adapter
	// answers with a plain SYN|ACK, which is how RFC 3168 declines ECN.
	tcpSYNIgnoredFlags = tcpFlagECE | tcpFlagCWR
)

// ErrPacketAdapterClosed reports packet processing attempted after adapter shutdown.
var ErrPacketAdapterClosed = errors.New("client: packet adapter is closed")

// errPacketAdapterUnsupportedProtocol marks well-formed local packets that carry
// a protocol or IPv6 extension the tunnel does not serve (for example ICMP and
// ICMPv6). Ingress drops these packets and reports nil so that routine host
// traffic cannot terminate the tunnel; only malformed packets report errors.
var errPacketAdapterUnsupportedProtocol = errors.New("client: packet adapter protocol is unsupported")

// LocalDNSAnswers resolves a captured local DNS query without exposing it to a public resolver.
type LocalDNSAnswers func(context.Context, []byte) ([]string, error)

// PacketAdapterOptions bounds packet-tunnel flow and packet processing.
type PacketAdapterOptions struct {
	MaxFlows        int
	MaxPacketBytes  int
	MaxLocalPackets int
	UDPMode         transport.UDPMode
	Random          io.Reader
	DNSAnswers      LocalDNSAnswers
}

// PacketAdapter converts bounded local IP packets to existing encrypted flow frames.
type PacketAdapter struct {
	mu sync.Mutex

	application   *session.Application
	proxy         *LocalProxy
	maximumFlows  int
	maximumPacket int
	maximumLocal  int
	udpMode       transport.UDPMode
	random        io.Reader
	dnsAnswers    LocalDNSAnswers
	closed        bool
	nextFlowID    uint64
	nextPacketID  uint16
	flowsByTuple  map[packetAdapterTuple]*packetAdapterFlow
	flowsByID     map[uint64]*packetAdapterFlow
	dnsRequests   map[uint64]packetAdapterDNSRequest
	ipv4Fragments map[packetAdapterIPv4FragmentKey]*packetAdapterIPv4FragmentSet
	ipv6Fragments map[packetAdapterIPv6FragmentKey]*packetAdapterIPv6FragmentSet
	localPackets  [][]byte
	// pendingFlowCloses retains locally committed flow teardown (idle UDP expiry
	// and non-retransmitted TCP resets) until the bounded application queue
	// accepts it. Ingress and the encrypted writer both retry it; while it is
	// unqueued, new ingress is dropped so the slice remains bounded by MaxFlows.
	pendingFlowCloses []protocol.AuroraFrame
}

type packetAdapterTuple struct {
	version    uint8
	protocol   uint8
	client     netip.Addr
	target     netip.Addr
	clientPort uint16
	targetPort uint16
}

type packetAdapterFlow struct {
	flowID             uint64
	tuple              packetAdapterTuple
	kind               uint8
	clientNextSequence uint32
	relayNextSequence  uint32
	localClosed        bool
	peerClosed         bool
	lastActivity       time.Time
}

type packetAdapterDNSRequest struct {
	version       uint8
	client        netip.Addr
	target        netip.Addr
	clientPort    uint16
	targetPort    uint16
	transactionID uint16
	expiresAt     time.Time
}

type packetAdapterIPv4FragmentKey struct {
	protocol uint8
	source   netip.Addr
	target   netip.Addr
	id       uint16
}

type packetAdapterIPv4Fragment struct {
	key     packetAdapterIPv4FragmentKey
	header  []byte
	payload []byte
	offset  int
	more    bool
}

type packetAdapterIPv4FragmentSegment struct {
	offset  int
	payload []byte
}

type packetAdapterIPv4FragmentSet struct {
	header             []byte
	segments           []packetAdapterIPv4FragmentSegment
	totalPayloadLength int
	payloadBytes       int
	expiresAt          time.Time
}

type packetAdapterIPv6FragmentKey struct {
	source netip.Addr
	target netip.Addr
	id     uint32
}

type packetAdapterIPv6FragmentPacket struct {
	key                     packetAdapterIPv6FragmentKey
	header                  []byte
	nextHeaderOffset        int
	nextHeaderAfterFragment uint8
	payload                 []byte
	offset                  int
	more                    bool
}

type packetAdapterIPv6FragmentSegment struct {
	offset  int
	payload []byte
}

type packetAdapterIPv6FragmentSet struct {
	header             []byte
	nextHeaderOffset   int
	nextHeader         uint8
	segments           []packetAdapterIPv6FragmentSegment
	totalPayloadLength int
	payloadBytes       int
	expiresAt          time.Time
}

type packetAdapterIPPacket struct {
	version  uint8
	protocol uint8
	source   netip.Addr
	target   netip.Addr
	tcp      packetAdapterTCPPacket
	udp      packetAdapterUDPPacket
}

type packetAdapterTCPPacket struct {
	sourcePort      uint16
	destinationPort uint16
	sequence        uint32
	acknowledgment  uint32
	flags           uint8
	payload         []byte
}

type packetAdapterUDPPacket struct {
	sourcePort      uint16
	destinationPort uint16
	payload         []byte
}

// NewPacketAdapter creates a packet-tunnel adapter bound to one encrypted application session.
func NewPacketAdapter(application *session.Application, options PacketAdapterOptions) (*PacketAdapter, error) {
	if application == nil {
		return nil, fmt.Errorf("client: packet adapter application is required")
	}
	maximumFlows, maximumPacket, maximumLocal, udpMode, err := normalizePacketAdapterOptions(options)
	if err != nil {
		return nil, err
	}
	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(randomSource, prefix); err != nil {
		zeroPacketAdapterBytes(prefix)
		return nil, fmt.Errorf("client: initialize packet adapter flow IDs: %w", err)
	}
	nextFlowID := binary.BigEndian.Uint64(prefix)
	zeroPacketAdapterBytes(prefix)
	if nextFlowID == 0 || nextFlowID > wire.MaxVarint {
		nextFlowID = 1
	}
	return &PacketAdapter{
		application:   application,
		proxy:         NewLocalProxy(),
		maximumFlows:  maximumFlows,
		maximumPacket: maximumPacket,
		maximumLocal:  maximumLocal,
		udpMode:       udpMode,
		random:        randomSource,
		dnsAnswers:    options.DNSAnswers,
		nextFlowID:    nextFlowID,
		flowsByTuple:  make(map[packetAdapterTuple]*packetAdapterFlow),
		flowsByID:     make(map[uint64]*packetAdapterFlow),
		dnsRequests:   make(map[uint64]packetAdapterDNSRequest),
		ipv4Fragments: make(map[packetAdapterIPv4FragmentKey]*packetAdapterIPv4FragmentSet),
		ipv6Fragments: make(map[packetAdapterIPv6FragmentKey]*packetAdapterIPv6FragmentSet),
	}, nil
}

// Close clears adapter-owned packet state. It does not close the application session.
func (a *PacketAdapter) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	zeroPacketAdapterPacketList(a.localPackets)
	a.localPackets = nil
	for key, set := range a.ipv4Fragments {
		a.discardIPv4FragmentSetLocked(key, set)
	}
	for key, set := range a.ipv6Fragments {
		a.discardIPv6FragmentSetLocked(key, set)
	}
	for flowID := range a.flowsByID {
		_ = a.proxy.Close(flowID)
	}
	zeroPacketAdapterBlocks([]protocol.FrameBlock{{Frames: a.pendingFlowCloses}})
	a.pendingFlowCloses = nil
	a.flowsByTuple = nil
	a.flowsByID = nil
	a.dnsRequests = nil
	a.application = nil
	a.proxy = nil
	a.random = nil
	a.dnsAnswers = nil
}

// Ingress captures one local packet and queues the corresponding encrypted flow
// frames. Well-formed packets the tunnel cannot serve (unsupported protocols or
// IPv6 extensions) and packets refused for transient queue backpressure
// (session.ErrBackpressure) are dropped and report nil; malformed or
// contradictory packets report errors.
func (a *PacketAdapter) Ingress(ctx context.Context, encoded []byte, now time.Time) error {
	if a == nil {
		return fmt.Errorf("client: packet adapter is nil")
	}
	if ctx == nil {
		return fmt.Errorf("client: packet adapter context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return fmt.Errorf("client: packet adapter requires a valid time")
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrPacketAdapterClosed
	}
	a.expireIPv4FragmentsLocked(now)
	a.expireIPv6FragmentsLocked(now)
	expiredUDPFrames, err := a.expireUDPFlowsLocked(now)
	hasDNSAnswers := a.dnsAnswers != nil
	if err != nil {
		a.mu.Unlock()
		return err
	}
	a.pendingFlowCloses = append(a.pendingFlowCloses, expiredUDPFrames...)
	if len(a.pendingFlowCloses) != 0 {
		if err := a.queuePendingFlowClosesLocked(ctx); err != nil {
			a.mu.Unlock()
			// Expiration is already committed locally. Retain the unqueued closes and
			// drop this ingress packet until queue capacity is available, so relay
			// sockets are eventually reclaimed without growing cleanup state.
			return dropPacketAdapterBackpressure(err)
		}
	}
	a.mu.Unlock()
	if fragment, fragmented, err := parsePacketAdapterIPv4Fragment(encoded, a.maximumPacket); err != nil {
		return err
	} else if fragmented {
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			return ErrPacketAdapterClosed
		}
		reassembled, err := a.ingressIPv4FragmentLocked(fragment, now)
		a.mu.Unlock()
		if err != nil {
			return err
		}
		if reassembled == nil {
			return nil
		}
		defer zeroPacketAdapterBytes(reassembled)
		encoded = reassembled
	}
	if fragment, fragmented, err := parsePacketAdapterIPv6Fragment(encoded, a.maximumPacket); err != nil {
		// The fragment pre-pass walks the IPv6 extension chain and can meet an
		// unservable option before the main parse does; drop it the same way.
		if errors.Is(err, errPacketAdapterUnsupportedProtocol) {
			return nil
		}
		return err
	} else if fragmented {
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			return ErrPacketAdapterClosed
		}
		reassembled, err := a.ingressIPv6FragmentLocked(fragment, now)
		a.mu.Unlock()
		if err != nil {
			return err
		}
		if reassembled == nil {
			return nil
		}
		defer zeroPacketAdapterBytes(reassembled)
		encoded = reassembled
	}
	packet, err := parsePacketAdapterIPPacket(encoded, a.maximumPacket)
	if err != nil {
		if errors.Is(err, errPacketAdapterUnsupportedProtocol) {
			return nil
		}
		return err
	}
	if packet.protocol == packetAdapterUDP && packet.udp.destinationPort == packetAdapterDNSPort {
		if hasDNSAnswers {
			return dropPacketAdapterBackpressure(a.ingressDNS(ctx, packet, now))
		}
		return dropPacketAdapterBackpressure(a.ingressRelayedDNS(ctx, packet, now))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrPacketAdapterClosed
	}
	switch packet.protocol {
	case packetAdapterTCP:
		return dropPacketAdapterBackpressure(a.ingressTCPLocked(ctx, packet, now))
	case packetAdapterUDP:
		return dropPacketAdapterBackpressure(a.ingressUDPLocked(ctx, packet, now))
	default:
		return fmt.Errorf("client: unsupported packet protocol %d", packet.protocol)
	}
}

// NextEncryptedPacket waits for one encrypted packet queued by Ingress.
func (a *PacketAdapter) NextEncryptedPacket(ctx context.Context) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, ErrPacketAdapterClosed
	}
	application := a.application
	var flushErr error
	if len(a.pendingFlowCloses) != 0 {
		flushErr = a.queuePendingFlowClosesLocked(ctx)
	}
	a.mu.Unlock()
	if application == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	if flushErr != nil && !errors.Is(flushErr, session.ErrBackpressure) {
		return nil, flushErr
	}
	return application.NextPacket(ctx)
}

// HandleEncryptedPacket decrypts a relay packet and returns packets for the local tunnel.
func (a *PacketAdapter) HandleEncryptedPacket(ctx context.Context, encoded []byte, now time.Time) ([][]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("client: packet adapter context is nil")
	}
	if now.IsZero() || now.Unix() < 0 {
		return nil, fmt.Errorf("client: packet adapter requires a valid time")
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, ErrPacketAdapterClosed
	}
	application := a.application
	a.mu.Unlock()
	if application == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("client: encrypted packet size is invalid")
	}
	// MaxPacketBytes bounds cleartext IP packets crossing the TUN interface,
	// not authenticated carrier packets. Relay STREAM_DATA frames routinely
	// exceed an interface MTU and are segmented after decryption. Application
	// enforces its independently configured encrypted-packet input limit.
	blocks, err := application.HandlePacket(ctx, now, encoded)
	if err != nil {
		return nil, err
	}
	defer zeroPacketAdapterBlocks(blocks)
	return a.HandleFrameBlocks(ctx, blocks, now)
}

// HandleFrameBlocks converts decrypted relay frames to packets for the local tunnel.
// Callers retain ownership of blocks and must not mutate them until this method returns.
func (a *PacketAdapter) HandleFrameBlocks(ctx context.Context, blocks []protocol.FrameBlock, now time.Time) ([][]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("client: packet adapter context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return nil, fmt.Errorf("client: packet adapter requires a valid time")
	}
	for _, block := range blocks {
		if err := protocol.ValidateFrameBlock(block); err != nil {
			return nil, fmt.Errorf("client: invalid decoded relay frame block: %w", err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.application == nil {
		return nil, ErrPacketAdapterClosed
	}
	a.expireDNSRequestsLocked(now)
	var local [][]byte
	for _, block := range blocks {
		for _, frame := range block.Frames {
			packets, err := a.handleRelayFrameLocked(frame, now)
			if err != nil {
				zeroPacketAdapterPacketList(local)
				return nil, err
			}
			if len(packets) > a.maximumLocal-len(local) {
				zeroPacketAdapterPacketList(packets)
				zeroPacketAdapterPacketList(local)
				return nil, fmt.Errorf("client: relay frame block exceeds local packet limit")
			}
			local = append(local, packets...)
		}
	}
	return local, nil
}

// DrainLocalPackets returns synthetic packets created while accepting local traffic.
func (a *PacketAdapter) DrainLocalPackets() [][]byte {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	packets := a.localPackets
	a.localPackets = nil
	return packets
}

// FlowCount returns the number of active local packet mappings.
func (a *PacketAdapter) FlowCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flowCountLocked()
}

func (a *PacketAdapter) ingressTCPLocked(ctx context.Context, packet packetAdapterIPPacket, now time.Time) error {
	tuple := packetAdapterTuple{
		version: packet.version, protocol: packet.protocol, client: packet.source, target: packet.target,
		clientPort: packet.tcp.sourcePort, targetPort: packet.tcp.destinationPort,
	}
	mapping := a.flowsByTuple[tuple]
	if packet.tcp.flags&tcpFlagSYN != 0 {
		if packet.tcp.flags&^(tcpFlagSYN|tcpSYNIgnoredFlags) != 0 || len(packet.tcp.payload) != 0 {
			// A well-formed SYN the tunnel cannot serve: a TCP Fast Open SYN
			// carrying data, or an inbound SYN|ACK. Drop it as ingress does for
			// unsupported protocols — the kernel retries a Fast Open SYN without
			// its payload, while failing here would end every other flow too.
			return nil
		}
		if mapping != nil {
			if mapping.clientNextSequence != packet.tcp.sequence+1 {
				return fmt.Errorf("client: TCP SYN does not match existing packet flow")
			}
			response, err := a.makeTCPPacketLocked(mapping, mapping.relayNextSequence-1, mapping.clientNextSequence, tcpFlagSYN|tcpFlagACK, nil)
			if err != nil {
				return err
			}
			return a.enqueueLocalPacketLocked(response)
		}
		if a.flowCountLocked() >= a.maximumFlows {
			// The tunnel cannot carry another flow, but the flows it already
			// carries are healthy: refuse this connection instead of ending
			// the session. A RST lets the application fail immediately rather
			// than retransmitting a SYN into a blackhole.
			refused := &packetAdapterFlow{tuple: tuple}
			response, err := a.makeTCPPacketLocked(refused, 0, packet.tcp.sequence+1, tcpFlagACK|tcpFlagRST, nil)
			if err != nil {
				return nil
			}
			return a.enqueueLocalPacketLocked(response)
		}
		if len(a.localPackets) >= a.maximumLocal {
			return session.ErrBackpressure
		}
		flowID, err := a.allocateFlowIDLocked()
		if err != nil {
			return err
		}
		serverSequence, err := a.readUint32Locked()
		if err != nil {
			return err
		}
		_, open, err := a.proxy.OpenTCPFromFakeIPFrame(flowID, packet.target.String(), packet.tcp.destinationPort)
		if errors.Is(err, flow.ErrUnknownFakeIP) {
			open, err = a.proxy.OpenTUNTCPFrame(flowID, packet.target.String(), packet.tcp.destinationPort)
		}
		if err != nil {
			return err
		}
		if err := a.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{open}}); err != nil {
			_ = a.proxy.Close(flowID)
			return err
		}
		mapping = &packetAdapterFlow{
			flowID: flowID, tuple: tuple, kind: flow.FlowKindTCPStream,
			clientNextSequence: packet.tcp.sequence + 1,
			relayNextSequence:  serverSequence + 1,
		}
		a.flowsByTuple[tuple] = mapping
		a.flowsByID[flowID] = mapping
		response, err := a.makeTCPPacketLocked(mapping, serverSequence, mapping.clientNextSequence, tcpFlagSYN|tcpFlagACK, nil)
		if err != nil {
			return err
		}
		return a.enqueueLocalPacketLocked(response)
	}
	if mapping == nil || mapping.kind != flow.FlowKindTCPStream || mapping.localClosed {
		// A non-SYN packet with no live flow is routine close-handshake fallout:
		// the kernel's final ACK and late retransmits arrive after the flow was
		// removed, and half-close ACKs arrive after the local FIN. No flow state
		// exists to desync, so drop the packet instead of failing the session.
		// A genuine kernel/adapter divergence still surfaces as a sequence
		// mismatch on a live flow below.
		return nil
	}
	if packet.tcp.flags&tcpFlagRST != 0 {
		return a.closeLocalFlowLocked(ctx, mapping, now, false)
	}
	if packet.tcp.sequence != mapping.clientNextSequence {
		if tcpSequenceBefore(packet.tcp.sequence, mapping.clientNextSequence) {
			response, err := a.makeTCPPacketLocked(mapping, mapping.relayNextSequence, mapping.clientNextSequence, tcpFlagACK, nil)
			if err != nil {
				return err
			}
			return a.enqueueLocalPacketLocked(response)
		}
		return fmt.Errorf("client: packet adapter received out-of-order TCP data")
	}
	frames := make([]protocol.AuroraFrame, 0, 2)
	if len(packet.tcp.payload) != 0 {
		frame, err := a.proxy.SendTCP(mapping.flowID, packet.tcp.payload, 0)
		if err != nil {
			return err
		}
		frames = append(frames, frame)
	}
	fin := packet.tcp.flags&tcpFlagFIN != 0
	if fin {
		frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: mapping.flowID, CloseCode: protocol.CloseNormal, FinalSequenceHintPresent: true, FinalSequenceHint: uint64(packet.tcp.sequence) + uint64(len(packet.tcp.payload)) + 1})
		if err != nil {
			return err
		}
		frames = append(frames, frame)
	}
	if len(frames) != 0 {
		if len(a.localPackets) >= a.maximumLocal {
			return session.ErrBackpressure
		}
		if err := a.application.QueueFrames(ctx, protocol.FrameBlock{Frames: frames}); err != nil {
			return err
		}
		mapping.clientNextSequence += uint32(len(packet.tcp.payload))
		if fin {
			mapping.clientNextSequence++
			mapping.localClosed = true
			_ = a.proxy.Close(mapping.flowID)
			if mapping.peerClosed {
				// The relay closed first (a server-initiated close), so this FIN
				// completes the mutual close. Retire the mapping here as
				// closeLocalFlowLocked does, otherwise the tuple and flow ID leak
				// until the adapter is closed and a later connection reusing the
				// local port collides with the dead mapping.
				a.removeFlowLocked(mapping)
			}
		}
		response, err := a.makeTCPPacketLocked(mapping, mapping.relayNextSequence, mapping.clientNextSequence, tcpFlagACK, nil)
		if err != nil {
			return err
		}
		return a.enqueueLocalPacketLocked(response)
	}
	return nil
}

func (a *PacketAdapter) ingressUDPLocked(ctx context.Context, packet packetAdapterIPPacket, now time.Time) error {
	tuple := packetAdapterTuple{
		version: packet.version, protocol: packet.protocol, client: packet.source, target: packet.target,
		clientPort: packet.udp.sourcePort, targetPort: packet.udp.destinationPort,
	}
	mapping := a.flowsByTuple[tuple]
	frames := make([]protocol.AuroraFrame, 0, 2)
	var data protocol.AuroraFrame
	if mapping != nil {
		mapping.lastActivity = now
		data, err := a.proxy.SendUDPWithOptions(mapping.flowID, packet.udp.payload, UDPSendOptions{NowUnix: uint64(now.Unix()), UDPMode: a.udpMode})
		if err != nil {
			if a.proxy.HasFlow(mapping.flowID) {
				return err
			}
			a.removeFlowLocked(mapping)
			mapping = nil
		} else {
			frames = append(frames, data)
		}
	}
	if mapping == nil {
		if a.flowCountLocked() >= a.maximumFlows {
			// UDP has no refusal signal, so drop the datagram: an unservable
			// association must not end the flows the tunnel already carries.
			return nil
		}
		flowID, err := a.allocateFlowIDLocked()
		if err != nil {
			return err
		}
		_, open, err := a.proxy.OpenUDPFromFakeIPFrame(flowID, packet.target.String(), packet.udp.destinationPort, uint64(now.Unix()))
		if errors.Is(err, flow.ErrUnknownFakeIP) {
			open, err = a.proxy.OpenTUNUDPFrame(flowID, packet.target.String(), packet.udp.destinationPort, uint64(now.Unix()))
		}
		if err != nil {
			return err
		}
		mapping = &packetAdapterFlow{flowID: flowID, tuple: tuple, kind: flow.FlowKindUDPAssociation, lastActivity: now}
		frames = append(frames, open)
		data, err = a.proxy.SendUDPWithOptions(mapping.flowID, packet.udp.payload, UDPSendOptions{NowUnix: uint64(now.Unix()), UDPMode: a.udpMode})
		if err != nil {
			_ = a.proxy.Close(mapping.flowID)
			return err
		}
		frames = append(frames, data)
	}
	if err := a.application.QueueFrames(ctx, protocol.FrameBlock{Frames: frames}); err != nil {
		if len(frames) == 2 {
			_ = a.proxy.Close(mapping.flowID)
		}
		return err
	}
	if _, exists := a.flowsByID[mapping.flowID]; !exists {
		a.flowsByTuple[tuple] = mapping
		a.flowsByID[mapping.flowID] = mapping
	}
	return nil
}

func (a *PacketAdapter) ingressDNS(ctx context.Context, packet packetAdapterIPPacket, now time.Time) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrPacketAdapterClosed
	}
	dnsAnswers := a.dnsAnswers
	a.mu.Unlock()
	if dnsAnswers == nil {
		return fmt.Errorf("client: packet adapter local DNS answers are unavailable")
	}
	answers, err := dnsAnswers(ctx, append([]byte(nil), packet.udp.payload...))
	if err != nil {
		return fmt.Errorf("client: packet adapter local DNS answer: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrPacketAdapterClosed
	}
	if len(a.localPackets) >= a.maximumLocal {
		return session.ErrBackpressure
	}
	flowID, err := a.allocateFlowIDLocked()
	if err != nil {
		return err
	}
	result, err := a.proxy.AnswerLocalDNSQuery(flowID, packet.udp.payload, answers, uint64(now.Unix()))
	if err != nil {
		return fmt.Errorf("client: packet adapter local DNS query: %w", err)
	}
	response, err := buildPacketAdapterUDPPacket(packet.version, packet.target, packet.source, packet.udp.destinationPort, packet.udp.sourcePort, result.Response, a.nextPacketID)
	if err != nil {
		return err
	}
	if err := a.validateLocalPacketLocked(response); err != nil {
		return err
	}
	if result.Frame.FrameType != 0 {
		if err := a.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{result.Frame}}); err != nil {
			zeroPacketAdapterBytes(response)
			return err
		}
	}
	a.nextPacketID++
	return a.enqueueLocalPacketLocked(response)
}

func (a *PacketAdapter) ingressRelayedDNS(ctx context.Context, packet packetAdapterIPPacket, now time.Time) error {
	transactionID, err := packetAdapterDNSQueryTransactionID(packet.udp.payload)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrPacketAdapterClosed
	}
	a.expireDNSRequestsLocked(now)
	if a.flowCountLocked() >= a.maximumFlows {
		// Drop the query rather than ending every other flow; the resolver
		// retries, and pending DNS flows expire on their own.
		return nil
	}
	flowID, err := a.allocateFlowIDLocked()
	if err != nil {
		return err
	}
	frame, err := protocol.NewDNSMessageFrame(flowID, packet.udp.payload)
	if err != nil {
		return err
	}
	if err := a.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		return err
	}
	a.dnsRequests[flowID] = packetAdapterDNSRequest{
		version:       packet.version,
		client:        packet.source,
		target:        packet.target,
		clientPort:    packet.udp.sourcePort,
		targetPort:    packet.udp.destinationPort,
		transactionID: transactionID,
		expiresAt:     now.Add(defaultPacketAdapterDNSLifetime),
	}
	return nil
}

func (a *PacketAdapter) handleRelayFrameLocked(frame protocol.AuroraFrame, now time.Time) ([][]byte, error) {
	switch frame.FrameType {
	case registry.FramePadding:
		return nil, nil
	case registry.FrameDNSMessage:
		return a.handleRelayDNSLocked(frame, now)
	case registry.FrameUDPTargetConfirm:
		mapping := a.flowsByID[frame.FlowID]
		if mapping == nil {
			// The association may have expired locally while its confirmation was
			// still in flight. Like late data and FLOW_CLOSE frames, a confirmation
			// for retired state is harmless and must not end the entire tunnel.
			return nil, nil
		}
		if mapping.kind != flow.FlowKindUDPAssociation {
			return nil, fmt.Errorf("client: packet adapter received UDP target confirmation for a non-UDP flow")
		}
		if err := a.proxy.ReceiveUDPTargetConfirmFrameAt(frame, uint64(now.Unix())); err != nil {
			return nil, err
		}
		return nil, nil
	case registry.FrameFlowClose:
		return a.handleRelayCloseLocked(frame, now)
	case registry.FrameStreamData, registry.FrameDatagramData:
		return a.handleRelayDataLocked(frame, now)
	default:
		return nil, fmt.Errorf("client: packet adapter received unsupported relay frame 0x%x", frame.FrameType)
	}
}

func (a *PacketAdapter) handleRelayDNSLocked(frame protocol.AuroraFrame, now time.Time) ([][]byte, error) {
	request, ok := a.dnsRequests[frame.FlowID]
	if !ok {
		// Pending DNS requests are deliberately short lived. A response delayed
		// past that lifetime names state the adapter has already retired, so drop
		// it instead of turning one stale lookup into a tunnel-wide failure.
		return nil, nil
	}
	if !now.Before(request.expiresAt) {
		delete(a.dnsRequests, frame.FlowID)
		return nil, nil
	}
	if err := packetAdapterDNSResponseMatches(frame.Payload, request.transactionID); err != nil {
		return nil, err
	}
	packet, err := buildPacketAdapterUDPPacket(request.version, request.target, request.client, request.targetPort, request.clientPort, frame.Payload, a.nextPacketID)
	if err != nil {
		return nil, err
	}
	if err := a.validateLocalPacketLocked(packet); err != nil {
		return nil, err
	}
	delete(a.dnsRequests, frame.FlowID)
	a.nextPacketID++
	return [][]byte{packet}, nil
}

func (a *PacketAdapter) handleRelayDataLocked(frame protocol.AuroraFrame, now time.Time) ([][]byte, error) {
	mapping := a.flowsByID[frame.FlowID]
	if mapping == nil {
		// The flow was retired locally (a local reset or a completed close) while
		// the relay still had data on the wire. No flow state exists to desync,
		// so drop the frame instead of failing the whole tunnel.
		return nil, nil
	}
	if mapping.peerClosed {
		return nil, fmt.Errorf("client: packet adapter received data after the relay closed the flow")
	}
	switch mapping.kind {
	case flow.FlowKindTCPStream:
		if frame.FrameType != registry.FrameStreamData {
			return nil, fmt.Errorf("client: packet adapter received non-stream TCP data")
		}
		return a.makeRelayTCPPacketsLocked(mapping, frame.Payload)
	case flow.FlowKindUDPAssociation:
		if frame.FrameType != registry.FrameDatagramData && (frame.FrameType != registry.FrameStreamData || a.udpMode != transport.UDPOverStreamFallback) {
			return nil, fmt.Errorf("client: packet adapter received invalid UDP data frame")
		}
		// Relayed datagrams keep the association alive: a long inbound-only
		// transfer must not be swept out from under the client.
		mapping.lastActivity = now
		packet, err := buildPacketAdapterUDPPacket(mapping.tuple.version, mapping.tuple.target, mapping.tuple.client, mapping.tuple.targetPort, mapping.tuple.clientPort, frame.Payload, a.nextPacketID)
		if err != nil {
			return nil, err
		}
		if err := a.validateLocalPacketLocked(packet); err != nil {
			return nil, err
		}
		a.nextPacketID++
		return [][]byte{packet}, nil
	default:
		return nil, fmt.Errorf("client: packet adapter flow has unsupported kind")
	}
}

// makeRelayTCPPacketsLocked segments one relay stream frame into packets that
// fit the configured TUN MTU. The relay carries a byte stream and cannot know
// the client's platform MTU, so rejecting a valid large read here would turn
// ordinary destination traffic into a session-wide failure.
func (a *PacketAdapter) makeRelayTCPPacketsLocked(mapping *packetAdapterFlow, payload []byte) ([][]byte, error) {
	headerBytes := 40
	if mapping.tuple.version == 6 {
		headerBytes = 60
	} else if mapping.tuple.version != 4 {
		return nil, fmt.Errorf("client: packet adapter TCP flow has invalid IP version")
	}
	maximumPayload := a.maximumPacket - headerBytes
	if maximumPayload <= 0 {
		return nil, fmt.Errorf("client: packet adapter packet limit cannot hold TCP headers")
	}
	segmentCount := (len(payload)-1)/maximumPayload + 1
	if segmentCount > a.maximumLocal {
		return nil, fmt.Errorf("client: relay TCP data exceeds local packet limit")
	}
	packets := make([][]byte, 0, segmentCount)
	sequence := mapping.relayNextSequence
	for offset := 0; offset < len(payload); offset += maximumPayload {
		end := offset + maximumPayload
		if end > len(payload) {
			end = len(payload)
		}
		packet, err := a.makeTCPPacketLocked(mapping, sequence, mapping.clientNextSequence, tcpFlagACK|tcpFlagPSH, payload[offset:end])
		if err != nil {
			zeroPacketAdapterPacketList(packets)
			return nil, err
		}
		packets = append(packets, packet)
		sequence += uint32(end - offset)
	}
	mapping.relayNextSequence = sequence
	return packets, nil
}

func (a *PacketAdapter) handleRelayCloseLocked(frame protocol.AuroraFrame, now time.Time) ([][]byte, error) {
	mapping := a.flowsByID[frame.FlowID]
	if mapping == nil {
		// The relay answers a local reset with its own close, and repeats a close
		// it believes was lost. Both name a flow the adapter already retired, so
		// drop them rather than fail the tunnel.
		return nil, nil
	}
	r := wire.NewReader(frame.Payload)
	close := protocol.DecodeFlowClose(r)
	if r.Err() != nil || !r.EOF() || close.FlowID != frame.FlowID {
		return nil, fmt.Errorf("client: packet adapter received malformed flow close")
	}
	if err := a.proxy.ReceiveFlowCloseFrame(frame, uint64(now.Unix()), 0); err != nil && !mapping.localClosed {
		return nil, err
	}
	mapping.peerClosed = true
	if mapping.kind == flow.FlowKindUDPAssociation {
		a.removeFlowLocked(mapping)
		return nil, nil
	}
	flags := uint8(tcpFlagACK | tcpFlagFIN)
	if close.CloseCode != protocol.CloseNormal {
		flags = tcpFlagACK | tcpFlagRST
	}
	packet, err := a.makeTCPPacketLocked(mapping, mapping.relayNextSequence, mapping.clientNextSequence, flags, nil)
	if err != nil {
		return nil, err
	}
	if close.CloseCode != protocol.CloseNormal {
		a.removeFlowLocked(mapping)
		return [][]byte{packet}, nil
	}
	mapping.relayNextSequence++
	if mapping.localClosed {
		a.removeFlowLocked(mapping)
	}
	return [][]byte{packet}, nil
}

func (a *PacketAdapter) closeLocalFlowLocked(ctx context.Context, mapping *packetAdapterFlow, now time.Time, fin bool) error {
	if mapping == nil {
		return fmt.Errorf("client: packet adapter flow is unavailable")
	}
	closeCode := uint64(protocol.CloseNormal)
	if !fin {
		closeCode = protocol.CloseResetByPeer
	}
	frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: mapping.flowID, CloseCode: closeCode, FinalSequenceHintPresent: fin, FinalSequenceHint: uint64(mapping.clientNextSequence)})
	if err != nil {
		return err
	}
	if err := a.application.QueueFrames(ctx, protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		if !fin && errors.Is(err, session.ErrBackpressure) {
			// Unlike FIN, the local stack does not retransmit an RST. Commit the
			// reset locally and retain its close frame for the ordered retry path;
			// otherwise this dead tuple survives indefinitely under congestion.
			a.pendingFlowCloses = append(a.pendingFlowCloses, frame)
			a.removeFlowLocked(mapping)
		}
		return err
	}
	mapping.localClosed = true
	_ = a.proxy.Close(mapping.flowID)
	if !fin || mapping.peerClosed {
		a.removeFlowLocked(mapping)
	}
	return nil
}

func (a *PacketAdapter) makeTCPPacketLocked(mapping *packetAdapterFlow, sequence, acknowledgment uint32, flags uint8, payload []byte) ([]byte, error) {
	packet, err := buildPacketAdapterTCPPacket(mapping.tuple.version, mapping.tuple.target, mapping.tuple.client, mapping.tuple.targetPort, mapping.tuple.clientPort, sequence, acknowledgment, flags, payload, a.nextPacketID)
	if err != nil {
		return nil, err
	}
	if err := a.validateLocalPacketLocked(packet); err != nil {
		return nil, err
	}
	a.nextPacketID++
	return packet, nil
}

func (a *PacketAdapter) enqueueLocalPacketLocked(packet []byte) error {
	if err := a.validateLocalPacketLocked(packet); err != nil {
		return err
	}
	if len(a.localPackets) >= a.maximumLocal {
		zeroPacketAdapterBytes(packet)
		return session.ErrBackpressure
	}
	a.localPackets = append(a.localPackets, packet)
	return nil
}

func (a *PacketAdapter) validateLocalPacketLocked(packet []byte) error {
	if len(packet) == 0 {
		return fmt.Errorf("client: packet adapter local packet is empty")
	}
	if len(packet) > a.maximumPacket {
		zeroPacketAdapterBytes(packet)
		return fmt.Errorf("client: packet adapter local packet exceeds configured limit")
	}
	return nil
}

func (a *PacketAdapter) allocateFlowIDLocked() (uint64, error) {
	for attempts := 0; attempts <= a.maximumFlows; attempts++ {
		flowID := a.nextFlowID
		a.nextFlowID++
		if a.nextFlowID == 0 || a.nextFlowID > wire.MaxVarint {
			a.nextFlowID = 1
		}
		if flowID != 0 && a.flowsByID[flowID] == nil {
			if _, pendingDNS := a.dnsRequests[flowID]; !pendingDNS {
				return flowID, nil
			}
		}
	}
	return 0, fmt.Errorf("client: packet adapter flow ID space is exhausted")
}

func (a *PacketAdapter) flowCountLocked() int {
	return len(a.flowsByID) + len(a.dnsRequests)
}

func (a *PacketAdapter) readUint32Locked() (uint32, error) {
	value := make([]byte, 4)
	defer zeroPacketAdapterBytes(value)
	if _, err := io.ReadFull(a.random, value); err != nil {
		return 0, fmt.Errorf("client: generate synthetic TCP sequence: %w", err)
	}
	return binary.BigEndian.Uint32(value), nil
}

func (a *PacketAdapter) removeFlowLocked(mapping *packetAdapterFlow) {
	if mapping == nil {
		return
	}
	delete(a.flowsByTuple, mapping.tuple)
	delete(a.flowsByID, mapping.flowID)
	_ = a.proxy.Close(mapping.flowID)
}

// expireUDPFlowsLocked retires UDP associations the client stopped using and
// returns the FLOW_CLOSE frames that release their relay-side sockets. TCP
// mappings are reclaimed by their own close handshake, but a UDP conversation
// has no close, so without this sweep idle associations accumulate until the
// adapter refuses every new flow. a.mu must be held.
func (a *PacketAdapter) expireUDPFlowsLocked(now time.Time) ([]protocol.AuroraFrame, error) {
	var expired []*packetAdapterFlow
	for _, mapping := range a.flowsByID {
		if mapping.kind != flow.FlowKindUDPAssociation || mapping.lastActivity.IsZero() {
			continue
		}
		if now.Sub(mapping.lastActivity) >= defaultPacketAdapterUDPIdleLifetime {
			expired = append(expired, mapping)
		}
	}
	frames := make([]protocol.AuroraFrame, 0, len(expired))
	for _, mapping := range expired {
		frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
			FlowID:    mapping.flowID,
			CloseCode: protocol.CloseIdleTimeout,
		})
		if err != nil {
			zeroPacketAdapterBlocks([]protocol.FrameBlock{{Frames: frames}})
			return nil, fmt.Errorf("client: close expired UDP association: %w", err)
		}
		frames = append(frames, frame)
	}
	for _, mapping := range expired {
		a.removeFlowLocked(mapping)
	}
	return frames, nil
}

// queuePendingFlowClosesLocked queues prefixes the application can currently
// accept, splitting an oversized aggregate block until it makes progress.
// Successfully encoded payloads are zeroed before ownership is released; an
// unqueued suffix remains owned by the adapter for the next ingress attempt.
// a.mu must be held.
func (a *PacketAdapter) queuePendingFlowClosesLocked(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("client: packet adapter close queue context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	batchSize := len(a.pendingFlowCloses)
	for len(a.pendingFlowCloses) != 0 {
		if batchSize > len(a.pendingFlowCloses) {
			batchSize = len(a.pendingFlowCloses)
		}
		block := protocol.FrameBlock{Frames: a.pendingFlowCloses[:batchSize]}
		if err := a.application.QueueFrames(ctx, block); err != nil {
			if batchSize == 1 {
				return err
			}
			batchSize /= 2
			continue
		}
		for index := range batchSize {
			zeroPacketAdapterBytes(a.pendingFlowCloses[index].Payload)
			a.pendingFlowCloses[index] = protocol.AuroraFrame{}
		}
		a.pendingFlowCloses = a.pendingFlowCloses[batchSize:]
		batchSize = len(a.pendingFlowCloses)
	}
	a.pendingFlowCloses = nil
	return nil
}

func (a *PacketAdapter) expireDNSRequestsLocked(now time.Time) {
	for flowID, request := range a.dnsRequests {
		if !now.Before(request.expiresAt) {
			delete(a.dnsRequests, flowID)
		}
	}
}

func packetAdapterDNSQueryTransactionID(message []byte) (uint16, error) {
	if len(message) < 12 || len(message) > maximumPacketAdapterDNSMessageBytes || message[2]&0x80 != 0 || message[2]&0x78 != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
	}
	offset := 12
	nameBytes := 0
	for {
		if offset >= len(message) {
			return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
		}
		labelLength := int(message[offset])
		offset++
		nameBytes++
		if labelLength == 0 {
			break
		}
		if labelLength > 63 || nameBytes+labelLength > 255 || offset+labelLength > len(message) {
			return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
		}
		for _, value := range message[offset : offset+labelLength] {
			if value < 0x21 || value > 0x7e || value == '.' {
				return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
			}
		}
		offset += labelLength
		nameBytes += labelLength
	}
	if offset+4 > len(message) || binary.BigEndian.Uint16(message[offset+2:offset+4]) != 1 {
		return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
	}
	offset += 4
	if binary.BigEndian.Uint16(message[6:8]) != 0 || binary.BigEndian.Uint16(message[8:10]) != 0 || binary.BigEndian.Uint16(message[10:12]) > 4 {
		return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
	}
	for additional := 0; additional < int(binary.BigEndian.Uint16(message[10:12])); additional++ {
		nameBytes = 0
		for {
			if offset >= len(message) {
				return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
			}
			labelLength := int(message[offset])
			offset++
			nameBytes++
			if labelLength == 0 {
				break
			}
			if labelLength > 63 || nameBytes+labelLength > 255 || offset+labelLength > len(message) {
				return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
			}
			for _, value := range message[offset : offset+labelLength] {
				if value < 0x21 || value > 0x7e || value == '.' {
					return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
				}
			}
			offset += labelLength
			nameBytes += labelLength
		}
		if offset+10 > len(message) {
			return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
		}
		rdataLength := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += 10
		if rdataLength > len(message)-offset {
			return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
		}
		offset += rdataLength
	}
	if offset != len(message) {
		return 0, fmt.Errorf("client: packet adapter DNS query is malformed")
	}
	return binary.BigEndian.Uint16(message[:2]), nil
}

func packetAdapterDNSResponseMatches(message []byte, transactionID uint16) error {
	if len(message) < 12 || len(message) > maximumPacketAdapterDNSMessageBytes || message[2]&0x80 == 0 || message[2]&0x78 != 0 || binary.BigEndian.Uint16(message[:2]) != transactionID || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return fmt.Errorf("client: packet adapter DNS response is malformed")
	}
	return nil
}

func normalizePacketAdapterOptions(options PacketAdapterOptions) (int, int, int, transport.UDPMode, error) {
	maximumFlows := options.MaxFlows
	if maximumFlows == 0 {
		maximumFlows = defaultPacketAdapterFlows
	}
	if maximumFlows < 1 || maximumFlows > maximumPacketAdapterFlows {
		return 0, 0, 0, 0, fmt.Errorf("client: packet adapter flow limit is invalid")
	}
	maximumPacket := options.MaxPacketBytes
	if maximumPacket == 0 {
		maximumPacket = defaultPacketAdapterPacketBytes
	}
	if maximumPacket < minimumPacketAdapterPacketBytes || maximumPacket > maximumPacketAdapterPacketBytes {
		return 0, 0, 0, 0, fmt.Errorf("client: packet adapter packet limit is invalid")
	}
	maximumLocal := options.MaxLocalPackets
	if maximumLocal == 0 {
		maximumLocal = defaultPacketAdapterLocalPackets
	}
	if maximumLocal < 1 || maximumLocal > maximumPacketAdapterLocalPackets {
		return 0, 0, 0, 0, fmt.Errorf("client: packet adapter local packet limit is invalid")
	}
	udpMode := options.UDPMode
	if udpMode == 0 {
		udpMode = transport.UDPOverStreamFallback
	}
	if udpMode != transport.UDPOverStreamFallback && udpMode != transport.UDPNativeDatagram {
		return 0, 0, 0, 0, fmt.Errorf("client: packet adapter UDP mode is invalid")
	}
	return maximumFlows, maximumPacket, maximumLocal, udpMode, nil
}

func parsePacketAdapterIPPacket(encoded []byte, maximum int) (packetAdapterIPPacket, error) {
	if len(encoded) < 1 || len(encoded) > maximum {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IP packet size is invalid")
	}
	switch encoded[0] >> 4 {
	case 4:
		return parsePacketAdapterIPv4(encoded)
	case 6:
		return parsePacketAdapterIPv6(encoded)
	default:
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IP version is unsupported")
	}
}

func parsePacketAdapterIPv4(encoded []byte) (packetAdapterIPPacket, error) {
	if len(encoded) < 20 || encoded[0]&0x0f < 5 {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv4 header is malformed")
	}
	headerLength := int(encoded[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(encoded[2:4]))
	if headerLength > len(encoded) || totalLength != len(encoded) || totalLength < headerLength || packetAdapterChecksum(encoded[:headerLength]) != 0 {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv4 packet is malformed")
	}
	fragment := binary.BigEndian.Uint16(encoded[6:8])
	if fragment&0x3fff != 0 || encoded[8] == 0 {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv4 fragments are unsupported")
	}
	packet := packetAdapterIPPacket{
		version:  4,
		protocol: encoded[9],
		source:   netip.AddrFrom4([4]byte(encoded[12:16])),
		target:   netip.AddrFrom4([4]byte(encoded[16:20])),
	}
	if !packet.source.IsValid() || !packet.target.IsValid() {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv4 address is invalid")
	}
	return parsePacketAdapterTransport(packet, encoded[headerLength:], false)
}

func parsePacketAdapterIPv4Fragment(encoded []byte, maximum int) (packetAdapterIPv4Fragment, bool, error) {
	if len(encoded) == 0 || encoded[0]>>4 != 4 {
		return packetAdapterIPv4Fragment{}, false, nil
	}
	if len(encoded) > maximum || len(encoded) < 20 || encoded[0]&0x0f < 5 {
		return packetAdapterIPv4Fragment{}, false, fmt.Errorf("client: packet adapter IPv4 header is malformed")
	}
	headerLength := int(encoded[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(encoded[2:4]))
	if headerLength > len(encoded) || totalLength != len(encoded) || totalLength < headerLength || packetAdapterChecksum(encoded[:headerLength]) != 0 || encoded[8] == 0 {
		return packetAdapterIPv4Fragment{}, false, fmt.Errorf("client: packet adapter IPv4 packet is malformed")
	}
	flagsAndOffset := binary.BigEndian.Uint16(encoded[6:8])
	if flagsAndOffset&0x8000 != 0 {
		return packetAdapterIPv4Fragment{}, false, fmt.Errorf("client: packet adapter IPv4 fragment flags are invalid")
	}
	more := flagsAndOffset&0x2000 != 0
	offset := int(flagsAndOffset&0x1fff) * 8
	if flagsAndOffset&0x4000 != 0 && (more || offset != 0) {
		return packetAdapterIPv4Fragment{}, false, fmt.Errorf("client: packet adapter IPv4 fragment conflicts with Don't Fragment")
	}
	if !more && offset == 0 {
		return packetAdapterIPv4Fragment{}, false, nil
	}
	payload := encoded[headerLength:]
	if len(payload) == 0 || (more && len(payload)%8 != 0) || offset+len(payload) > maximum-20 {
		return packetAdapterIPv4Fragment{}, false, fmt.Errorf("client: packet adapter IPv4 fragment is malformed")
	}
	fragment := packetAdapterIPv4Fragment{
		key: packetAdapterIPv4FragmentKey{
			protocol: encoded[9],
			source:   netip.AddrFrom4([4]byte(encoded[12:16])),
			target:   netip.AddrFrom4([4]byte(encoded[16:20])),
			id:       binary.BigEndian.Uint16(encoded[4:6]),
		},
		payload: payload,
		offset:  offset,
		more:    more,
	}
	if !fragment.key.source.IsValid() || !fragment.key.target.IsValid() {
		return packetAdapterIPv4Fragment{}, false, fmt.Errorf("client: packet adapter IPv4 address is invalid")
	}
	if offset == 0 {
		fragment.header = encoded[:headerLength]
	}
	return fragment, true, nil
}

func (a *PacketAdapter) ingressIPv4FragmentLocked(fragment packetAdapterIPv4Fragment, now time.Time) ([]byte, error) {
	set := a.ipv4Fragments[fragment.key]
	if set == nil {
		fragmentSetLimit := a.maximumFlows
		if fragmentSetLimit > maximumPacketAdapterIPv4FragmentSets {
			fragmentSetLimit = maximumPacketAdapterIPv4FragmentSets
		}
		if len(a.ipv4Fragments) >= fragmentSetLimit {
			return nil, fmt.Errorf("client: packet adapter IPv4 fragment set limit reached")
		}
		set = &packetAdapterIPv4FragmentSet{
			totalPayloadLength: -1,
			expiresAt:          now.Add(defaultPacketAdapterIPv4FragmentLifetime),
		}
		a.ipv4Fragments[fragment.key] = set
	}
	end := fragment.offset + len(fragment.payload)
	if set.totalPayloadLength >= 0 && end > set.totalPayloadLength {
		a.discardIPv4FragmentSetLocked(fragment.key, set)
		return nil, fmt.Errorf("client: packet adapter IPv4 fragment exceeds final length")
	}
	if !fragment.more {
		if set.totalPayloadLength >= 0 && set.totalPayloadLength != end {
			a.discardIPv4FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv4 fragments have inconsistent final length")
		}
		for _, existing := range set.segments {
			if existing.offset+len(existing.payload) > end {
				a.discardIPv4FragmentSetLocked(fragment.key, set)
				return nil, fmt.Errorf("client: packet adapter IPv4 fragment exceeds final length")
			}
		}
		if set.header != nil && len(set.header)+end > a.maximumPacket {
			a.discardIPv4FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv4 reassembled packet exceeds limit")
		}
		set.totalPayloadLength = end
	}
	if len(set.segments) >= maximumPacketAdapterIPv4Fragments || set.payloadBytes+len(fragment.payload) > a.maximumPacket-20 {
		a.discardIPv4FragmentSetLocked(fragment.key, set)
		return nil, fmt.Errorf("client: packet adapter IPv4 fragment set exceeds limits")
	}
	for _, existing := range set.segments {
		if fragment.offset < existing.offset+len(existing.payload) && existing.offset < end {
			a.discardIPv4FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv4 fragments overlap")
		}
	}
	if fragment.offset == 0 {
		set.header = append([]byte(nil), fragment.header...)
		if set.totalPayloadLength >= 0 && len(set.header)+set.totalPayloadLength > a.maximumPacket {
			a.discardIPv4FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv4 reassembled packet exceeds limit")
		}
	}
	set.segments = append(set.segments, packetAdapterIPv4FragmentSegment{
		offset:  fragment.offset,
		payload: append([]byte(nil), fragment.payload...),
	})
	set.payloadBytes += len(fragment.payload)
	if set.header == nil || set.totalPayloadLength < 0 {
		return nil, nil
	}
	sort.Slice(set.segments, func(i, j int) bool { return set.segments[i].offset < set.segments[j].offset })
	nextOffset := 0
	for _, segment := range set.segments {
		if segment.offset != nextOffset {
			return nil, nil
		}
		nextOffset += len(segment.payload)
	}
	if nextOffset != set.totalPayloadLength || len(set.header)+nextOffset > a.maximumPacket {
		return nil, nil
	}
	reassembled := make([]byte, len(set.header)+nextOffset)
	copy(reassembled, set.header)
	binary.BigEndian.PutUint16(reassembled[2:4], uint16(len(reassembled)))
	binary.BigEndian.PutUint16(reassembled[6:8], binary.BigEndian.Uint16(reassembled[6:8])&0x4000)
	binary.BigEndian.PutUint16(reassembled[10:12], 0)
	binary.BigEndian.PutUint16(reassembled[10:12], packetAdapterChecksum(reassembled[:len(set.header)]))
	for _, segment := range set.segments {
		copy(reassembled[len(set.header)+segment.offset:], segment.payload)
	}
	a.discardIPv4FragmentSetLocked(fragment.key, set)
	return reassembled, nil
}

func (a *PacketAdapter) expireIPv4FragmentsLocked(now time.Time) {
	for key, set := range a.ipv4Fragments {
		if !now.Before(set.expiresAt) {
			a.discardIPv4FragmentSetLocked(key, set)
		}
	}
}

func (a *PacketAdapter) discardIPv4FragmentSetLocked(key packetAdapterIPv4FragmentKey, set *packetAdapterIPv4FragmentSet) {
	delete(a.ipv4Fragments, key)
	zeroPacketAdapterBytes(set.header)
	for index := range set.segments {
		zeroPacketAdapterBytes(set.segments[index].payload)
	}
	set.header = nil
	set.segments = nil
	set.totalPayloadLength = 0
	set.payloadBytes = 0
}

func parsePacketAdapterIPv6Fragment(encoded []byte, maximum int) (packetAdapterIPv6FragmentPacket, bool, error) {
	if len(encoded) == 0 || encoded[0]>>4 != 6 {
		return packetAdapterIPv6FragmentPacket{}, false, nil
	}
	if len(encoded) > maximum || len(encoded) < 40 || int(binary.BigEndian.Uint16(encoded[4:6])) != len(encoded)-40 || encoded[7] == 0 {
		return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 packet is malformed")
	}
	nextHeader := encoded[6]
	nextHeaderOffset := 6
	offset := 40
	seenDestination := false
	for headerCount := 0; ; headerCount++ {
		switch nextHeader {
		case packetAdapterTCP, packetAdapterUDP:
			return packetAdapterIPv6FragmentPacket{}, false, nil
		case packetAdapterIPv6HopByHop:
			if headerCount != 0 {
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 hop-by-hop header position is invalid")
			}
		case packetAdapterIPv6Destination:
			if seenDestination {
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 destination options are duplicated")
			}
			seenDestination = true
		case packetAdapterIPv6Fragment:
			if headerCount >= maximumPacketAdapterIPv6Options {
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 extension header chain is too long")
			}
			next, payloadOffset, fragmentOffset, more, id, err := parsePacketAdapterIPv6FragmentFields(encoded, offset)
			if err != nil {
				return packetAdapterIPv6FragmentPacket{}, false, err
			}
			if next != packetAdapterTCP && next != packetAdapterUDP && next != packetAdapterIPv6Destination {
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 fragment next header is unsupported")
			}
			if next == packetAdapterIPv6Destination && seenDestination {
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 destination options are duplicated")
			}
			if fragmentOffset == 0 && !more {
				return packetAdapterIPv6FragmentPacket{}, false, nil
			}
			payload := encoded[payloadOffset:]
			if len(payload) == 0 || (more && len(payload)%8 != 0) || fragmentOffset+len(payload) > maximum-40 {
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 fragment is malformed")
			}
			header := append([]byte(nil), encoded[:offset]...)
			binary.BigEndian.PutUint16(header[4:6], 0)
			fragment := packetAdapterIPv6FragmentPacket{
				key: packetAdapterIPv6FragmentKey{
					source: netip.AddrFrom16([16]byte(encoded[8:24])),
					target: netip.AddrFrom16([16]byte(encoded[24:40])),
					id:     id,
				},
				header:                  header,
				nextHeaderOffset:        nextHeaderOffset,
				nextHeaderAfterFragment: next,
				payload:                 payload,
				offset:                  fragmentOffset,
				more:                    more,
			}
			if !fragment.key.source.IsValid() || !fragment.key.target.IsValid() {
				zeroPacketAdapterBytes(header)
				return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 address is invalid")
			}
			return fragment, true, nil
		default:
			return packetAdapterIPv6FragmentPacket{}, false, nil
		}
		if headerCount >= maximumPacketAdapterIPv6Options {
			return packetAdapterIPv6FragmentPacket{}, false, fmt.Errorf("client: packet adapter IPv6 extension header chain is too long")
		}
		var err error
		nextHeaderOffset = offset
		nextHeader, offset, err = parsePacketAdapterIPv6OptionsHeader(encoded, offset)
		if err != nil {
			return packetAdapterIPv6FragmentPacket{}, false, err
		}
	}
}

func (a *PacketAdapter) ingressIPv6FragmentLocked(fragment packetAdapterIPv6FragmentPacket, now time.Time) ([]byte, error) {
	set := a.ipv6Fragments[fragment.key]
	if set == nil {
		fragmentSetLimit := a.maximumFlows
		if fragmentSetLimit > maximumPacketAdapterIPv6FragmentSets {
			fragmentSetLimit = maximumPacketAdapterIPv6FragmentSets
		}
		if len(a.ipv6Fragments) >= fragmentSetLimit {
			zeroPacketAdapterBytes(fragment.header)
			return nil, fmt.Errorf("client: packet adapter IPv6 fragment set limit reached")
		}
		set = &packetAdapterIPv6FragmentSet{
			header:             fragment.header,
			nextHeaderOffset:   fragment.nextHeaderOffset,
			nextHeader:         fragment.nextHeaderAfterFragment,
			totalPayloadLength: -1,
			expiresAt:          now.Add(defaultPacketAdapterIPv6FragmentLifetime),
		}
		a.ipv6Fragments[fragment.key] = set
	} else {
		if !bytes.Equal(set.header, fragment.header) || set.nextHeaderOffset != fragment.nextHeaderOffset || set.nextHeader != fragment.nextHeaderAfterFragment {
			zeroPacketAdapterBytes(fragment.header)
			a.discardIPv6FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv6 fragments have inconsistent headers")
		}
		zeroPacketAdapterBytes(fragment.header)
	}
	end := fragment.offset + len(fragment.payload)
	if set.totalPayloadLength >= 0 && end > set.totalPayloadLength {
		a.discardIPv6FragmentSetLocked(fragment.key, set)
		return nil, fmt.Errorf("client: packet adapter IPv6 fragment exceeds final length")
	}
	if !fragment.more {
		if set.totalPayloadLength >= 0 && set.totalPayloadLength != end {
			a.discardIPv6FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv6 fragments have inconsistent final length")
		}
		for _, existing := range set.segments {
			if existing.offset+len(existing.payload) > end {
				a.discardIPv6FragmentSetLocked(fragment.key, set)
				return nil, fmt.Errorf("client: packet adapter IPv6 fragment exceeds final length")
			}
		}
		if len(set.header)+end > a.maximumPacket {
			a.discardIPv6FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv6 reassembled packet exceeds limit")
		}
		set.totalPayloadLength = end
	}
	if len(set.segments) >= maximumPacketAdapterIPv6Fragments || set.payloadBytes+len(fragment.payload) > a.maximumPacket-40 {
		a.discardIPv6FragmentSetLocked(fragment.key, set)
		return nil, fmt.Errorf("client: packet adapter IPv6 fragment set exceeds limits")
	}
	for _, existing := range set.segments {
		if fragment.offset < existing.offset+len(existing.payload) && existing.offset < end {
			a.discardIPv6FragmentSetLocked(fragment.key, set)
			return nil, fmt.Errorf("client: packet adapter IPv6 fragments overlap")
		}
	}
	set.segments = append(set.segments, packetAdapterIPv6FragmentSegment{
		offset:  fragment.offset,
		payload: append([]byte(nil), fragment.payload...),
	})
	set.payloadBytes += len(fragment.payload)
	if set.totalPayloadLength < 0 {
		return nil, nil
	}
	sort.Slice(set.segments, func(i, j int) bool { return set.segments[i].offset < set.segments[j].offset })
	nextOffset := 0
	for _, segment := range set.segments {
		if segment.offset != nextOffset {
			return nil, nil
		}
		nextOffset += len(segment.payload)
	}
	if nextOffset != set.totalPayloadLength || len(set.header)+nextOffset > a.maximumPacket {
		return nil, nil
	}
	reassembled := make([]byte, len(set.header)+nextOffset)
	copy(reassembled, set.header)
	binary.BigEndian.PutUint16(reassembled[4:6], uint16(len(reassembled)-40))
	reassembled[set.nextHeaderOffset] = set.nextHeader
	for _, segment := range set.segments {
		copy(reassembled[len(set.header)+segment.offset:], segment.payload)
	}
	a.discardIPv6FragmentSetLocked(fragment.key, set)
	return reassembled, nil
}

func (a *PacketAdapter) expireIPv6FragmentsLocked(now time.Time) {
	for key, set := range a.ipv6Fragments {
		if !now.Before(set.expiresAt) {
			a.discardIPv6FragmentSetLocked(key, set)
		}
	}
}

func (a *PacketAdapter) discardIPv6FragmentSetLocked(key packetAdapterIPv6FragmentKey, set *packetAdapterIPv6FragmentSet) {
	delete(a.ipv6Fragments, key)
	zeroPacketAdapterBytes(set.header)
	for index := range set.segments {
		zeroPacketAdapterBytes(set.segments[index].payload)
	}
	set.header = nil
	set.segments = nil
	set.totalPayloadLength = 0
	set.payloadBytes = 0
}

func parsePacketAdapterIPv6(encoded []byte) (packetAdapterIPPacket, error) {
	if len(encoded) < 40 || int(binary.BigEndian.Uint16(encoded[4:6])) != len(encoded)-40 || encoded[7] == 0 {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv6 packet is malformed")
	}
	protocol, segmentOffset, err := parsePacketAdapterIPv6Headers(encoded)
	if err != nil {
		return packetAdapterIPPacket{}, err
	}
	packet := packetAdapterIPPacket{
		version:  6,
		protocol: protocol,
		source:   netip.AddrFrom16([16]byte(encoded[8:24])),
		target:   netip.AddrFrom16([16]byte(encoded[24:40])),
	}
	if !packet.source.IsValid() || !packet.target.IsValid() {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv6 address is invalid")
	}
	return parsePacketAdapterTransport(packet, encoded[segmentOffset:], true)
}

func parsePacketAdapterIPv6Headers(encoded []byte) (uint8, int, error) {
	nextHeader := encoded[6]
	offset := 40
	seenDestination := false
	seenFragment := false
	for headerCount := 0; ; headerCount++ {
		switch nextHeader {
		case packetAdapterTCP, packetAdapterUDP:
			return nextHeader, offset, nil
		case packetAdapterIPv6HopByHop:
			if headerCount != 0 {
				return 0, 0, fmt.Errorf("client: packet adapter IPv6 hop-by-hop header position is invalid")
			}
		case packetAdapterIPv6Destination:
			if seenDestination {
				return 0, 0, fmt.Errorf("client: packet adapter IPv6 destination options are duplicated")
			}
			seenDestination = true
		case packetAdapterIPv6Fragment:
			if seenFragment {
				return 0, 0, fmt.Errorf("client: packet adapter IPv6 fragment header is duplicated")
			}
			seenFragment = true
		default:
			return 0, 0, fmt.Errorf("client: packet adapter IPv6 extension header is unsupported: %w", errPacketAdapterUnsupportedProtocol)
		}
		if headerCount >= maximumPacketAdapterIPv6Options {
			return 0, 0, fmt.Errorf("client: packet adapter IPv6 extension header chain is too long")
		}
		var err error
		if nextHeader == packetAdapterIPv6Fragment {
			nextHeader, offset, err = parsePacketAdapterIPv6FragmentHeader(encoded, offset)
		} else {
			nextHeader, offset, err = parsePacketAdapterIPv6OptionsHeader(encoded, offset)
		}
		if err != nil {
			return 0, 0, err
		}
	}
}

func parsePacketAdapterIPv6FragmentHeader(encoded []byte, offset int) (uint8, int, error) {
	nextHeader, payloadOffset, fragmentOffset, more, _, err := parsePacketAdapterIPv6FragmentFields(encoded, offset)
	if err != nil {
		return 0, 0, err
	}
	if fragmentOffset != 0 || more {
		return 0, 0, fmt.Errorf("client: packet adapter IPv6 fragmented packets are unsupported")
	}
	return nextHeader, payloadOffset, nil
}

func parsePacketAdapterIPv6FragmentFields(encoded []byte, offset int) (uint8, int, int, bool, uint32, error) {
	if offset < 40 || offset+8 > len(encoded) || encoded[offset+1] != 0 {
		return 0, 0, 0, false, 0, fmt.Errorf("client: packet adapter IPv6 fragment header is malformed")
	}
	flags := binary.BigEndian.Uint16(encoded[offset+2 : offset+4])
	if flags&0x0006 != 0 {
		return 0, 0, 0, false, 0, fmt.Errorf("client: packet adapter IPv6 fragment header reserved bits are set")
	}
	return encoded[offset], offset + 8, int(flags & 0xfff8), flags&0x0001 != 0, binary.BigEndian.Uint32(encoded[offset+4 : offset+8]), nil
}

func parsePacketAdapterIPv6OptionsHeader(encoded []byte, offset int) (uint8, int, error) {
	if offset < 40 || offset+2 > len(encoded) {
		return 0, 0, fmt.Errorf("client: packet adapter IPv6 options header is malformed")
	}
	length := (int(encoded[offset+1]) + 1) * 8
	if length > len(encoded)-offset {
		return 0, 0, fmt.Errorf("client: packet adapter IPv6 options header is malformed")
	}
	if err := parsePacketAdapterIPv6Options(encoded[offset+2 : offset+length]); err != nil {
		return 0, 0, err
	}
	return encoded[offset], offset + length, nil
}

func parsePacketAdapterIPv6Options(encoded []byte) error {
	for len(encoded) > 0 {
		if encoded[0] == 0 {
			encoded = encoded[1:]
			continue
		}
		if len(encoded) < 2 || int(encoded[1]) > len(encoded)-2 {
			return fmt.Errorf("client: packet adapter IPv6 option is malformed")
		}
		if encoded[0]>>6 != 0 {
			return fmt.Errorf("client: packet adapter IPv6 option requires unsupported handling: %w", errPacketAdapterUnsupportedProtocol)
		}
		encoded = encoded[2+int(encoded[1]):]
	}
	return nil
}

func parsePacketAdapterTransport(packet packetAdapterIPPacket, segment []byte, requireUDPChecksum bool) (packetAdapterIPPacket, error) {
	switch packet.protocol {
	case packetAdapterTCP:
		if len(segment) < 20 || segment[12]>>4 < 5 || int(segment[12]>>4)*4 > len(segment) || packetAdapterTransportChecksum(packet.version, packet.source, packet.target, packet.protocol, segment) != 0 {
			return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter TCP segment is malformed")
		}
		headerLength := int(segment[12]>>4) * 4
		if segment[12]&0x0e != 0 || binary.BigEndian.Uint16(segment[:2]) == 0 || binary.BigEndian.Uint16(segment[2:4]) == 0 {
			return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter TCP header is invalid")
		}
		packet.tcp = packetAdapterTCPPacket{
			sourcePort:      binary.BigEndian.Uint16(segment[:2]),
			destinationPort: binary.BigEndian.Uint16(segment[2:4]),
			sequence:        binary.BigEndian.Uint32(segment[4:8]),
			acknowledgment:  binary.BigEndian.Uint32(segment[8:12]),
			flags:           segment[13],
			payload:         segment[headerLength:],
		}
		return packet, nil
	case packetAdapterUDP:
		if len(segment) < 8 || int(binary.BigEndian.Uint16(segment[4:6])) != len(segment) || binary.BigEndian.Uint16(segment[:2]) == 0 || binary.BigEndian.Uint16(segment[2:4]) == 0 {
			return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter UDP segment is malformed")
		}
		checksum := binary.BigEndian.Uint16(segment[6:8])
		if (requireUDPChecksum && checksum == 0) || (checksum != 0 && packetAdapterTransportChecksum(packet.version, packet.source, packet.target, packet.protocol, segment) != 0) {
			return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter UDP checksum is invalid")
		}
		packet.udp = packetAdapterUDPPacket{
			sourcePort:      binary.BigEndian.Uint16(segment[:2]),
			destinationPort: binary.BigEndian.Uint16(segment[2:4]),
			payload:         segment[8:],
		}
		return packet, nil
	default:
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter transport protocol is unsupported: %w", errPacketAdapterUnsupportedProtocol)
	}
}

func buildPacketAdapterTCPPacket(version uint8, source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgment uint32, flags uint8, payload []byte, packetID uint16) ([]byte, error) {
	segment := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(segment[:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], targetPort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	binary.BigEndian.PutUint32(segment[8:12], acknowledgment)
	segment[12] = 5 << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], 65535)
	copy(segment[20:], payload)
	binary.BigEndian.PutUint16(segment[16:18], packetAdapterTransportChecksum(version, source, target, packetAdapterTCP, segment))
	return buildPacketAdapterIPPacket(version, source, target, packetAdapterTCP, segment, packetID)
}

func buildPacketAdapterUDPPacket(version uint8, source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, packetID uint16) ([]byte, error) {
	if len(payload) > 65527 {
		return nil, fmt.Errorf("client: packet adapter UDP payload is too large")
	}
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], targetPort)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	copy(segment[8:], payload)
	checksum := packetAdapterTransportChecksum(version, source, target, packetAdapterUDP, segment)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(segment[6:8], checksum)
	return buildPacketAdapterIPPacket(version, source, target, packetAdapterUDP, segment, packetID)
}

func buildPacketAdapterIPPacket(version uint8, source, target netip.Addr, protocol uint8, payload []byte, packetID uint16) ([]byte, error) {
	if !source.IsValid() || !target.IsValid() || source.Is4() != target.Is4() {
		return nil, fmt.Errorf("client: packet adapter IP addresses are invalid")
	}
	switch version {
	case 4:
		if !source.Is4() || len(payload) > 65515 {
			return nil, fmt.Errorf("client: packet adapter IPv4 packet is too large")
		}
		packet := make([]byte, 20+len(payload))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], packetID)
		packet[6] = 0x40
		packet[8] = 64
		packet[9] = protocol
		sourceBytes := source.As4()
		targetBytes := target.As4()
		copy(packet[12:16], sourceBytes[:])
		copy(packet[16:20], targetBytes[:])
		binary.BigEndian.PutUint16(packet[10:12], packetAdapterChecksum(packet[:20]))
		copy(packet[20:], payload)
		return packet, nil
	case 6:
		if !source.Is6() || len(payload) > 65535 {
			return nil, fmt.Errorf("client: packet adapter IPv6 packet is too large")
		}
		packet := make([]byte, 40+len(payload))
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
		packet[6] = protocol
		packet[7] = 64
		sourceBytes := source.As16()
		targetBytes := target.As16()
		copy(packet[8:24], sourceBytes[:])
		copy(packet[24:40], targetBytes[:])
		copy(packet[40:], payload)
		return packet, nil
	default:
		return nil, fmt.Errorf("client: packet adapter IP version is invalid")
	}
}

func packetAdapterTransportChecksum(version uint8, source, target netip.Addr, protocol uint8, segment []byte) uint16 {
	pseudo := make([]byte, 0, 40)
	if version == 4 {
		sourceBytes := source.As4()
		targetBytes := target.As4()
		pseudo = append(pseudo, sourceBytes[:]...)
		pseudo = append(pseudo, targetBytes[:]...)
		pseudo = append(pseudo, 0, protocol)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(segment)))
	} else {
		sourceBytes := source.As16()
		targetBytes := target.As16()
		pseudo = append(pseudo, sourceBytes[:]...)
		pseudo = append(pseudo, targetBytes[:]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(segment)))
		pseudo = append(pseudo, 0, 0, 0, protocol)
	}
	return packetAdapterChecksum(pseudo, segment)
}

func packetAdapterChecksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd byte
	hasOdd := false
	for _, part := range parts {
		for _, value := range part {
			if !hasOdd {
				odd = value
				hasOdd = true
				continue
			}
			sum += uint32(odd)<<8 | uint32(value)
			hasOdd = false
		}
	}
	if hasOdd {
		sum += uint32(odd) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func tcpSequenceBefore(left, right uint32) bool {
	return int32(left-right) < 0
}

// dropPacketAdapterBackpressure maps transient queue backpressure to a dropped
// packet: the kernel retransmits TCP and UDP loss is acceptable, so the session
// must survive instead of the read loop terminating. This matches the native
// ABI, where backpressure maps to a status the mobile clients treat as a drop.
func dropPacketAdapterBackpressure(err error) error {
	if errors.Is(err, session.ErrBackpressure) {
		return nil
	}
	return err
}

func zeroPacketAdapterBlocks(blocks []protocol.FrameBlock) {
	for index := range blocks {
		for frame := range blocks[index].Frames {
			zeroPacketAdapterBytes(blocks[index].Frames[frame].Payload)
		}
	}
}

func zeroPacketAdapterPacketList(packets [][]byte) {
	for _, packet := range packets {
		zeroPacketAdapterBytes(packet)
	}
}

func zeroPacketAdapterBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
