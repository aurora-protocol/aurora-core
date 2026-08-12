package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
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
	packetAdapterTCP                 = 6
	packetAdapterUDP                 = 17
	packetAdapterDNSPort             = 53
	tcpFlagFIN                       = 0x01
	tcpFlagSYN                       = 0x02
	tcpFlagRST                       = 0x04
	tcpFlagPSH                       = 0x08
	tcpFlagACK                       = 0x10
)

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
	nextFlowID    uint64
	nextPacketID  uint16
	flowsByTuple  map[packetAdapterTuple]*packetAdapterFlow
	flowsByID     map[uint64]*packetAdapterFlow
	localPackets  [][]byte
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
	}, nil
}

// Ingress captures one local packet and queues the corresponding encrypted flow frames.
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
	packet, err := parsePacketAdapterIPPacket(encoded, a.maximumPacket)
	if err != nil {
		return err
	}
	if packet.protocol == packetAdapterUDP && packet.udp.destinationPort == packetAdapterDNSPort {
		return a.ingressDNS(ctx, packet, now)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch packet.protocol {
	case packetAdapterTCP:
		return a.ingressTCPLocked(ctx, packet, now)
	case packetAdapterUDP:
		return a.ingressUDPLocked(ctx, packet, now)
	default:
		return fmt.Errorf("client: unsupported packet protocol %d", packet.protocol)
	}
}

// NextEncryptedPacket waits for one encrypted packet queued by Ingress.
func (a *PacketAdapter) NextEncryptedPacket(ctx context.Context) ([]byte, error) {
	if a == nil || a.application == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	return a.application.NextPacket(ctx)
}

// HandleEncryptedPacket decrypts a relay packet and returns packets for the local tunnel.
func (a *PacketAdapter) HandleEncryptedPacket(ctx context.Context, encoded []byte, now time.Time) ([][]byte, error) {
	if a == nil || a.application == nil {
		return nil, fmt.Errorf("client: packet adapter application is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("client: packet adapter context is nil")
	}
	if now.IsZero() || now.Unix() < 0 {
		return nil, fmt.Errorf("client: packet adapter requires a valid time")
	}
	if len(encoded) == 0 || len(encoded) > a.maximumPacket+64 {
		return nil, fmt.Errorf("client: encrypted packet size is invalid")
	}
	blocks, err := a.application.HandlePacket(ctx, now, encoded)
	if err != nil {
		return nil, err
	}
	defer zeroPacketAdapterBlocks(blocks)
	a.mu.Lock()
	defer a.mu.Unlock()
	var local [][]byte
	for _, block := range blocks {
		for _, frame := range block.Frames {
			packets, err := a.handleRelayFrameLocked(frame, now)
			if err != nil {
				zeroPacketAdapterPacketList(local)
				return nil, err
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
	return len(a.flowsByID)
}

func (a *PacketAdapter) ingressTCPLocked(ctx context.Context, packet packetAdapterIPPacket, now time.Time) error {
	tuple := packetAdapterTuple{
		version: packet.version, protocol: packet.protocol, client: packet.source, target: packet.target,
		clientPort: packet.tcp.sourcePort, targetPort: packet.tcp.destinationPort,
	}
	mapping := a.flowsByTuple[tuple]
	if packet.tcp.flags&tcpFlagSYN != 0 {
		if packet.tcp.flags != tcpFlagSYN || len(packet.tcp.payload) != 0 {
			return fmt.Errorf("client: packet adapter only accepts an initial TCP SYN")
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
		if len(a.flowsByID) >= a.maximumFlows {
			return fmt.Errorf("client: packet adapter flow limit reached")
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
		return fmt.Errorf("client: packet adapter received TCP data for an unknown flow")
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
		if len(a.flowsByID) >= a.maximumFlows {
			return fmt.Errorf("client: packet adapter flow limit reached")
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
		mapping = &packetAdapterFlow{flowID: flowID, tuple: tuple, kind: flow.FlowKindUDPAssociation}
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
	if a.dnsAnswers == nil {
		return fmt.Errorf("client: packet adapter local DNS answers are unavailable")
	}
	answers, err := a.dnsAnswers(ctx, append([]byte(nil), packet.udp.payload...))
	if err != nil {
		return fmt.Errorf("client: packet adapter local DNS answer: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
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

func (a *PacketAdapter) handleRelayFrameLocked(frame protocol.AuroraFrame, now time.Time) ([][]byte, error) {
	switch frame.FrameType {
	case registry.FramePadding:
		return nil, nil
	case registry.FrameUDPTargetConfirm:
		if err := a.proxy.ReceiveUDPTargetConfirmFrameAt(frame, uint64(now.Unix())); err != nil {
			return nil, err
		}
		return nil, nil
	case registry.FrameFlowClose:
		return a.handleRelayCloseLocked(frame, now)
	case registry.FrameStreamData, registry.FrameDatagramData:
		return a.handleRelayDataLocked(frame)
	default:
		return nil, fmt.Errorf("client: packet adapter received unsupported relay frame 0x%x", frame.FrameType)
	}
}

func (a *PacketAdapter) handleRelayDataLocked(frame protocol.AuroraFrame) ([][]byte, error) {
	mapping := a.flowsByID[frame.FlowID]
	if mapping == nil || mapping.peerClosed {
		return nil, fmt.Errorf("client: packet adapter received data for unknown flow")
	}
	switch mapping.kind {
	case flow.FlowKindTCPStream:
		if frame.FrameType != registry.FrameStreamData {
			return nil, fmt.Errorf("client: packet adapter received non-stream TCP data")
		}
		packet, err := a.makeTCPPacketLocked(mapping, mapping.relayNextSequence, mapping.clientNextSequence, tcpFlagACK|tcpFlagPSH, frame.Payload)
		if err != nil {
			return nil, err
		}
		mapping.relayNextSequence += uint32(len(frame.Payload))
		return [][]byte{packet}, nil
	case flow.FlowKindUDPAssociation:
		if frame.FrameType != registry.FrameDatagramData && (frame.FrameType != registry.FrameStreamData || a.udpMode != transport.UDPOverStreamFallback) {
			return nil, fmt.Errorf("client: packet adapter received invalid UDP data frame")
		}
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

func (a *PacketAdapter) handleRelayCloseLocked(frame protocol.AuroraFrame, now time.Time) ([][]byte, error) {
	mapping := a.flowsByID[frame.FlowID]
	if mapping == nil {
		return nil, fmt.Errorf("client: packet adapter received close for unknown flow")
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
			return flowID, nil
		}
	}
	return 0, fmt.Errorf("client: packet adapter flow ID space is exhausted")
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

func parsePacketAdapterIPv6(encoded []byte) (packetAdapterIPPacket, error) {
	if len(encoded) < 40 || int(binary.BigEndian.Uint16(encoded[4:6])) != len(encoded)-40 || encoded[7] == 0 {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv6 packet is malformed")
	}
	packet := packetAdapterIPPacket{
		version:  6,
		protocol: encoded[6],
		source:   netip.AddrFrom16([16]byte(encoded[8:24])),
		target:   netip.AddrFrom16([16]byte(encoded[24:40])),
	}
	if !packet.source.IsValid() || !packet.target.IsValid() {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv6 address is invalid")
	}
	if packet.protocol != packetAdapterTCP && packet.protocol != packetAdapterUDP {
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter IPv6 extension headers are unsupported")
	}
	return parsePacketAdapterTransport(packet, encoded[40:], true)
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
		return packetAdapterIPPacket{}, fmt.Errorf("client: packet adapter transport protocol is unsupported")
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
