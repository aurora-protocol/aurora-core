package packet

import (
	"fmt"
	"sync"

	"github.com/aurora-protocol/aurora-core/protocol"
)

const defaultReceiverWindowSize uint64 = 1024

type ReceiverConfig struct {
	Protector  Protector
	WindowSize uint64
}

type Receiver struct {
	mu         sync.Mutex
	protector  Protector
	windowSize uint64
	seen       map[receiverPacketNumberKey]struct{}
	highest    map[receiverPacketNumberSpace]uint64
	havePacket map[receiverPacketNumberSpace]bool
}

type receiverPacketNumberSpace struct {
	RouteInstanceID uint64
	HopLayer        uint8
	Direction       uint8
	KeyPhase        uint8
}

type receiverPacketNumberKey struct {
	Space        receiverPacketNumberSpace
	PacketNumber uint64
}

func NewReceiver(cfg ReceiverConfig) *Receiver {
	windowSize := cfg.WindowSize
	if windowSize == 0 {
		windowSize = defaultReceiverWindowSize
	}
	return &Receiver{
		protector:  cfg.Protector,
		windowSize: windowSize,
		seen:       make(map[receiverPacketNumberKey]struct{}),
		highest:    make(map[receiverPacketNumberSpace]uint64),
		havePacket: make(map[receiverPacketNumberSpace]bool),
	}
}

func (r *Receiver) Open(pkt AuroraPacket) (protocol.FrameBlock, error) {
	r.mu.Lock()
	if err := r.checkPacketNumberLocked(pkt); err != nil {
		r.mu.Unlock()
		return protocol.FrameBlock{}, err
	}
	r.mu.Unlock()

	block, err := r.protector.Open(pkt)
	if err != nil {
		return protocol.FrameBlock{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkPacketNumberLocked(pkt); err != nil {
		return protocol.FrameBlock{}, err
	}
	r.markPacketNumberLocked(pkt)
	return block, nil
}

func (r *Receiver) checkPacketNumberLocked(pkt AuroraPacket) error {
	space := packetNumberSpace(pkt)
	key := receiverPacketNumberKey{Space: space, PacketNumber: pkt.PacketNumber}
	if _, ok := r.seen[key]; ok {
		return fmt.Errorf("packet: duplicate packet number %d", pkt.PacketNumber)
	}
	highest := r.highest[space]
	if r.havePacket[space] && highest >= r.windowSize && pkt.PacketNumber < highest-r.windowSize {
		return fmt.Errorf("packet: packet number %d outside receiver window", pkt.PacketNumber)
	}
	return nil
}

func (r *Receiver) markPacketNumberLocked(pkt AuroraPacket) {
	space := packetNumberSpace(pkt)
	key := receiverPacketNumberKey{Space: space, PacketNumber: pkt.PacketNumber}
	r.seen[key] = struct{}{}
	if !r.havePacket[space] || pkt.PacketNumber > r.highest[space] {
		r.highest[space] = pkt.PacketNumber
		r.havePacket[space] = true
	}
	if !r.havePacket[space] || r.highest[space] < r.windowSize {
		return
	}
	cutoff := r.highest[space] - r.windowSize
	for seen := range r.seen {
		if seen.Space == space && seen.PacketNumber < cutoff {
			delete(r.seen, seen)
		}
	}
}

func packetNumberSpace(pkt AuroraPacket) receiverPacketNumberSpace {
	return receiverPacketNumberSpace{
		RouteInstanceID: pkt.RouteInstanceID,
		HopLayer:        pkt.HopLayer,
		Direction:       pkt.Direction,
		KeyPhase:        pkt.KeyPhase,
	}
}
