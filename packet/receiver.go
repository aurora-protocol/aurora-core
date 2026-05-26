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
	seen       map[uint64]struct{}
	highest    uint64
	havePacket bool
}

func NewReceiver(cfg ReceiverConfig) *Receiver {
	windowSize := cfg.WindowSize
	if windowSize == 0 {
		windowSize = defaultReceiverWindowSize
	}
	return &Receiver{
		protector:  cfg.Protector,
		windowSize: windowSize,
		seen:       make(map[uint64]struct{}),
	}
}

func (r *Receiver) Open(pkt AuroraPacket) (protocol.FrameBlock, error) {
	r.mu.Lock()
	if err := r.checkPacketNumberLocked(pkt.PacketNumber); err != nil {
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
	if err := r.checkPacketNumberLocked(pkt.PacketNumber); err != nil {
		return protocol.FrameBlock{}, err
	}
	r.markPacketNumberLocked(pkt.PacketNumber)
	return block, nil
}

func (r *Receiver) checkPacketNumberLocked(packetNumber uint64) error {
	if _, ok := r.seen[packetNumber]; ok {
		return fmt.Errorf("packet: duplicate packet number %d", packetNumber)
	}
	if r.havePacket && r.highest >= r.windowSize && packetNumber < r.highest-r.windowSize {
		return fmt.Errorf("packet: packet number %d outside receiver window", packetNumber)
	}
	return nil
}

func (r *Receiver) markPacketNumberLocked(packetNumber uint64) {
	r.seen[packetNumber] = struct{}{}
	if !r.havePacket || packetNumber > r.highest {
		r.highest = packetNumber
		r.havePacket = true
	}
	if !r.havePacket || r.highest < r.windowSize {
		return
	}
	cutoff := r.highest - r.windowSize
	for seen := range r.seen {
		if seen < cutoff {
			delete(r.seen, seen)
		}
	}
}
