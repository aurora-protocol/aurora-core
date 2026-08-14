package packet

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

const defaultReceiverWindowSize uint64 = 1024

type ReceiverConfig struct {
	Protector  Protector
	WindowSize uint64
}

type Receiver struct {
	mu                  sync.Mutex
	protector           Protector
	directionProtectors map[receiverPacketNumberSpace]*Protector
	windowSize          uint64
	seen                map[receiverPacketNumberKey]struct{}
	highest             map[receiverPacketNumberSpace]uint64
	havePacket          map[receiverPacketNumberSpace]bool
}

// ReceiverStats reports replay-window memory use.
type ReceiverStats struct {
	PacketNumberSpaces int
	SeenPackets        int
}

type PreparedOpen struct {
	owner *Receiver
	key   receiverPacketNumberKey
	block protocol.FrameBlock
	valid bool
}

// Block returns an owned copy of the authenticated frame block.
func (p *PreparedOpen) Block() protocol.FrameBlock {
	if p == nil || !p.valid {
		return protocol.FrameBlock{}
	}
	return cloneReceiverFrameBlock(p.block)
}

// TakeBlock transfers ownership of the authenticated frame block to the caller.
func (p *PreparedOpen) TakeBlock() protocol.FrameBlock {
	if p == nil || !p.valid {
		return protocol.FrameBlock{}
	}
	block := p.block
	p.block = protocol.FrameBlock{}
	return block
}

// Destroy zeroes and releases authenticated plaintext owned by the preparation.
func (p *PreparedOpen) Destroy() {
	if p == nil {
		return
	}
	destroyFrameBlock(&p.block)
	*p = PreparedOpen{}
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
	protector := cfg.Protector
	_ = protector.Prepare()
	return &Receiver{
		protector:           protector,
		directionProtectors: make(map[receiverPacketNumberSpace]*Protector),
		windowSize:          windowSize,
		seen:                make(map[receiverPacketNumberKey]struct{}),
		highest:             make(map[receiverPacketNumberSpace]uint64),
		havePacket:          make(map[receiverPacketNumberSpace]bool),
	}
}

// Stats returns an atomic snapshot of replay-window memory use.
func (r *Receiver) Stats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ReceiverStats{PacketNumberSpaces: len(r.havePacket), SeenPackets: len(r.seen)}
}

// Destroy releases cached traffic material and replay-window state.
func (r *Receiver) Destroy() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.protector.Destroy()
	for _, protector := range r.directionProtectors {
		protector.Destroy()
	}
	r.directionProtectors = nil
	r.seen = nil
	r.highest = nil
	r.havePacket = nil
}

// ForgetPacketNumberSpace removes replay state for an erased key phase.
func (r *Receiver) ForgetPacketNumberSpace(routeInstanceID uint64, hopLayer, direction, keyPhase uint8) {
	space := receiverPacketNumberSpace{
		RouteInstanceID: routeInstanceID,
		HopLayer:        hopLayer,
		Direction:       direction,
		KeyPhase:        keyPhase,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// An in-flight open can retain a protector after this cache eviction.
	delete(r.directionProtectors, space)
	delete(r.highest, space)
	delete(r.havePacket, space)
	for key := range r.seen {
		if key.Space == space {
			delete(r.seen, key)
		}
	}
}

func (r *Receiver) Open(pkt AuroraPacket) (protocol.FrameBlock, error) {
	prepared, err := r.PrepareOpen(pkt)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	defer prepared.Destroy()
	block := prepared.TakeBlock()
	if err := r.CommitPreparedOpen(&prepared); err != nil {
		destroyFrameBlock(&block)
		return protocol.FrameBlock{}, err
	}
	return block, nil
}

func (r *Receiver) OpenWithDirectionState(pkt AuroraPacket, state *DirectionState, suite uint64, now time.Time) (protocol.FrameBlock, error) {
	previousPhase, drainDeadline, hadDrain := state.DrainInfo()
	prepared, err := r.PrepareOpenWithDirectionState(pkt, state, suite, now)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	defer prepared.Destroy()
	block := prepared.TakeBlock()
	if err := r.CommitPreparedOpen(&prepared); err != nil {
		destroyFrameBlock(&block)
		return protocol.FrameBlock{}, err
	}
	state.ExpireDrainAt(now)
	if hadDrain && now.After(drainDeadline) && state.DrainUntil.IsZero() {
		r.ForgetPacketNumberSpace(state.RouteInstanceID, state.HopLayer, state.Direction, previousPhase)
	}
	return block, nil
}

func (r *Receiver) PrepareOpen(pkt AuroraPacket) (PreparedOpen, error) {
	return r.prepareOpenWithProtector(pkt, &r.protector)
}

// PrepareOpenWithDirectionState authenticates synchronously without retaining
// or mutating state material. The caller must keep state unchanged until return.
func (r *Receiver) PrepareOpenWithDirectionState(pkt AuroraPacket, state *DirectionState, suite uint64, now time.Time) (PreparedOpen, error) {
	if state == nil {
		return PreparedOpen{}, fmt.Errorf("packet: missing direction state")
	}
	material, err := state.materialForPacketView(pkt, now)
	if err != nil {
		return PreparedOpen{}, err
	}
	protector, err := r.directionProtector(pkt, state, suite, material)
	if err != nil {
		return PreparedOpen{}, err
	}
	return r.prepareOpenWithProtector(pkt, protector)
}

func (r *Receiver) prepareOpenWithProtector(pkt AuroraPacket, protector *Protector) (PreparedOpen, error) {
	if protector == nil {
		return PreparedOpen{}, fmt.Errorf("packet: missing protector")
	}
	r.mu.Lock()
	if err := r.checkPacketNumberLocked(pkt); err != nil {
		r.mu.Unlock()
		return PreparedOpen{}, err
	}
	r.mu.Unlock()

	block, err := protector.Open(pkt)
	if err != nil {
		return PreparedOpen{}, err
	}

	r.mu.Lock()
	if err := r.checkPacketNumberLocked(pkt); err != nil {
		r.mu.Unlock()
		destroyFrameBlock(&block)
		return PreparedOpen{}, err
	}
	r.mu.Unlock()
	return PreparedOpen{
		owner: r,
		key:   receiverPacketNumberKey{Space: packetNumberSpace(pkt), PacketNumber: pkt.PacketNumber},
		block: block,
		valid: true,
	}, nil
}

func (r *Receiver) directionProtector(pkt AuroraPacket, state *DirectionState, suite uint64, material KeyMaterial) (*Protector, error) {
	space := packetNumberSpace(pkt)
	r.mu.Lock()
	defer r.mu.Unlock()
	if protector := r.directionProtectors[space]; protector != nil && protector.Suite == suite && protector.RouteInstanceID == state.RouteInstanceID && protector.HopLayer == state.HopLayer && protector.Direction == state.Direction && protector.KeyPhase == pkt.KeyPhase && bytes.Equal(protector.Key, material.Key) && bytes.Equal(protector.StaticIV, material.IV) {
		return protector, nil
	}
	protector, err := NewProtector(suite, state.RouteInstanceID, state.HopLayer, state.Direction, pkt.KeyPhase, material.Key, material.IV)
	if err != nil {
		return nil, err
	}
	r.directionProtectors[space] = &protector
	return &protector, nil
}

func (r *Receiver) CommitPreparedOpen(prepared *PreparedOpen) error {
	if prepared == nil || !prepared.valid || prepared.owner != r {
		return fmt.Errorf("packet: invalid prepared packet open")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkPacketNumberKeyLocked(prepared.key); err != nil {
		return err
	}
	r.markPacketNumberKeyLocked(prepared.key)
	prepared.valid = false
	return nil
}

func (r *Receiver) checkPacketNumberLocked(pkt AuroraPacket) error {
	return r.checkPacketNumberKeyLocked(receiverPacketNumberKey{Space: packetNumberSpace(pkt), PacketNumber: pkt.PacketNumber})
}

func (r *Receiver) checkPacketNumberKeyLocked(key receiverPacketNumberKey) error {
	if _, ok := r.seen[key]; ok {
		return fmt.Errorf("packet: duplicate packet number %d", key.PacketNumber)
	}
	highest := r.highest[key.Space]
	if r.havePacket[key.Space] && highest >= r.windowSize && key.PacketNumber < highest-r.windowSize {
		return fmt.Errorf("packet: packet number %d outside receiver window", key.PacketNumber)
	}
	return nil
}

func (r *Receiver) markPacketNumberKeyLocked(key receiverPacketNumberKey) {
	space := key.Space
	r.seen[key] = struct{}{}
	if !r.havePacket[space] || key.PacketNumber > r.highest[space] {
		r.highest[space] = key.PacketNumber
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

func cloneReceiverFrameBlock(block protocol.FrameBlock) protocol.FrameBlock {
	cloned := protocol.FrameBlock{Frames: make([]protocol.AuroraFrame, len(block.Frames))}
	for i, frame := range block.Frames {
		cloned.Frames[i] = protocol.AuroraFrame{
			FrameType: frame.FrameType,
			FlowID:    frame.FlowID,
			Flags:     frame.Flags,
			Payload:   append([]byte(nil), frame.Payload...),
		}
	}
	return cloned
}

func destroyFrameBlock(block *protocol.FrameBlock) {
	for i := range block.Frames {
		for j := range block.Frames[i].Payload {
			block.Frames[i].Payload[j] = 0
		}
		block.Frames[i] = protocol.AuroraFrame{}
	}
	*block = protocol.FrameBlock{}
}

func packetNumberSpace(pkt AuroraPacket) receiverPacketNumberSpace {
	return receiverPacketNumberSpace{
		RouteInstanceID: pkt.RouteInstanceID,
		HopLayer:        pkt.HopLayer,
		Direction:       pkt.Direction,
		KeyPhase:        pkt.KeyPhase,
	}
}
