package packet

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

const defaultReceiverWindowSize uint64 = 1024

// MaxReceiverWindowSize bounds the replay window a receiver will honor. Larger
// configured windows are clamped to it, which only makes acceptance stricter.
const MaxReceiverWindowSize uint64 = 1 << 20

var errReceiverDestroyed = errors.New("packet: receiver destroyed")

type ReceiverConfig struct {
	Protector  Protector
	WindowSize uint64
}

type Receiver struct {
	mu                  sync.Mutex
	protector           Protector
	directionProtectors map[receiverPacketNumberSpace]*Protector
	protectorUses       map[*Protector]int
	retiredProtectors   map[*Protector]struct{}
	windowSize          uint64
	windowBits          uint64
	windows             map[receiverPacketNumberSpace]*replayWindow
	destroyed           bool
}

// replayWindow tracks accepted packet numbers in a fixed-size ring bitmap. Bit
// n%windowBits records packet number n, so the ring holds exactly the window
// [highest-windowSize, highest] and needs no per-packet pruning.
type replayWindow struct {
	highest uint64
	bits    []uint64
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
	if windowSize > MaxReceiverWindowSize {
		windowSize = MaxReceiverWindowSize
	}
	protector := cloneProtectorForReceiver(cfg.Protector)
	_ = protector.Prepare()
	return &Receiver{
		protector:           protector,
		directionProtectors: make(map[receiverPacketNumberSpace]*Protector),
		windowSize:          windowSize,
		windowBits:          windowSize + 1,
		windows:             make(map[receiverPacketNumberSpace]*replayWindow),
	}
}

// cloneProtectorForReceiver gives the receiver exclusive ownership of traffic
// material and derived state. A shallow Protector copy would share the
// caller's key slices and sealing scratch, so retiring the receiver could erase
// or race with a protector the caller still uses.
func cloneProtectorForReceiver(source Protector) Protector {
	return Protector{
		Suite:           source.Suite,
		RouteInstanceID: source.RouteInstanceID,
		HopLayer:        source.HopLayer,
		Direction:       source.Direction,
		KeyPhase:        source.KeyPhase,
		Key:             append([]byte(nil), source.Key...),
		StaticIV:        append([]byte(nil), source.StaticIV...),
		NextPacket:      source.NextPacket,
	}
}

// Stats returns an atomic snapshot of replay-window memory use.
func (r *Receiver) Stats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := 0
	for _, window := range r.windows {
		seen += window.count()
	}
	return ReceiverStats{PacketNumberSpaces: len(r.windows), SeenPackets: seen}
}

// Destroy releases replay-window state and retires cached traffic material.
// Material pinned by an in-progress open is zeroed when that open returns.
func (r *Receiver) Destroy() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.destroyed = true
	r.retireProtectorLocked(&r.protector)
	for _, protector := range r.directionProtectors {
		r.retireProtectorLocked(protector)
	}
	r.directionProtectors = nil
	r.windows = nil
}

// ForgetPacketNumberSpace removes replay state and retires cached traffic
// material for an erased key phase.
func (r *Receiver) ForgetPacketNumberSpace(routeInstanceID uint64, hopLayer, direction, keyPhase uint8) {
	space := receiverPacketNumberSpace{
		RouteInstanceID: routeInstanceID,
		HopLayer:        hopLayer,
		Direction:       direction,
		KeyPhase:        keyPhase,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	protector := r.directionProtectors[space]
	delete(r.directionProtectors, space)
	r.retireProtectorLocked(protector)
	delete(r.windows, space)
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
	r.mu.Lock()
	protector, err := r.acquireProtectorLocked(&r.protector)
	r.mu.Unlock()
	if err != nil {
		return PreparedOpen{}, err
	}
	defer r.releaseProtector(protector)
	return r.prepareOpenWithProtector(pkt, protector, false)
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
	defer r.releaseProtector(protector)
	return r.prepareOpenWithProtector(pkt, protector, false)
}

// PrepareOpenOwnedWithDirectionState authenticates a packet buffer that is
// exclusively owned by the caller. The packet payload is consumed and cannot
// be retried after this call.
func (r *Receiver) PrepareOpenOwnedWithDirectionState(pkt AuroraPacket, state *DirectionState, suite uint64, now time.Time) (PreparedOpen, error) {
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
	defer r.releaseProtector(protector)
	return r.prepareOpenWithProtector(pkt, protector, true)
}

func (r *Receiver) prepareOpenWithProtector(pkt AuroraPacket, protector *Protector, owned bool) (PreparedOpen, error) {
	if protector == nil {
		return PreparedOpen{}, fmt.Errorf("packet: missing protector")
	}
	r.mu.Lock()
	if err := r.checkPacketNumberLocked(pkt); err != nil {
		r.mu.Unlock()
		return PreparedOpen{}, err
	}
	r.mu.Unlock()

	var (
		block protocol.FrameBlock
		err   error
	)
	if owned {
		block, err = protector.OpenOwned(pkt)
	} else {
		block, err = protector.Open(pkt)
	}
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
	if r.destroyed {
		return nil, errReceiverDestroyed
	}
	if protector := r.directionProtectors[space]; protector != nil && protector.Suite == suite && protector.RouteInstanceID == state.RouteInstanceID && protector.HopLayer == state.HopLayer && protector.Direction == state.Direction && protector.KeyPhase == pkt.KeyPhase && bytes.Equal(protector.Key, material.Key) && bytes.Equal(protector.StaticIV, material.IV) {
		return r.acquireProtectorLocked(protector)
	}
	previous := r.directionProtectors[space]
	delete(r.directionProtectors, space)
	r.retireProtectorLocked(previous)
	protector, err := NewProtector(suite, state.RouteInstanceID, state.HopLayer, state.Direction, pkt.KeyPhase, material.Key, material.IV)
	if err != nil {
		return nil, err
	}
	if r.directionProtectors == nil {
		r.directionProtectors = make(map[receiverPacketNumberSpace]*Protector)
	}
	r.directionProtectors[space] = &protector
	return r.acquireProtectorLocked(&protector)
}

// acquireProtectorLocked pins traffic material while an authenticated open is
// in progress. r.mu must be held.
func (r *Receiver) acquireProtectorLocked(protector *Protector) (*Protector, error) {
	if r.destroyed {
		return nil, errReceiverDestroyed
	}
	if protector == nil {
		return nil, fmt.Errorf("packet: missing protector")
	}
	if r.protectorUses == nil {
		r.protectorUses = make(map[*Protector]int)
	}
	r.protectorUses[protector]++
	return protector, nil
}

func (r *Receiver) releaseProtector(protector *Protector) {
	if protector == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	uses := r.protectorUses[protector]
	if uses > 1 {
		r.protectorUses[protector] = uses - 1
		return
	}
	delete(r.protectorUses, protector)
	if _, retired := r.retiredProtectors[protector]; retired {
		delete(r.retiredProtectors, protector)
		protector.Destroy()
	}
}

// retireProtectorLocked removes traffic material as soon as no authenticated
// open can still be using it. r.mu must be held.
func (r *Receiver) retireProtectorLocked(protector *Protector) {
	if protector == nil {
		return
	}
	if r.protectorUses[protector] == 0 {
		protector.Destroy()
		return
	}
	if r.retiredProtectors == nil {
		r.retiredProtectors = make(map[*Protector]struct{})
	}
	r.retiredProtectors[protector] = struct{}{}
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
	if r.destroyed {
		return errReceiverDestroyed
	}
	window := r.windows[key.Space]
	if window == nil || key.PacketNumber > window.highest {
		return nil
	}
	distance := window.highest - key.PacketNumber
	if distance > r.windowSize {
		return fmt.Errorf("packet: packet number %d outside receiver window", key.PacketNumber)
	}
	if window.contains(key.PacketNumber, r.windowBits) {
		return fmt.Errorf("packet: duplicate packet number %d", key.PacketNumber)
	}
	return nil
}

func (r *Receiver) markPacketNumberKeyLocked(key receiverPacketNumberKey) {
	if r.windows == nil {
		return
	}
	window := r.windows[key.Space]
	if window == nil {
		window = &replayWindow{
			highest: key.PacketNumber,
			bits:    make([]uint64, (r.windowBits+63)/64),
		}
		window.set(key.PacketNumber, r.windowBits)
		r.windows[key.Space] = window
		return
	}
	if key.PacketNumber > window.highest {
		window.advance(key.PacketNumber, r.windowBits)
	} else if window.highest-key.PacketNumber > r.windowSize {
		return
	}
	window.set(key.PacketNumber, r.windowBits)
}

func (w *replayWindow) contains(packetNumber, windowBits uint64) bool {
	index := packetNumber % windowBits
	return w.bits[index/64]&(1<<(index%64)) != 0
}

func (w *replayWindow) set(packetNumber, windowBits uint64) {
	index := packetNumber % windowBits
	w.bits[index/64] |= 1 << (index % 64)
}

// advance slides the window up to highest, clearing the slots that newly
// entered it. Sequential traffic clears a single bit per packet.
func (w *replayWindow) advance(highest, windowBits uint64) {
	distance := highest - w.highest
	if distance >= windowBits {
		for i := range w.bits {
			w.bits[i] = 0
		}
		w.highest = highest
		return
	}
	for offset := uint64(1); offset <= distance; offset++ {
		index := (w.highest + offset) % windowBits
		w.bits[index/64] &^= 1 << (index % 64)
	}
	w.highest = highest
}

func (w *replayWindow) count() int {
	total := 0
	for _, word := range w.bits {
		total += bits.OnesCount64(word)
	}
	return total
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
