package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

var (
	ErrBackpressure = errors.New("session: queue backpressure")
	ErrClosed       = errors.New("session: closed")
)

const (
	defaultMaxQueuedPackets       = 256
	defaultMaxQueuedBytes         = 4 << 20
	defaultControlReservedPackets = 2
	defaultControlReservedBytes   = 16 << 10
	defaultReplayWindow           = 1024

	maxQueuedPackets = 4096
	maxQueuedBytes   = 64 << 20
	minReservedBytes = 8 << 10
	minReplayWindow  = 64
	maxReplayWindow  = 1 << 20

	maxPacketEncodingOverhead = 8 + 1 + 1 + 1 + 8 + 3 + 16
	maxPacketCiphertextBytes  = 0xffffff
)

type DirectionConfig struct {
	Direction uint8
	Secret    []byte
	Key       []byte
	IV        []byte
}

type Config struct {
	Suite           uint64
	RouteInstanceID uint64
	HopLayer        uint8
	Write           DirectionConfig
	Read            DirectionConfig
	Limits          Limits
	Random          io.Reader
}

type Limits struct {
	MaxQueuedPackets       int
	MaxQueuedBytes         int
	ControlReservedPackets int
	ControlReservedBytes   int
	ReplayWindow           uint64
}

type Application struct {
	mu sync.Mutex

	suite           uint64
	routeInstanceID uint64
	hopLayer        uint8
	limits          Limits
	random          io.Reader

	write              packet.Protector
	writeState         packet.DirectionState
	readState          packet.DirectionState
	receiver           *packet.Receiver
	writePacketNumbers [256]uint64

	queue           [][]byte
	queuedBytes     int
	reservedPackets int
	reservedBytes   int

	changed  chan struct{}
	closed   chan struct{}
	terminal error
}

func NewApplication(cfg Config) (*Application, error) {
	limits, err := normalizeLimits(cfg.Limits)
	if err != nil {
		return nil, err
	}
	if cfg.RouteInstanceID > wire.MaxVarint {
		return nil, fmt.Errorf("session: route instance ID exceeds canonical range")
	}
	secretLength, err := auroracrypto.SuiteHashLength(cfg.Suite)
	if err != nil {
		return nil, err
	}
	keyLength, err := auroracrypto.AEADKeyLength(cfg.Suite)
	if err != nil {
		return nil, err
	}
	if err := validateDirectionConfig("write", cfg.Write, secretLength, keyLength); err != nil {
		return nil, err
	}
	if err := validateDirectionConfig("read", cfg.Read, secretLength, keyLength); err != nil {
		return nil, err
	}
	if cfg.Write.Direction == cfg.Read.Direction {
		return nil, fmt.Errorf("session: write and read directions must differ")
	}
	randomSource, err := normalizeRandom(cfg.Random)
	if err != nil {
		return nil, err
	}

	writeMaterial := cloneDirectionConfig(cfg.Write)
	readMaterial := cloneDirectionConfig(cfg.Read)
	a := &Application{
		suite:           cfg.Suite,
		routeInstanceID: cfg.RouteInstanceID,
		hopLayer:        cfg.HopLayer,
		limits:          limits,
		random:          randomSource,
		write: packet.Protector{
			Suite:           cfg.Suite,
			RouteInstanceID: cfg.RouteInstanceID,
			HopLayer:        cfg.HopLayer,
			Direction:       writeMaterial.Direction,
			Key:             append([]byte(nil), writeMaterial.Key...),
			StaticIV:        append([]byte(nil), writeMaterial.IV...),
		},
		writeState: newDirectionState(cfg.RouteInstanceID, cfg.HopLayer, writeMaterial),
		readState:  newDirectionState(cfg.RouteInstanceID, cfg.HopLayer, readMaterial),
		receiver: packet.NewReceiver(packet.ReceiverConfig{
			WindowSize: limits.ReplayWindow,
		}),
		changed: make(chan struct{}, 1),
		closed:  make(chan struct{}),
	}
	return a, nil
}

func (a *Application) QueueFrames(ctx context.Context, block protocol.FrameBlock) error {
	return a.queueBlock(ctx, block, false)
}

func (a *Application) NextPacket(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("session: nil context")
	}
	for {
		a.mu.Lock()
		if a.terminal != nil {
			err := a.terminal
			a.mu.Unlock()
			return nil, err
		}
		if len(a.queue) > 0 {
			encoded := a.queue[0]
			a.queue[0] = nil
			a.queue = a.queue[1:]
			a.queuedBytes -= len(encoded)
			a.signalLocked()
			a.mu.Unlock()
			return append([]byte(nil), encoded...), nil
		}
		changed := a.changed
		closed := a.closed
		a.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-closed:
			a.mu.Lock()
			err := a.terminal
			a.mu.Unlock()
			return nil, err
		case <-changed:
		}
	}
}

func (a *Application) HandlePacket(ctx context.Context, now time.Time, encoded []byte) ([]protocol.FrameBlock, error) {
	if ctx == nil {
		return nil, fmt.Errorf("session: nil context")
	}
	if err := a.terminalError(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("session: empty packet")
	}
	if len(encoded) > a.limits.MaxQueuedBytes {
		return nil, fmt.Errorf("session: packet exceeds configured limit")
	}
	pkt, err := packet.DecodeAuroraPacket(encoded)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return nil, a.terminal
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	block, err := a.receiver.OpenWithDirectionState(pkt, &a.readState, a.suite, now)
	if err != nil {
		return nil, err
	}
	return []protocol.FrameBlock{cloneFrameBlock(block)}, nil
}

func (a *Application) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return nil
	}
	a.terminal = ErrClosed
	for i, encoded := range a.queue {
		zeroBytes(encoded)
		a.queue[i] = nil
	}
	a.queue = nil
	a.queuedBytes = 0
	a.reservedPackets = 0
	a.reservedBytes = 0
	zeroBytes(a.write.Key)
	zeroBytes(a.write.StaticIV)
	zeroDirectionState(&a.writeState)
	zeroDirectionState(&a.readState)
	a.signalLocked()
	close(a.closed)
	return nil
}

func (a *Application) queueBlock(ctx context.Context, block protocol.FrameBlock, control bool) error {
	if ctx == nil {
		return fmt.Errorf("session: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := protocol.ValidateFrameBlockForDirection(block, a.write.Direction); err != nil {
		return err
	}
	reservation, err := encodedPacketReservation(block)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return a.terminal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !a.reserveLocked(reservation, control) {
		return ErrBackpressure
	}
	defer a.releaseReservationLocked(reservation)

	owned := cloneFrameBlock(block)
	phase := a.write.KeyPhase
	nextPacket := a.writePacketNumbers[phase]
	if nextPacket > wire.MaxVarint {
		return fmt.Errorf("session: packet number exceeds canonical range")
	}
	a.write.NextPacket = nextPacket
	pkt, err := a.write.Seal(owned)
	if err != nil {
		return err
	}
	encoded, err := protocol.Encode(pkt)
	if err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	if len(encoded) > reservation {
		a.write.NextPacket = nextPacket
		return fmt.Errorf("session: encoded packet exceeds reservation")
	}
	a.releaseReservationLocked(reservation)
	if err := a.enqueueEncodedLocked(encoded, control); err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	a.writePacketNumbers[phase] = a.write.NextPacket
	a.signalLocked()
	return nil
}

func (a *Application) enqueueEncodedLocked(encoded []byte, control bool) error {
	if !a.hasCapacityLocked(len(encoded), control) {
		return ErrBackpressure
	}
	a.queue = append(a.queue, append([]byte(nil), encoded...))
	a.queuedBytes += len(encoded)
	return nil
}

func (a *Application) reserveLocked(bytes int, control bool) bool {
	if !a.hasCapacityLocked(bytes, control) {
		return false
	}
	a.reservedPackets++
	a.reservedBytes += bytes
	return true
}

func (a *Application) releaseReservationLocked(bytes int) {
	if a.reservedPackets == 0 {
		return
	}
	a.reservedPackets--
	a.reservedBytes -= bytes
}

func (a *Application) hasCapacityLocked(bytes int, control bool) bool {
	packetLimit := a.limits.MaxQueuedPackets
	byteLimit := a.limits.MaxQueuedBytes
	if !control {
		packetLimit -= a.limits.ControlReservedPackets
		byteLimit -= a.limits.ControlReservedBytes
	}
	if a.queuedPacketsLocked() >= packetLimit-a.reservedPackets {
		return false
	}
	return bytes <= byteLimit-a.queuedBytes-a.reservedBytes
}

func (a *Application) queuedPacketsLocked() int {
	return len(a.queue)
}

func (a *Application) signalLocked() {
	select {
	case a.changed <- struct{}{}:
	default:
	}
}

func (a *Application) terminalError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.terminal
}

func normalizeLimits(limits Limits) (Limits, error) {
	if limits == (Limits{}) {
		return Limits{
			MaxQueuedPackets:       defaultMaxQueuedPackets,
			MaxQueuedBytes:         defaultMaxQueuedBytes,
			ControlReservedPackets: defaultControlReservedPackets,
			ControlReservedBytes:   defaultControlReservedBytes,
			ReplayWindow:           defaultReplayWindow,
		}, nil
	}
	if limits.MaxQueuedPackets == 0 || limits.MaxQueuedBytes == 0 || limits.ControlReservedPackets == 0 || limits.ControlReservedBytes == 0 || limits.ReplayWindow == 0 {
		return Limits{}, fmt.Errorf("session: nonzero limits must specify every field")
	}
	if limits.MaxQueuedPackets < 0 || limits.MaxQueuedPackets > maxQueuedPackets {
		return Limits{}, fmt.Errorf("session: invalid maximum queued packets")
	}
	if limits.MaxQueuedBytes < 0 || limits.MaxQueuedBytes > maxQueuedBytes {
		return Limits{}, fmt.Errorf("session: invalid maximum queued bytes")
	}
	if limits.ControlReservedPackets < defaultControlReservedPackets || limits.ControlReservedPackets >= limits.MaxQueuedPackets {
		return Limits{}, fmt.Errorf("session: invalid control packet reservation")
	}
	if limits.ControlReservedBytes < minReservedBytes || limits.ControlReservedBytes >= limits.MaxQueuedBytes {
		return Limits{}, fmt.Errorf("session: invalid control byte reservation")
	}
	if limits.ReplayWindow < minReplayWindow || limits.ReplayWindow > maxReplayWindow {
		return Limits{}, fmt.Errorf("session: invalid replay window")
	}
	return limits, nil
}

func validateDirectionConfig(label string, cfg DirectionConfig, secretLength, keyLength int) error {
	if cfg.Direction > 1 {
		return fmt.Errorf("session: %s direction %d is reserved", label, cfg.Direction)
	}
	if len(cfg.Secret) != secretLength {
		return fmt.Errorf("session: %s secret length %d, want %d", label, len(cfg.Secret), secretLength)
	}
	if len(cfg.Key) != keyLength {
		return fmt.Errorf("session: %s key length %d, want %d", label, len(cfg.Key), keyLength)
	}
	if len(cfg.IV) != 12 {
		return fmt.Errorf("session: %s IV length %d, want 12", label, len(cfg.IV))
	}
	return nil
}

func normalizeRandom(randomSource io.Reader) (io.Reader, error) {
	if randomSource == nil {
		return rand.Reader, nil
	}
	value := reflect.ValueOf(randomSource)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, fmt.Errorf("session: nil random reader")
		}
	}
	return randomSource, nil
}

func newDirectionState(routeInstanceID uint64, hopLayer uint8, cfg DirectionConfig) packet.DirectionState {
	return packet.DirectionState{
		RouteInstanceID: routeInstanceID,
		HopLayer:        hopLayer,
		Direction:       cfg.Direction,
		Material: packet.KeyMaterial{
			AppSecret: append([]byte(nil), cfg.Secret...),
			Key:       append([]byte(nil), cfg.Key...),
			IV:        append([]byte(nil), cfg.IV...),
		},
	}
}

func encodedPacketReservation(block protocol.FrameBlock) (int, error) {
	plainLength, err := encodedFrameBlockLength(block)
	if err != nil {
		return 0, err
	}
	if plainLength > maxPacketCiphertextBytes {
		return 0, fmt.Errorf("session: packet plaintext exceeds canonical limit")
	}
	return checkedLengthAdd(plainLength, maxPacketEncodingOverhead)
}

func encodedFrameBlockLength(block protocol.FrameBlock) (int, error) {
	countLength, err := wire.VarintLen(uint64(len(block.Frames)))
	if err != nil {
		return 0, err
	}
	total := countLength
	for _, frame := range block.Frames {
		if len(frame.Payload) > maxPacketCiphertextBytes {
			return 0, fmt.Errorf("session: frame payload exceeds canonical limit")
		}
		for _, value := range []uint64{frame.FrameType, frame.FlowID, frame.Flags} {
			length, err := wire.VarintLen(value)
			if err != nil {
				return 0, err
			}
			total, err = checkedLengthAdd(total, length)
			if err != nil {
				return 0, err
			}
		}
		frameLength, err := checkedLengthAdd(3, len(frame.Payload))
		if err != nil {
			return 0, err
		}
		total, err = checkedLengthAdd(total, frameLength)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func checkedLengthAdd(current, additional int) (int, error) {
	if additional < 0 || current > int(^uint(0)>>1)-additional {
		return 0, fmt.Errorf("session: encoded packet length overflow")
	}
	return current + additional, nil
}

func cloneDirectionConfig(cfg DirectionConfig) DirectionConfig {
	return DirectionConfig{
		Direction: cfg.Direction,
		Secret:    append([]byte(nil), cfg.Secret...),
		Key:       append([]byte(nil), cfg.Key...),
		IV:        append([]byte(nil), cfg.IV...),
	}
}

func cloneFrameBlock(block protocol.FrameBlock) protocol.FrameBlock {
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

func zeroDirectionState(state *packet.DirectionState) {
	zeroBytes(state.Material.AppSecret)
	zeroBytes(state.Material.Key)
	zeroBytes(state.Material.IV)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
