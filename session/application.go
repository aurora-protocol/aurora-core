package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

var (
	ErrBackpressure   = errors.New("session: queue backpressure")
	ErrClosed         = errors.New("session: closed")
	ErrNoPacket       = errors.New("session: no packet available")
	ErrSessionControl = errors.New("session: key control requires orchestration")
	errRekeyRequired  = errors.New("session: key update required")
)

const (
	defaultMaxQueuedPackets              = 256
	defaultMaxQueuedBytes                = 4 << 20
	defaultControlReservedPackets        = 2
	defaultControlReservedBytes          = 16 << 10
	defaultReplayWindow                  = 1024
	defaultRekeyMaxAge                   = 30 * time.Minute
	defaultRekeyMaxBytes          uint64 = 8 << 30
	defaultRekeyMaxPackets        uint64 = (1 << 32) - (1 << 16)

	maxQueuedPackets = 4096
	maxQueuedBytes   = 64 << 20
	minReservedBytes = 8 << 10
	minReplayWindow  = 64
	maxReplayWindow  = 1 << 20

	maxPacketEncodingOverhead = 8 + 1 + 1 + 1 + 8 + 3 + 16
	maxPacketCiphertextBytes  = 0xffffff
	maximumHighPriorityBurst  = 4
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
	Rekey           RekeyPolicy
	Entropy         EntropySource
}

type Limits struct {
	MaxQueuedPackets       int
	MaxQueuedBytes         int
	ControlReservedPackets int
	ControlReservedBytes   int
	ReplayWindow           uint64
}

type RekeyPolicy struct {
	MaxAge     time.Duration
	MaxBytes   uint64
	MaxPackets uint64
}

// Stats reports current and lifetime peak outbound queue usage.
type Stats struct {
	QueuedPackets     int
	QueuedBytes       int
	PeakQueuedPackets int
	PeakQueuedBytes   int
}

type Application struct {
	mu            sync.Mutex
	readMu        sync.Mutex
	writeUpdateMu sync.Mutex

	suite           uint64
	routeInstanceID uint64
	hopLayer        uint8
	limits          Limits
	rekey           RekeyPolicy
	entropy         EntropySource
	entropyGate     chan struct{}
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	clock           applicationClock

	write               packet.Protector
	writeState          packet.DirectionState
	readState           packet.DirectionState
	receiver            *packet.Receiver
	writePacketNumbers  [256]uint64
	writePhaseStartedAt time.Time
	writePhaseBytes     uint64

	queue                []queuedPacket
	highPriorityBurst    int
	queuedBytes          int
	reservedPackets      int
	reservedBytes        int
	pendingWriteUpdate   bool
	peakQueuedPackets    int
	peakQueuedBytes      int
	writeDrainStop       func() bool
	readDrainStop        func() bool
	writeDrainGeneration uint64
	readDrainGeneration  uint64
	writeDrainPins       int
	readDrainPins        int

	changed  chan struct{}
	closed   chan struct{}
	terminal error
}

func NewApplication(cfg Config) (*Application, error) {
	return newApplicationWithClock(cfg, systemApplicationClock{})
}

func newApplicationWithClock(cfg Config, clock applicationClock) (*Application, error) {
	if clock == nil {
		return nil, fmt.Errorf("session: nil application clock")
	}
	limits, err := normalizeLimits(cfg.Limits)
	if err != nil {
		return nil, err
	}
	rekey, err := normalizeRekeyPolicy(cfg.Rekey)
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
	write, err := packet.NewProtector(cfg.Suite, cfg.RouteInstanceID, cfg.HopLayer, cfg.Write.Direction, 0, cfg.Write.Key, cfg.Write.IV)
	if err != nil {
		return nil, fmt.Errorf("session: prepare write protector: %w", err)
	}
	entropy, err := normalizeEntropy(cfg.Entropy)
	if err != nil {
		return nil, err
	}
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())

	a := &Application{
		suite:               cfg.Suite,
		routeInstanceID:     cfg.RouteInstanceID,
		hopLayer:            cfg.HopLayer,
		limits:              limits,
		rekey:               rekey,
		entropy:             entropy,
		entropyGate:         make(chan struct{}, 1),
		lifecycleCtx:        lifecycleCtx,
		lifecycleCancel:     lifecycleCancel,
		clock:               clock,
		writePhaseStartedAt: clock.Now(),
		write:               write,
		writeState:          newDirectionState(cfg.RouteInstanceID, cfg.HopLayer, cfg.Write),
		readState:           newDirectionState(cfg.RouteInstanceID, cfg.HopLayer, cfg.Read),
		receiver: packet.NewReceiver(packet.ReceiverConfig{
			WindowSize: limits.ReplayWindow,
		}),
		changed: make(chan struct{}, 1),
		closed:  make(chan struct{}),
	}
	a.entropyGate <- struct{}{}
	return a, nil
}

func (a *Application) QueueFrames(ctx context.Context, block protocol.FrameBlock) error {
	for _, frame := range block.Frames {
		switch frame.FrameType {
		case registry.FrameKeyUpdate, registry.FrameKeyUpdateAck, registry.FrameKeyUpdateRequest:
			return fmt.Errorf("%w: frame type 0x%x", ErrSessionControl, frame.FrameType)
		}
	}
	err := a.queueBlock(ctx, block, false, isHighPriorityFrameBlock(block))
	if errors.Is(err, errRekeyRequired) {
		if err := a.InitiateKeyUpdate(ctx, 0); err != nil && !errors.Is(err, ErrBackpressure) {
			return err
		}
		return ErrBackpressure
	}
	return err
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
		if err := ctx.Err(); err != nil {
			a.mu.Unlock()
			return nil, err
		}
		if len(a.queue) > 0 {
			encoded, err := a.takeNextPacketLocked()
			a.mu.Unlock()
			return encoded, err
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

// TryNextPacket returns one queued encrypted packet without waiting.
func (a *Application) TryNextPacket() ([]byte, error) {
	if a == nil {
		return nil, ErrClosed
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return nil, a.terminal
	}
	if len(a.queue) == 0 {
		return nil, ErrNoPacket
	}
	return a.takeNextPacketLocked()
}

// takeNextPacketLocked transfers ownership of the selected queued packet. a.mu must be held.
func (a *Application) takeNextPacketLocked() ([]byte, error) {
	index := a.nextQueuedPacketIndexLocked()
	queued := a.queue[index]
	if queued.update != nil {
		now := a.clock.Now()
		if err := a.writeState.CommitPreparedUpdate(queued.update.prepared, now); err != nil {
			return nil, a.failLocked(fmt.Errorf("session: commit emitted key update: %w", err))
		}
		if err := a.activateWriteStateLocked(now); err != nil {
			return nil, a.failLocked(fmt.Errorf("session: activate write key state: %w", err))
		}
		a.scheduleWriteDrainLocked()
		a.pendingWriteUpdate = false
	}
	encodedBytes := len(queued.encoded)
	encoded := queued.encoded
	wasHighPriority := queued.highPriority
	wasControl := queued.control
	queued.encoded = nil
	a.queuedBytes -= encodedBytes
	queued.Destroy()
	last := len(a.queue) - 1
	copy(a.queue[index:], a.queue[index+1:])
	a.queue[last] = queuedPacket{}
	a.queue = a.queue[:last]
	if wasHighPriority {
		a.highPriorityBurst++
	} else if !wasControl {
		a.highPriorityBurst = 0
	}
	a.signalLocked()
	return encoded, nil
}

func (a *Application) nextQueuedPacketIndexLocked() int {
	if len(a.queue) == 0 || a.queue[0].control {
		return 0
	}
	highPriority := -1
	normal := -1
	for index := range a.queue {
		queued := a.queue[index]
		if queued.control {
			continue
		}
		if queued.highPriority {
			if highPriority == -1 {
				highPriority = index
			}
			continue
		}
		if normal == -1 {
			normal = index
		}
	}
	if highPriority != -1 && (a.highPriorityBurst < maximumHighPriorityBurst || normal == -1) {
		return highPriority
	}
	if normal != -1 {
		return normal
	}
	return 0
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
	if len(encoded) > a.packetInputLimit() {
		return nil, fmt.Errorf("session: packet exceeds configured limit")
	}
	a.readMu.Lock()
	defer a.readMu.Unlock()
	pkt, err := packet.DecodeAuroraPacketView(encoded)
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
	preparedOpen, err := a.receiver.PrepareOpenWithDirectionState(pkt, &a.readState, a.suite, now)
	if err != nil {
		return nil, err
	}
	defer preparedOpen.Destroy()
	block := preparedOpen.TakeBlock()
	defer func() { zeroFrameBlock(block) }()
	blocks, err := a.handleKeyControlsLocked(ctx, now, pkt.KeyPhase, &block, func() error {
		return a.receiver.CommitPreparedOpen(&preparedOpen)
	})
	if err != nil {
		if isRetryableControlError(err) {
			return nil, err
		}
		return nil, a.failLocked(err)
	}
	a.expireReadDrainLocked(now)
	return blocks, nil
}

func (a *Application) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return nil
	}
	a.terminateLocked(ErrClosed)
	return nil
}

// Done closes when the application becomes terminal.
func (a *Application) Done() <-chan struct{} { return a.closed }

// Err returns the terminal error after Done closes and nil while active.
func (a *Application) Err() error { return a.terminalError() }

// Stats returns an atomic snapshot. Peak values remain available after Close.
func (a *Application) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Stats{
		QueuedPackets:     len(a.queue),
		QueuedBytes:       a.queuedBytes,
		PeakQueuedPackets: a.peakQueuedPackets,
		PeakQueuedBytes:   a.peakQueuedBytes,
	}
}

func (a *Application) terminateLocked(err error) {
	if a.terminal != nil {
		return
	}
	if err == nil {
		err = ErrClosed
	}
	a.terminal = err
	a.lifecycleCancel()
	a.stopDrainTimersLocked()
	for i := range a.queue {
		a.queue[i].Destroy()
	}
	a.queue = nil
	a.queuedBytes = 0
	a.reservedPackets = 0
	a.reservedBytes = 0
	a.pendingWriteUpdate = false
	a.write.Destroy()
	a.receiver.Destroy()
	a.writeState.Destroy()
	a.readState.Destroy()
	a.writePacketNumbers = [256]uint64{}
	a.writePhaseBytes = 0
	a.writePhaseStartedAt = time.Time{}
	a.signalLocked()
	close(a.closed)
}

func (a *Application) failLocked(err error) error {
	if a.terminal == nil {
		a.terminateLocked(err)
	}
	return a.terminal
}

func (a *Application) queueBlock(ctx context.Context, block protocol.FrameBlock, control, highPriority bool) error {
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
	if !control && a.pendingWriteUpdate {
		return ErrBackpressure
	}
	if !control {
		if uint64(reservation) > a.rekey.MaxBytes {
			return fmt.Errorf("session: packet reservation exceeds rekey byte limit")
		}
		if a.needsKeyUpdateLocked(a.clock.Now(), reservation) {
			return errRekeyRequired
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !a.reserveLocked(reservation, control) {
		return ErrBackpressure
	}
	reservationHeld := true
	defer func() {
		if reservationHeld {
			a.releaseReservationLocked(reservation)
		}
	}()

	encoded, phase, nextPacket, sealedNext, err := a.sealCurrentWriteBlockLocked(block)
	if err != nil {
		return err
	}
	defer func() { zeroBytes(encoded) }()
	encodedBytes := len(encoded)
	if len(encoded) > reservation {
		a.write.NextPacket = nextPacket
		return fmt.Errorf("session: encoded packet exceeds reservation")
	}
	if err := ctx.Err(); err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	a.releaseReservationLocked(reservation)
	reservationHeld = false
	if err := a.enqueueEncodedLocked(&encoded, control, highPriority); err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	a.writePacketNumbers[phase] = sealedNext
	a.recordQueuedPacketLocked(encodedBytes)
	a.signalLocked()
	return nil
}

func (a *Application) enqueueEncodedLocked(encoded *[]byte, control, highPriority bool) error {
	if encoded == nil || !a.hasCapacityLocked(len(*encoded), control) {
		return ErrBackpressure
	}
	a.queue = append(a.queue, queuedPacket{encoded: *encoded, control: control, highPriority: highPriority})
	a.queuedBytes += len(*encoded)
	*encoded = nil
	a.recordQueuePeakLocked()
	return nil
}

func (a *Application) enqueueControlBeforeWriteUpdateLocked(encoded *[]byte) error {
	if encoded == nil || !a.hasCapacityLocked(len(*encoded), true) {
		return ErrBackpressure
	}
	index := len(a.queue)
	for i := range a.queue {
		if a.queue[i].update != nil {
			index = i
			break
		}
	}
	a.queue = append(a.queue, queuedPacket{})
	copy(a.queue[index+1:], a.queue[index:])
	a.queue[index] = queuedPacket{encoded: *encoded, control: true}
	a.queuedBytes += len(*encoded)
	*encoded = nil
	a.recordQueuePeakLocked()
	return nil
}

func isHighPriorityFrameBlock(block protocol.FrameBlock) bool {
	if len(block.Frames) == 0 {
		return false
	}
	for _, frame := range block.Frames {
		if frame.FrameType != registry.FrameDNSMessage {
			return false
		}
	}
	return true
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

func (a *Application) recordQueuePeakLocked() {
	if len(a.queue) > a.peakQueuedPackets {
		a.peakQueuedPackets = len(a.queue)
	}
	if a.queuedBytes > a.peakQueuedBytes {
		a.peakQueuedBytes = a.queuedBytes
	}
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

func (a *Application) packetInputLimit() int {
	canonicalLimit := maxPacketCiphertextBytes + maxPacketEncodingOverhead
	if a.limits.MaxQueuedBytes < canonicalLimit {
		return a.limits.MaxQueuedBytes
	}
	return canonicalLimit
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

func normalizeRekeyPolicy(policy RekeyPolicy) (RekeyPolicy, error) {
	if policy == (RekeyPolicy{}) {
		return RekeyPolicy{
			MaxAge:     defaultRekeyMaxAge,
			MaxBytes:   defaultRekeyMaxBytes,
			MaxPackets: defaultRekeyMaxPackets,
		}, nil
	}
	if policy.MaxAge <= 0 || policy.MaxBytes == 0 || policy.MaxPackets == 0 {
		return RekeyPolicy{}, fmt.Errorf("session: rekey policy must specify positive age, byte, and packet limits")
	}
	if policy.MaxPackets > wire.MaxVarint {
		return RekeyPolicy{}, fmt.Errorf("session: rekey packet limit exceeds canonical range")
	}
	return policy, nil
}

func (a *Application) needsKeyUpdateLocked(now time.Time, nextBytes int) bool {
	if !a.writePhaseStartedAt.IsZero() && !now.Before(a.writePhaseStartedAt.Add(a.rekey.MaxAge)) {
		return true
	}
	if a.writePhaseBytes >= a.rekey.MaxBytes || uint64(nextBytes) > a.rekey.MaxBytes-a.writePhaseBytes {
		return true
	}
	return a.writePacketNumbers[a.write.KeyPhase] >= a.rekey.MaxPackets
}

func (a *Application) recordQueuedPacketLocked(encodedBytes int) {
	if encodedBytes <= 0 {
		return
	}
	if uint64(encodedBytes) > ^uint64(0)-a.writePhaseBytes {
		a.writePhaseBytes = ^uint64(0)
		return
	}
	a.writePhaseBytes += uint64(encodedBytes)
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

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
