package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const keyUpdateNonceBytes = 16

type queuedPacket struct {
	encoded []byte
	update  *queuedWriteUpdate
}

func (p *queuedPacket) Destroy() {
	if p == nil {
		return
	}
	zeroBytes(p.encoded)
	if p.update != nil {
		p.update.prepared.Destroy()
		*p.update = queuedWriteUpdate{}
	}
	*p = queuedPacket{}
}

type queuedWriteUpdate struct {
	prepared packet.PreparedKeyUpdate
}

func (a *Application) InitiateKeyUpdate(ctx context.Context, reason uint64) error {
	if ctx == nil {
		return fmt.Errorf("session: nil context")
	}
	if reason > wire.MaxVarint {
		return fmt.Errorf("session: key update reason exceeds canonical range")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.writeUpdateMu.Lock()
	defer a.writeUpdateMu.Unlock()

	a.mu.Lock()
	if a.terminal != nil {
		err := a.terminal
		a.mu.Unlock()
		return err
	}
	if a.pendingWriteUpdate {
		a.mu.Unlock()
		return ErrBackpressure
	}
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return err
	}
	reservation, err := keyUpdateReservation(a.writeState, reason)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if !a.reserveLocked(reservation, true) {
		a.mu.Unlock()
		return ErrBackpressure
	}
	a.mu.Unlock()

	nonce, randomErr := a.readNonce()
	defer zeroBytes(nonce)

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return a.terminal
	}
	reservationHeld := true
	defer func() {
		if reservationHeld {
			a.releaseReservationLocked(reservation)
		}
	}()
	if randomErr != nil {
		return fmt.Errorf("session: generate key update nonce: %w", randomErr)
	}
	if a.pendingWriteUpdate {
		return ErrBackpressure
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	prepared, err := a.writeState.PrepareUpdate(a.suite, nonce, true, reason, now)
	if err != nil {
		return err
	}
	preparedOwned := true
	defer func() {
		if preparedOwned {
			prepared.Destroy()
		}
	}()
	frame := prepared.Frame()
	defer zeroBytes(frame.UpdateNonce)
	block, err := keyUpdateFrameBlock(frame)
	if err != nil {
		return err
	}
	defer zeroFrameBlock(block)
	actualReservation, err := encodedPacketReservation(block)
	if err != nil {
		return err
	}
	if actualReservation != reservation {
		return fmt.Errorf("session: key update reservation changed during preparation")
	}

	encoded, phase, nextPacket, sealedNext, err := a.sealCurrentWriteBlockLocked(block)
	if err != nil {
		return err
	}
	defer func() { zeroBytes(encoded) }()
	encodedBytes := len(encoded)
	if len(encoded) > reservation {
		a.write.NextPacket = nextPacket
		return fmt.Errorf("session: encoded key update exceeds reservation")
	}
	if err := ctx.Err(); err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	a.releaseReservationLocked(reservation)
	reservationHeld = false
	if err := a.enqueueWriteUpdateLocked(&encoded, &prepared); err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	preparedOwned = false
	a.writePacketNumbers[phase] = sealedNext
	a.recordQueuedPacketLocked(encodedBytes)
	a.pendingWriteUpdate = true
	a.signalLocked()
	return nil
}

func (a *Application) enqueueWriteUpdateLocked(encoded *[]byte, prepared *packet.PreparedKeyUpdate) error {
	if encoded == nil || !a.hasCapacityLocked(len(*encoded), true) {
		return ErrBackpressure
	}
	update := &queuedWriteUpdate{prepared: *prepared}
	*prepared = packet.PreparedKeyUpdate{}
	a.queue = append(a.queue, queuedPacket{
		encoded: *encoded,
		update:  update,
	})
	a.queuedBytes += len(*encoded)
	*encoded = nil
	a.recordQueuePeakLocked()
	return nil
}

type keyControls struct {
	update *protocol.KeyUpdate
	ack    *protocol.KeyUpdateACK
	frames []protocol.AuroraFrame
}

type retryableControlError struct{ err error }

func (e retryableControlError) Error() string { return e.err.Error() }
func (e retryableControlError) Unwrap() error { return e.err }

func isRetryableControlError(err error) bool {
	_, ok := err.(retryableControlError)
	return ok
}

func (c *keyControls) Destroy() {
	if c.update != nil {
		zeroBytes(c.update.UpdateNonce)
	}
	if c.ack != nil {
		zeroBytes(c.ack.AckNonce)
	}
	for i := range c.frames {
		zeroBytes(c.frames[i].Payload)
		c.frames[i] = protocol.AuroraFrame{}
	}
	*c = keyControls{}
}

func (a *Application) handleKeyControlsLocked(now time.Time, packetKeyPhase uint8, block *protocol.FrameBlock, commitReplay func() error) ([]protocol.FrameBlock, error) {
	controls, err := scanKeyControls(block)
	if err != nil {
		return nil, err
	}
	defer controls.Destroy()
	if controls.update != nil && controls.update.OldKeyPhase != packetKeyPhase {
		return nil, fmt.Errorf("session: key update old phase does not match packet phase")
	}
	if controls.ack != nil && packetKeyPhase != a.readState.KeyPhase {
		return nil, fmt.Errorf("session: key update acknowledgement is not under the current read phase")
	}

	var reservation int
	reservationHeld := false
	defer func() {
		if reservationHeld {
			a.releaseReservationLocked(reservation)
		}
	}()
	var ackNonce []byte
	defer zeroBytes(ackNonce)
	if controls.update != nil && controls.update.AckRequired {
		ackNonce = make([]byte, keyUpdateNonceBytes)
		prospective := protocol.KeyUpdateACK{
			RouteInstanceID: controls.update.RouteInstanceID,
			HopLayer:        controls.update.HopLayer,
			AckedDirection:  controls.update.Direction,
			AckedKeyPhase:   controls.update.NewKeyPhase,
			AckNonce:        ackNonce,
		}
		ackBlock, err := keyUpdateACKFrameBlock(prospective)
		if err != nil {
			return nil, err
		}
		reservation, err = encodedPacketReservation(ackBlock)
		zeroFrameBlock(ackBlock)
		if err != nil {
			return nil, err
		}
		if !a.reserveLocked(reservation, true) {
			return nil, retryableControlError{err: fmt.Errorf("session: reserve key update acknowledgement: %w", ErrBackpressure)}
		}
		reservationHeld = true
		a.mu.Unlock()
		generatedNonce, randomErr := a.readNonce()
		a.mu.Lock()
		if a.terminal != nil {
			reservationHeld = false
			zeroBytes(generatedNonce)
			return nil, a.terminal
		}
		if randomErr != nil {
			zeroBytes(generatedNonce)
			return nil, retryableControlError{err: fmt.Errorf("session: generate key update acknowledgement nonce: %w", randomErr)}
		}
		copy(ackNonce, generatedNonce)
		zeroBytes(generatedNonce)
	}

	var writeCandidate packet.DirectionState
	haveWriteCandidate := false
	if controls.ack != nil {
		writeCandidate = a.writeState.Clone()
		haveWriteCandidate = true
		defer func() {
			if haveWriteCandidate {
				writeCandidate.Destroy()
			}
		}()
		if err := writeCandidate.ApplyKeyUpdateACK(*controls.ack, now); err != nil {
			return nil, fmt.Errorf("session: apply key update acknowledgement: %w", err)
		}
	}

	var updateResult packet.KeyUpdateResult
	haveUpdateResult := false
	var readCandidate packet.DirectionState
	haveReadCandidate := false
	if controls.update != nil {
		readCandidate = a.readState.Clone()
		haveReadCandidate = true
		defer func() {
			if haveReadCandidate {
				readCandidate.Destroy()
			}
		}()
		updateResult, err = readCandidate.ApplyReceivedUpdateAt(a.suite, *controls.update, ackNonce, now)
		if err != nil {
			return nil, fmt.Errorf("session: apply received key update: %w", err)
		}
		haveUpdateResult = true
		defer func() {
			if haveUpdateResult {
				updateResult.Destroy()
			}
		}()
	}

	var ackEncoded []byte
	defer func() { zeroBytes(ackEncoded) }()
	var ackPhase uint8
	var ackNextPacket uint64
	var ackSealedNext uint64
	if controls.update != nil && controls.update.AckRequired {
		if updateResult.ACK == nil {
			return nil, fmt.Errorf("session: key update omitted required acknowledgement")
		}
		ackBlock, err := keyUpdateACKFrameBlock(*updateResult.ACK)
		if err != nil {
			return nil, err
		}
		defer zeroFrameBlock(ackBlock)
		ackEncoded, ackPhase, ackNextPacket, ackSealedNext, err = a.sealCurrentWriteBlockLocked(ackBlock)
		if err != nil {
			return nil, err
		}
		if len(ackEncoded) > reservation {
			a.write.NextPacket = ackNextPacket
			return nil, fmt.Errorf("session: encoded key update acknowledgement exceeds reservation")
		}
	}
	if err := commitReplay(); err != nil {
		if ackEncoded != nil {
			a.write.NextPacket = ackNextPacket
		}
		return nil, err
	}
	if ackEncoded != nil {
		ackEncodedBytes := len(ackEncoded)
		a.releaseReservationLocked(reservation)
		reservationHeld = false
		if err := a.enqueueControlBeforeWriteUpdateLocked(&ackEncoded); err != nil {
			a.write.NextPacket = ackNextPacket
			return nil, err
		}
		a.writePacketNumbers[ackPhase] = ackSealedNext
		a.recordQueuedPacketLocked(ackEncodedBytes)
		a.signalLocked()
	}

	if haveWriteCandidate {
		previous := a.writeState
		a.writeState = writeCandidate
		haveWriteCandidate = false
		previous.Destroy()
	}
	if haveReadCandidate {
		previous := a.readState
		a.readState = readCandidate
		haveReadCandidate = false
		previous.Destroy()
	}
	if len(controls.frames) == 0 {
		return nil, nil
	}
	frames := controls.frames
	controls.frames = nil
	return []protocol.FrameBlock{{Frames: frames}}, nil
}

func scanKeyControls(block *protocol.FrameBlock) (keyControls, error) {
	if block == nil {
		return keyControls{}, fmt.Errorf("session: missing frame block")
	}
	frames := block.Frames
	controls := keyControls{frames: frames[:0]}
	for _, frame := range frames {
		switch frame.FrameType {
		case registry.FrameKeyUpdate:
			if controls.update != nil {
				controls.Destroy()
				return keyControls{}, fmt.Errorf("session: multiple key updates in one packet")
			}
			update, err := decodeKeyUpdate(frame.Payload)
			if err != nil {
				controls.Destroy()
				return keyControls{}, err
			}
			controls.update = &update
			zeroBytes(frame.Payload)
		case registry.FrameKeyUpdateAck:
			if controls.ack != nil {
				controls.Destroy()
				return keyControls{}, fmt.Errorf("session: multiple key update acknowledgements in one packet")
			}
			ack, err := decodeKeyUpdateACK(frame.Payload)
			if err != nil {
				controls.Destroy()
				return keyControls{}, err
			}
			controls.ack = &ack
			zeroBytes(frame.Payload)
		case registry.FrameKeyUpdateRequest:
			// Update requests are optional and are consumed after protocol validation.
			zeroBytes(frame.Payload)
		default:
			controls.frames = append(controls.frames, frame)
		}
	}
	for i := len(controls.frames); i < len(frames); i++ {
		frames[i] = protocol.AuroraFrame{}
	}
	block.Frames = nil
	return controls, nil
}

func decodeKeyUpdate(payload []byte) (protocol.KeyUpdate, error) {
	r := wire.NewReader(payload)
	update := protocol.DecodeKeyUpdate(r)
	if r.Err() != nil {
		return protocol.KeyUpdate{}, r.Err()
	}
	if !r.EOF() {
		return protocol.KeyUpdate{}, fmt.Errorf("session: trailing key update payload bytes")
	}
	return update, nil
}

func decodeKeyUpdateACK(payload []byte) (protocol.KeyUpdateACK, error) {
	r := wire.NewReader(payload)
	ack := protocol.DecodeKeyUpdateACK(r)
	if r.Err() != nil {
		return protocol.KeyUpdateACK{}, r.Err()
	}
	if !r.EOF() {
		return protocol.KeyUpdateACK{}, fmt.Errorf("session: trailing key update acknowledgement payload bytes")
	}
	return ack, nil
}

func keyUpdateFrameBlock(update protocol.KeyUpdate) (protocol.FrameBlock, error) {
	payload, err := protocol.Encode(update)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameKeyUpdate,
		Payload:   payload,
	}}}, nil
}

func keyUpdateReservation(state packet.DirectionState, reason uint64) (int, error) {
	if state.KeyPhase == 255 {
		return 0, fmt.Errorf("packet: KEY_UPDATE key phase exhausted")
	}
	block, err := keyUpdateFrameBlock(protocol.KeyUpdate{
		RouteInstanceID: state.RouteInstanceID,
		HopLayer:        state.HopLayer,
		Direction:       state.Direction,
		OldKeyPhase:     state.KeyPhase,
		NewKeyPhase:     state.KeyPhase + 1,
		UpdateNonce:     make([]byte, keyUpdateNonceBytes),
		AckRequired:     true,
		UpdateReason:    reason,
	})
	if err != nil {
		return 0, err
	}
	defer zeroFrameBlock(block)
	return encodedPacketReservation(block)
}

func keyUpdateACKFrameBlock(ack protocol.KeyUpdateACK) (protocol.FrameBlock, error) {
	payload, err := protocol.Encode(ack)
	if err != nil {
		return protocol.FrameBlock{}, err
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameKeyUpdateAck,
		Payload:   payload,
	}}}, nil
}

func (a *Application) sealCurrentWriteBlockLocked(block protocol.FrameBlock) ([]byte, uint8, uint64, uint64, error) {
	if err := a.validateWriteProtectorLocked(); err != nil {
		return nil, 0, 0, 0, err
	}
	phase := a.write.KeyPhase
	nextPacket := a.writePacketNumbers[phase]
	if nextPacket > wire.MaxVarint {
		return nil, 0, 0, 0, fmt.Errorf("session: packet number exceeds canonical range")
	}
	a.write.NextPacket = nextPacket
	pkt, err := a.write.Seal(block)
	if err != nil {
		a.write.NextPacket = nextPacket
		return nil, 0, 0, 0, err
	}
	sealedNext := a.write.NextPacket
	encoded, err := protocol.Encode(pkt)
	if err != nil {
		a.write.NextPacket = nextPacket
		return nil, 0, 0, 0, err
	}
	return encoded, phase, nextPacket, sealedNext, nil
}

func (a *Application) validateWriteProtectorLocked() error {
	if a.write.RouteInstanceID != a.writeState.RouteInstanceID || a.write.HopLayer != a.writeState.HopLayer || a.write.Direction != a.writeState.Direction || a.write.KeyPhase != a.writeState.KeyPhase {
		return fmt.Errorf("session: write protector metadata is inconsistent with key state")
	}
	if !bytes.Equal(a.write.Key, a.writeState.Material.Key) || !bytes.Equal(a.write.StaticIV, a.writeState.Material.IV) {
		return fmt.Errorf("session: write protector material is inconsistent with key state")
	}
	return nil
}

func (a *Application) activateWriteStateLocked() {
	key := append([]byte(nil), a.writeState.Material.Key...)
	iv := append([]byte(nil), a.writeState.Material.IV...)
	zeroBytes(a.write.Key)
	zeroBytes(a.write.StaticIV)
	a.write.KeyPhase = a.writeState.KeyPhase
	a.write.Key = key
	a.write.StaticIV = iv
	a.write.NextPacket = a.writePacketNumbers[a.write.KeyPhase]
	a.writePhaseBytes = 0
	a.writePhaseStartedAt = time.Now()
}

func (a *Application) readNonce() ([]byte, error) {
	a.randomMu.Lock()
	defer a.randomMu.Unlock()
	nonce := make([]byte, keyUpdateNonceBytes)
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		zeroBytes(nonce)
		return nil, err
	}
	return nonce, nil
}

func zeroFrameBlock(block protocol.FrameBlock) {
	for i := range block.Frames {
		zeroBytes(block.Frames[i].Payload)
	}
}
