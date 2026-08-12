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

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.terminal != nil {
		return a.terminal
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	nonce := make([]byte, keyUpdateNonceBytes)
	defer zeroBytes(nonce)
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		return fmt.Errorf("session: generate key update nonce: %w", err)
	}
	now := time.Now()
	prepared, err := a.writeState.PrepareUpdate(a.suite, nonce, true, reason, now)
	if err != nil {
		return err
	}
	defer prepared.Destroy()
	frame := prepared.Frame()
	defer zeroBytes(frame.UpdateNonce)
	block, err := keyUpdateFrameBlock(frame)
	if err != nil {
		return err
	}
	defer zeroFrameBlock(block)
	reservation, err := encodedPacketReservation(block)
	if err != nil {
		return err
	}
	if !a.reserveLocked(reservation, true) {
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
	if err := a.enqueueEncodedLocked(encoded, true); err != nil {
		a.write.NextPacket = nextPacket
		return err
	}
	if err := a.writeState.CommitPreparedUpdate(prepared, now); err != nil {
		a.rollbackLastEncodedLocked()
		a.write.NextPacket = nextPacket
		return err
	}
	a.writePacketNumbers[phase] = sealedNext
	a.activateWriteStateLocked()
	a.signalLocked()
	return nil
}

type keyControls struct {
	update *protocol.KeyUpdate
	ack    *protocol.KeyUpdateACK
	frames []protocol.AuroraFrame
}

func (c *keyControls) Destroy() {
	if c.update != nil {
		zeroBytes(c.update.UpdateNonce)
	}
	if c.ack != nil {
		zeroBytes(c.ack.AckNonce)
	}
	*c = keyControls{}
}

func (a *Application) handleKeyControlsLocked(now time.Time, packetKeyPhase uint8, block protocol.FrameBlock, readCandidate *packet.DirectionState) ([]protocol.FrameBlock, error) {
	controls, err := scanKeyControls(block)
	if err != nil {
		return nil, err
	}
	defer controls.Destroy()
	if controls.update != nil && controls.update.OldKeyPhase != packetKeyPhase {
		return nil, fmt.Errorf("session: key update old phase does not match packet phase")
	}
	if controls.ack != nil && packetKeyPhase != readCandidate.KeyPhase {
		return nil, fmt.Errorf("session: key update acknowledgement is not under the current read phase")
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
		if _, err := io.ReadFull(a.random, ackNonce); err != nil {
			return nil, fmt.Errorf("session: generate key update acknowledgement nonce: %w", err)
		}
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
			return nil, fmt.Errorf("session: reserve key update acknowledgement: %w", ErrBackpressure)
		}
		reservationHeld = true
	}

	var updateResult packet.KeyUpdateResult
	haveUpdateResult := false
	if controls.update != nil {
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

	if controls.update != nil && controls.update.AckRequired {
		if updateResult.ACK == nil {
			return nil, fmt.Errorf("session: key update omitted required acknowledgement")
		}
		ackBlock, err := keyUpdateACKFrameBlock(*updateResult.ACK)
		if err != nil {
			return nil, err
		}
		defer zeroFrameBlock(ackBlock)
		encoded, phase, nextPacket, sealedNext, err := a.sealCurrentWriteBlockLocked(ackBlock)
		if err != nil {
			return nil, err
		}
		if len(encoded) > reservation {
			a.write.NextPacket = nextPacket
			return nil, fmt.Errorf("session: encoded key update acknowledgement exceeds reservation")
		}
		a.releaseReservationLocked(reservation)
		reservationHeld = false
		if err := a.enqueueEncodedLocked(encoded, true); err != nil {
			a.write.NextPacket = nextPacket
			return nil, err
		}
		a.writePacketNumbers[phase] = sealedNext
		a.signalLocked()
	}

	if haveWriteCandidate {
		previous := a.writeState
		a.writeState = writeCandidate
		haveWriteCandidate = false
		previous.Destroy()
	}
	if len(controls.frames) == 0 {
		return nil, nil
	}
	return []protocol.FrameBlock{{Frames: controls.frames}}, nil
}

func scanKeyControls(block protocol.FrameBlock) (keyControls, error) {
	controls := keyControls{frames: make([]protocol.AuroraFrame, 0, len(block.Frames))}
	for _, frame := range block.Frames {
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
		case registry.FrameKeyUpdateRequest:
			// Update requests are optional and are consumed after protocol validation.
		default:
			controls.frames = append(controls.frames, cloneFrame(frame))
		}
	}
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
}

func cloneFrame(frame protocol.AuroraFrame) protocol.AuroraFrame {
	return protocol.AuroraFrame{
		FrameType: frame.FrameType,
		FlowID:    frame.FlowID,
		Flags:     frame.Flags,
		Payload:   append([]byte(nil), frame.Payload...),
	}
}

func zeroFrameBlock(block protocol.FrameBlock) {
	for i := range block.Frames {
		zeroBytes(block.Frames[i].Payload)
	}
}
