package packet

import (
	"bytes"
	"fmt"
	"time"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

const MaxDrainWindow = 10 * time.Second

type KeyMaterial struct {
	AppSecret []byte
	Key       []byte
	IV        []byte
}

type KeyUpdateResult struct {
	Next KeyMaterial
	ACK  *protocol.KeyUpdateACK
}

func DeriveKeyUpdate(suite uint64, currentAppSecret []byte, frame protocol.KeyUpdate) (KeyMaterial, error) {
	if frame.NewKeyPhase != frame.OldKeyPhase+1 {
		return KeyMaterial{}, fmt.Errorf("packet: skipped key phase %d -> %d", frame.OldKeyPhase, frame.NewKeyPhase)
	}
	context, err := KeyUpdateContext(frame)
	if err != nil {
		return KeyMaterial{}, err
	}
	hashLen, err := auroracrypto.SuiteHashLength(suite)
	if err != nil {
		return KeyMaterial{}, err
	}
	nextSecret, err := auroracrypto.HKDFExpandLabelForSuite(suite, currentAppSecret, "traffic upd", context, hashLen)
	if err != nil {
		return KeyMaterial{}, err
	}
	keyLen, err := auroracrypto.AEADKeyLength(suite)
	if err != nil {
		return KeyMaterial{}, err
	}
	key, err := auroracrypto.HKDFExpandLabelForSuite(suite, nextSecret, "key", nil, keyLen)
	if err != nil {
		return KeyMaterial{}, err
	}
	iv, err := auroracrypto.HKDFExpandLabelForSuite(suite, nextSecret, "iv", nil, 12)
	if err != nil {
		return KeyMaterial{}, err
	}
	return KeyMaterial{AppSecret: nextSecret, Key: key, IV: iv}, nil
}

func ApplyReceivedKeyUpdate(suite uint64, currentReadSecret []byte, frame protocol.KeyUpdate, ackNonce []byte) (KeyUpdateResult, error) {
	next, err := DeriveKeyUpdate(suite, currentReadSecret, frame)
	if err != nil {
		return KeyUpdateResult{}, err
	}
	var ack *protocol.KeyUpdateACK
	if frame.AckRequired {
		if len(ackNonce) != 16 {
			return KeyUpdateResult{}, fmt.Errorf("packet: KEY_UPDATE_ACK nonce length %d, want 16", len(ackNonce))
		}
		ack = &protocol.KeyUpdateACK{
			RouteInstanceID: frame.RouteInstanceID,
			HopLayer:        frame.HopLayer,
			AckedDirection:  frame.Direction,
			AckedKeyPhase:   frame.NewKeyPhase,
			AckNonce:        append([]byte(nil), ackNonce...),
		}
	}
	return KeyUpdateResult{Next: next, ACK: ack}, nil
}

func KeyUpdateContext(frame protocol.KeyUpdate) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 key update"))
	e.WriteVarint(frame.RouteInstanceID)
	e.WriteUint8(frame.HopLayer)
	e.WriteUint8(frame.Direction)
	e.WriteUint8(frame.OldKeyPhase)
	e.WriteUint8(frame.NewKeyPhase)
	e.WriteOpaque16(frame.UpdateNonce)
	return e.Bytes()
}

type DirectionState struct {
	RouteInstanceID uint64
	HopLayer        uint8
	Direction       uint8
	KeyPhase        uint8
	Material        KeyMaterial
	DrainUntil      time.Time

	lastReceivedUpdate       []byte
	lastReceivedUpdateResult KeyUpdateResult
}

func (s *DirectionState) InitiateUpdate(suite uint64, updateNonce []byte, ackRequired bool, reason uint64) (protocol.KeyUpdate, error) {
	frame := protocol.KeyUpdate{
		RouteInstanceID: s.RouteInstanceID,
		HopLayer:        s.HopLayer,
		Direction:       s.Direction,
		OldKeyPhase:     s.KeyPhase,
		NewKeyPhase:     s.KeyPhase + 1,
		UpdateNonce:     append([]byte(nil), updateNonce...),
		AckRequired:     ackRequired,
		UpdateReason:    reason,
	}
	next, err := DeriveKeyUpdate(suite, s.Material.AppSecret, frame)
	if err != nil {
		return protocol.KeyUpdate{}, err
	}
	s.KeyPhase = frame.NewKeyPhase
	s.Material = next
	s.DrainUntil = time.Now().Add(MaxDrainWindow)
	s.clearLastReceivedUpdate()
	return frame, nil
}

func (s *DirectionState) ApplyReceivedUpdate(suite uint64, frame protocol.KeyUpdate, ackNonce []byte) (KeyUpdateResult, error) {
	if frame.RouteInstanceID != s.RouteInstanceID {
		return KeyUpdateResult{}, fmt.Errorf("packet: KEY_UPDATE route instance mismatch")
	}
	if frame.HopLayer != s.HopLayer {
		return KeyUpdateResult{}, fmt.Errorf("packet: KEY_UPDATE hop layer mismatch")
	}
	if frame.Direction != s.Direction {
		return KeyUpdateResult{}, fmt.Errorf("packet: KEY_UPDATE direction mismatch")
	}
	encodedFrame, err := protocol.Encode(frame)
	if err != nil {
		return KeyUpdateResult{}, err
	}
	if frame.OldKeyPhase != s.KeyPhase {
		if s.isDuplicateReceivedUpdate(frame, encodedFrame, time.Now()) {
			return cloneKeyUpdateResult(s.lastReceivedUpdateResult), nil
		}
		return KeyUpdateResult{}, fmt.Errorf("packet: KEY_UPDATE old phase %d does not match active phase %d", frame.OldKeyPhase, s.KeyPhase)
	}
	res, err := ApplyReceivedKeyUpdate(suite, s.Material.AppSecret, frame, ackNonce)
	if err != nil {
		return KeyUpdateResult{}, err
	}
	s.KeyPhase = frame.NewKeyPhase
	s.Material = res.Next
	s.DrainUntil = time.Now().Add(MaxDrainWindow)
	s.lastReceivedUpdate = append(s.lastReceivedUpdate[:0], encodedFrame...)
	s.lastReceivedUpdateResult = cloneKeyUpdateResult(res)
	return res, nil
}

func (s *DirectionState) isDuplicateReceivedUpdate(frame protocol.KeyUpdate, encodedFrame []byte, now time.Time) bool {
	if len(s.lastReceivedUpdate) == 0 || s.DrainUntil.IsZero() || now.After(s.DrainUntil) {
		return false
	}
	if frame.NewKeyPhase != s.KeyPhase {
		return false
	}
	return bytes.Equal(s.lastReceivedUpdate, encodedFrame)
}

func (s *DirectionState) clearLastReceivedUpdate() {
	s.lastReceivedUpdate = nil
	s.lastReceivedUpdateResult = KeyUpdateResult{}
}

func cloneKeyUpdateResult(in KeyUpdateResult) KeyUpdateResult {
	out := KeyUpdateResult{
		Next: KeyMaterial{
			AppSecret: append([]byte(nil), in.Next.AppSecret...),
			Key:       append([]byte(nil), in.Next.Key...),
			IV:        append([]byte(nil), in.Next.IV...),
		},
	}
	if in.ACK != nil {
		ack := *in.ACK
		ack.AckNonce = append([]byte(nil), in.ACK.AckNonce...)
		out.ACK = &ack
	}
	return out
}
