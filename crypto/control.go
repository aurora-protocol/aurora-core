package auroracrypto

import (
	"encoding/binary"
	"fmt"

	"github.com/aurora-protocol/aurora-core/wire"
)

type ControlAADInput struct {
	SelectedVersion                 uint64
	SelectedSuite                   uint64
	MsgType                         uint64
	RouteInstanceID                 uint64
	HopIndex                        uint8
	ControlDirection                uint8
	HandshakeBindingContext         []byte
	PreludeTranscriptHashForThisHop []byte
}

func ControlAADPreimage(in ControlAADInput) ([]byte, error) {
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 control aad"))
	e.WriteVarint(in.SelectedVersion)
	e.WriteVarint(in.SelectedSuite)
	e.WriteVarint(in.MsgType)
	e.WriteVarint(in.RouteInstanceID)
	e.WriteUint8(in.HopIndex)
	e.WriteUint8(in.ControlDirection)
	e.WriteOpaque16(in.HandshakeBindingContext)
	e.WriteOpaque16(in.PreludeTranscriptHashForThisHop)
	return e.Bytes()
}

func ControlAAD(in ControlAADInput) ([]byte, error) {
	preimage, err := ControlAADPreimage(in)
	if err != nil {
		return nil, err
	}
	return SuiteHash(in.SelectedSuite, preimage)
}

func FirstHopRouteInstanceID(selectedSuite uint64, preludeTranscriptHash, relayDescriptorHash, firstHopBindingContext, clientNonce []byte) (uint64, error) {
	sum, err := SuiteHash(selectedSuite,
		[]byte("aurora v2.0 first-hop route id"),
		preludeTranscriptHash,
		relayDescriptorHash,
		firstHopBindingContext,
		clientNonce,
	)
	if err != nil {
		return 0, err
	}
	if len(sum) < 8 {
		return 0, fmt.Errorf("crypto: suite hash too short")
	}
	return binary.BigEndian.Uint64(sum[len(sum)-8:]) & ((uint64(1) << 62) - 1), nil
}

func PacketAD(selectedSuite uint64, routeInstanceID uint64, hopLayer, direction, keyPhase uint8, packetNumber uint64) ([]byte, error) {
	if direction > 1 {
		return nil, fmt.Errorf("crypto: reserved packet direction 0x%x", direction)
	}
	e := wire.NewEncoder()
	e.WriteBytes([]byte("aurora v2.0 packet"))
	e.WriteVarint(routeInstanceID)
	e.WriteUint8(hopLayer)
	e.WriteUint8(direction)
	e.WriteUint8(keyPhase)
	e.WriteVarint(packetNumber)
	preimage, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	return SuiteHash(selectedSuite, preimage)
}
