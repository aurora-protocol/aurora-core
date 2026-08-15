package auroracrypto

import (
	"encoding/binary"
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	packetADLabel                = "aurora v2.0 packet"
	packetADPreimageMaximumBytes = len(packetADLabel) + 8 + 3 + 8
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
	if err := validateControlAADInput(in); err != nil {
		return nil, err
	}
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

func validateControlAADInput(in ControlAADInput) error {
	if in.ControlDirection > 1 {
		return fmt.Errorf("crypto: reserved control direction 0x%x", in.ControlDirection)
	}
	switch in.MsgType {
	case registry.MsgCoverCapsule1, registry.MsgRouteCapsule1:
		if in.ControlDirection != 0 {
			return fmt.Errorf("crypto: control message 0x%x must use direction 0", in.MsgType)
		}
	case registry.MsgCoverCapsule2, registry.MsgRouteCapsule2:
		if in.ControlDirection != 1 {
			return fmt.Errorf("crypto: control message 0x%x must use direction 1", in.MsgType)
		}
	}
	return nil
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
	return AppendPacketAD(nil, selectedSuite, routeInstanceID, hopLayer, direction, keyPhase, packetNumber)
}

// AppendPacketAD appends the packet associated data to dst. A caller that
// already owns digest-sized storage avoids an allocation per packet.
func AppendPacketAD(dst []byte, selectedSuite uint64, routeInstanceID uint64, hopLayer, direction, keyPhase uint8, packetNumber uint64) ([]byte, error) {
	if direction > 1 {
		return nil, fmt.Errorf("crypto: reserved packet direction 0x%x", direction)
	}
	var storage [packetADPreimageMaximumBytes]byte
	preimage := append(storage[:0], packetADLabel...)
	var err error
	preimage, err = wire.AppendVarint(preimage, routeInstanceID)
	if err != nil {
		return nil, err
	}
	preimage = append(preimage, hopLayer, direction, keyPhase)
	preimage, err = wire.AppendVarint(preimage, packetNumber)
	if err != nil {
		return nil, err
	}
	return AppendSuiteHash(dst, selectedSuite, preimage)
}
