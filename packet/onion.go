package packet

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func SealSplit2Onion(exitBlock protocol.FrameBlock, entry *Protector, exit *Protector) (AuroraPacket, error) {
	if entry == nil || exit == nil {
		return AuroraPacket{}, fmt.Errorf("packet: split-2 protectors are required")
	}
	inner, err := exit.Seal(exitBlock)
	if err != nil {
		return AuroraPacket{}, err
	}
	encodedInner, err := protocol.Encode(inner)
	if err != nil {
		return AuroraPacket{}, err
	}
	outer := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameRouteForward,
		FlowID:    0,
		Payload:   encodedInner,
	}}}
	return entry.Seal(outer)
}

func DecodeForwardedPacket(block protocol.FrameBlock) (AuroraPacket, error) {
	if len(block.Frames) != 1 {
		return AuroraPacket{}, fmt.Errorf("packet: route-forward block must contain one frame")
	}
	frame := block.Frames[0]
	if frame.FrameType != registry.FrameRouteForward {
		return AuroraPacket{}, fmt.Errorf("packet: frame is not route-forward")
	}
	return DecodeAuroraPacket(frame.Payload)
}
