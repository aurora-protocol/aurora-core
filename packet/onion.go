package packet

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func SealSplit2Onion(exitBlock protocol.FrameBlock, entry *Protector, exit *Protector, forward protocol.RouteForwardFrame) (AuroraPacket, error) {
	if entry == nil || exit == nil {
		return AuroraPacket{}, fmt.Errorf("packet: split-2 protectors are required")
	}
	if forward.RouteInstanceID != exit.RouteInstanceID || forward.HopIndex != exit.HopLayer {
		return AuroraPacket{}, fmt.Errorf("packet: route-forward metadata does not match exit layer")
	}
	if err := protocol.ValidateRouteForwardFrame(forward); err != nil {
		return AuroraPacket{}, err
	}
	inner, err := exit.Seal(exitBlock)
	if err != nil {
		return AuroraPacket{}, err
	}
	encodedInner, err := protocol.Encode(inner)
	if err != nil {
		return AuroraPacket{}, err
	}
	forward.OpaqueNextHopPrelude = encodedInner
	forwardPayload, err := protocol.Encode(forward)
	if err != nil {
		return AuroraPacket{}, err
	}
	outer := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameRouteForward,
		FlowID:    0,
		Payload:   forwardPayload,
	}}}
	return entry.Seal(outer)
}

func SealSplit2BackwardOnion(exitBlock protocol.FrameBlock, entry *Protector, exit *Protector, forward protocol.RouteForwardFrame) (AuroraPacket, error) {
	if entry == nil || exit == nil {
		return AuroraPacket{}, fmt.Errorf("packet: split-2 protectors are required")
	}
	if entry.RouteInstanceID != exit.RouteInstanceID {
		return AuroraPacket{}, fmt.Errorf("packet: backward split-2 protectors use different route instances")
	}
	if entry.HopLayer != 0 || exit.HopLayer != 1 {
		return AuroraPacket{}, fmt.Errorf("packet: backward split-2 protectors must be entry hop 0 and exit hop 1")
	}
	if entry.Direction != 1 || exit.Direction != 1 {
		return AuroraPacket{}, fmt.Errorf("packet: backward split-2 protectors must use backward direction")
	}
	return SealSplit2Onion(exitBlock, entry, exit, forward)
}

func DecodeForwardedPacket(block protocol.FrameBlock) (AuroraPacket, error) {
	if len(block.Frames) != 1 {
		return AuroraPacket{}, fmt.Errorf("packet: route-forward block must contain one frame")
	}
	frame := block.Frames[0]
	if frame.FrameType != registry.FrameRouteForward {
		return AuroraPacket{}, fmt.Errorf("packet: frame is not route-forward")
	}
	forward, err := decodeRouteForwardPayload(frame.Payload)
	if err != nil {
		return AuroraPacket{}, err
	}
	return DecodeAuroraPacket(forward.OpaqueNextHopPrelude)
}

func decodeRouteForwardPayload(payload []byte) (protocol.RouteForwardFrame, error) {
	r := wire.NewReader(payload)
	forward := protocol.DecodeRouteForwardFrame(r)
	if r.Err() != nil {
		return protocol.RouteForwardFrame{}, r.Err()
	}
	if !r.EOF() {
		return protocol.RouteForwardFrame{}, fmt.Errorf("packet: trailing route-forward payload bytes")
	}
	return forward, nil
}
