package protocol

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type AuroraFrame struct {
	FrameType uint64
	FlowID    uint64
	Flags     uint64
	Payload   []byte
}

func (f AuroraFrame) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(f.FrameType)
	e.WriteVarint(f.FlowID)
	e.WriteVarint(f.Flags)
	e.WriteOpaque24(f.Payload)
}

func DecodeAuroraFrame(r *wire.Reader) AuroraFrame {
	return AuroraFrame{
		FrameType: r.ReadVarint(),
		FlowID:    r.ReadVarint(),
		Flags:     r.ReadVarint(),
		Payload:   r.ReadOpaque24(),
	}
}

type FrameBlock struct {
	Frames []AuroraFrame
}

func (b FrameBlock) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(uint64(len(b.Frames)))
	for _, f := range b.Frames {
		f.EncodeTo(e)
	}
}

func DecodeFrameBlock(encoded []byte) (FrameBlock, error) {
	r := wire.NewReader(encoded)
	count := r.ReadVarint()
	block := FrameBlock{Frames: make([]AuroraFrame, 0, count)}
	for i := uint64(0); i < count; i++ {
		block.Frames = append(block.Frames, DecodeAuroraFrame(r))
	}
	if r.Err() != nil {
		return FrameBlock{}, r.Err()
	}
	if !r.EOF() {
		return FrameBlock{}, fmt.Errorf("protocol: trailing FrameBlock bytes")
	}
	return block, nil
}

func ValidateFrameBlock(block FrameBlock) error {
	for _, frame := range block.Frames {
		if err := ValidateFrameType(frame.FrameType); err != nil {
			return err
		}
		if err := ValidateDataFrame(frame); err != nil {
			return err
		}
		if err := ValidateFlowManagementFrame(frame); err != nil {
			return err
		}
	}
	return nil
}

func ValidateFrameType(frameType uint64) error {
	switch frameType {
	case registry.FrameStreamData,
		registry.FrameDatagramData,
		registry.FrameIPPacket,
		registry.FrameDNSMessage,
		registry.FrameControl,
		registry.FramePathProbe,
		registry.FrameKeyUpdate,
		registry.FramePadding,
		registry.FrameClose,
		registry.FrameRouteForward,
		registry.FramePriorityUpdate,
		registry.FrameAckHint,
		registry.FrameKeyUpdateAck,
		registry.FrameKeyUpdateRequest,
		registry.FrameFlowOpen,
		registry.FrameUDPTargetConfirm,
		registry.FrameFlowClose:
		return nil
	default:
		if frameType <= 0x6fff {
			return fmt.Errorf("protocol: unknown reserved frame type 0x%x", frameType)
		}
		return nil
	}
}

func NewStreamDataFrame(flowID uint64, data []byte, flags uint64) (AuroraFrame, error) {
	return newDataFrame(registry.FrameStreamData, flowID, data, flags)
}

func NewDatagramDataFrame(flowID uint64, data []byte, flags uint64) (AuroraFrame, error) {
	return newDataFrame(registry.FrameDatagramData, flowID, data, flags)
}

func NewDNSMessageFrame(flowID uint64, message []byte) (AuroraFrame, error) {
	return newDataFrame(registry.FrameDNSMessage, flowID, message, 0)
}

func newDataFrame(frameType, flowID uint64, payload []byte, flags uint64) (AuroraFrame, error) {
	frame := AuroraFrame{
		FrameType: frameType,
		FlowID:    flowID,
		Flags:     flags,
		Payload:   append([]byte(nil), payload...),
	}
	if err := ValidateDataFrame(frame); err != nil {
		return AuroraFrame{}, err
	}
	return frame, nil
}

func ValidateDataFrame(frame AuroraFrame) error {
	switch frame.FrameType {
	case registry.FrameStreamData, registry.FrameDatagramData, registry.FrameDNSMessage:
	default:
		return nil
	}
	if frame.FlowID == 0 {
		return fmt.Errorf("protocol: data frame has zero flow_id")
	}
	if len(frame.Payload) == 0 {
		return fmt.Errorf("protocol: data frame has empty payload")
	}
	return nil
}

type KeyUpdate struct {
	RouteInstanceID uint64
	HopLayer        uint8
	Direction       uint8
	OldKeyPhase     uint8
	NewKeyPhase     uint8
	UpdateNonce     []byte
	AckRequired     bool
	UpdateReason    uint64
}

func (k KeyUpdate) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(k.RouteInstanceID)
	e.WriteUint8(k.HopLayer)
	e.WriteUint8(k.Direction)
	e.WriteUint8(k.OldKeyPhase)
	e.WriteUint8(k.NewKeyPhase)
	e.WriteOpaque16(k.UpdateNonce)
	if k.AckRequired {
		e.WriteUint8(1)
	} else {
		e.WriteUint8(0)
	}
	e.WriteVarint(k.UpdateReason)
}

func DecodeKeyUpdate(r *wire.Reader) KeyUpdate {
	return KeyUpdate{
		RouteInstanceID: r.ReadVarint(),
		HopLayer:        r.ReadUint8(),
		Direction:       r.ReadUint8(),
		OldKeyPhase:     r.ReadUint8(),
		NewKeyPhase:     r.ReadUint8(),
		UpdateNonce:     r.ReadOpaque16(),
		AckRequired:     r.ReadBool(),
		UpdateReason:    r.ReadVarint(),
	}
}

type KeyUpdateACK struct {
	RouteInstanceID uint64
	HopLayer        uint8
	AckedDirection  uint8
	AckedKeyPhase   uint8
	AckNonce        []byte
}

func (a KeyUpdateACK) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(a.RouteInstanceID)
	e.WriteUint8(a.HopLayer)
	e.WriteUint8(a.AckedDirection)
	e.WriteUint8(a.AckedKeyPhase)
	e.WriteOpaque16(a.AckNonce)
}

type KeyUpdateRequest struct {
	RouteInstanceID    uint64
	HopLayer           uint8
	RequestedDirection uint8
	RequestNonce       []byte
	RequestReason      uint64
}

func (r KeyUpdateRequest) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.RouteInstanceID)
	e.WriteUint8(r.HopLayer)
	e.WriteUint8(r.RequestedDirection)
	e.WriteOpaque16(r.RequestNonce)
	e.WriteVarint(r.RequestReason)
}

type FlowOpen struct {
	FlowOpenVersion    uint64
	FlowID             uint64
	FlowKind           uint8
	TargetKind         uint8
	TargetHost         []byte
	TargetPort         uint16
	UDPFQDNMode        uint8
	NameBindingID      []byte
	OriginalDomainHint []byte
	DNSAnswerSetHash   []byte
	LocalBindingMode   uint8
	PriorityClass      uint8
	Extensions         []Extension
}

func (f FlowOpen) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(f.FlowOpenVersion)
	e.WriteVarint(f.FlowID)
	e.WriteUint8(f.FlowKind)
	e.WriteUint8(f.TargetKind)
	e.WriteOpaque16(f.TargetHost)
	e.WriteUint16(f.TargetPort)
	e.WriteUint8(f.UDPFQDNMode)
	e.WriteOpaqueFixed(f.NameBindingID, 16)
	e.WriteOpaque16(f.OriginalDomainHint)
	e.WritePreHash(f.DNSAnswerSetHash)
	e.WriteUint8(f.LocalBindingMode)
	e.WriteUint8(f.PriorityClass)
	EncodeExtensions(e, f.Extensions)
}

func DecodeFlowOpen(r *wire.Reader) FlowOpen {
	return FlowOpen{
		FlowOpenVersion:    r.ReadVarint(),
		FlowID:             r.ReadVarint(),
		FlowKind:           r.ReadUint8(),
		TargetKind:         r.ReadUint8(),
		TargetHost:         r.ReadOpaque16(),
		TargetPort:         r.ReadUint16(),
		UDPFQDNMode:        r.ReadUint8(),
		NameBindingID:      r.ReadOpaqueFixed(16),
		OriginalDomainHint: r.ReadOpaque16(),
		DNSAnswerSetHash:   r.ReadPreHash(),
		LocalBindingMode:   r.ReadUint8(),
		PriorityClass:      r.ReadUint8(),
		Extensions:         DecodeExtensions(r),
	}
}

type UDPTargetConfirm struct {
	FlowID       uint64
	SelectedKind uint8
	SelectedHost []byte
	SelectedPort uint16
	Extensions   []Extension
}

func (u UDPTargetConfirm) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(u.FlowID)
	e.WriteUint8(u.SelectedKind)
	e.WriteOpaque16(u.SelectedHost)
	e.WriteUint16(u.SelectedPort)
	EncodeExtensions(e, u.Extensions)
}

func DecodeUDPTargetConfirm(r *wire.Reader) UDPTargetConfirm {
	return UDPTargetConfirm{
		FlowID:       r.ReadVarint(),
		SelectedKind: r.ReadUint8(),
		SelectedHost: r.ReadOpaque16(),
		SelectedPort: r.ReadUint16(),
		Extensions:   DecodeExtensions(r),
	}
}

type FlowClose struct {
	FlowID     uint64
	Reason     uint64
	ErrorCode  uint64
	Extensions []Extension
}

func (c FlowClose) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.FlowID)
	e.WriteVarint(c.Reason)
	e.WriteVarint(c.ErrorCode)
	EncodeExtensions(e, c.Extensions)
}

func DecodeFlowClose(r *wire.Reader) FlowClose {
	return FlowClose{
		FlowID:     r.ReadVarint(),
		Reason:     r.ReadVarint(),
		ErrorCode:  r.ReadVarint(),
		Extensions: DecodeExtensions(r),
	}
}

func ValidateFlowManagementFrame(frame AuroraFrame) error {
	r := wire.NewReader(frame.Payload)
	var payloadFlowID uint64
	var extensions []Extension
	switch frame.FrameType {
	case registry.FrameFlowOpen:
		payload := DecodeFlowOpen(r)
		payloadFlowID = payload.FlowID
		extensions = payload.Extensions
	case registry.FrameUDPTargetConfirm:
		payload := DecodeUDPTargetConfirm(r)
		payloadFlowID = payload.FlowID
		extensions = payload.Extensions
	case registry.FrameFlowClose:
		payload := DecodeFlowClose(r)
		payloadFlowID = payload.FlowID
		extensions = payload.Extensions
	default:
		return nil
	}
	if r.Err() != nil {
		return r.Err()
	}
	if err := ValidateExtensions(extensions, nil); err != nil {
		return err
	}
	if payloadFlowID != frame.FlowID {
		return fmt.Errorf("protocol: frame flow_id %d does not match payload flow_id %d", frame.FlowID, payloadFlowID)
	}
	return nil
}

type RouteForwardFrame struct {
	RouteInstanceID                uint64
	HopIndex                       uint8
	NextRelayDescriptorHash        []byte
	PreviousHopRelayDescriptorHash []byte
	NextRelayRoutingRecordID       []byte
	NextRelayLocatorType           uint64
	NextRelayLocator               []byte
	OpaqueNextHopPrelude           []byte
}

func (f RouteForwardFrame) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(f.RouteInstanceID)
	e.WriteUint8(f.HopIndex)
	e.WritePreHash(f.NextRelayDescriptorHash)
	e.WritePreHash(f.PreviousHopRelayDescriptorHash)
	e.WriteOpaque16(f.NextRelayRoutingRecordID)
	e.WriteVarint(f.NextRelayLocatorType)
	e.WriteOpaque16(f.NextRelayLocator)
	e.WriteOpaque24(f.OpaqueNextHopPrelude)
}

type RoutePreludeEnvelope struct {
	RouteInstanceID                uint64
	HopIndex                       uint8
	PreviousHopRelayDescriptorHash []byte
	NextRelayDescriptorHash        []byte
	HintIssuerID                   []byte
	RelayBucketID                  []byte
	HintEpochID                    uint64
	HintSelector                   []byte
	WrapSuiteID                    uint64
	WrapNonce                      []byte
	SealedRoutePrelude0            []byte
}

func (r RoutePreludeEnvelope) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(r.RouteInstanceID)
	e.WriteUint8(r.HopIndex)
	e.WritePreHash(r.PreviousHopRelayDescriptorHash)
	e.WritePreHash(r.NextRelayDescriptorHash)
	e.WriteOpaqueFixed(r.HintIssuerID, 16)
	e.WriteOpaqueFixed(r.RelayBucketID, 16)
	e.WriteUint64(r.HintEpochID)
	e.WriteOpaqueFixed(r.HintSelector, 16)
	e.WriteVarint(r.WrapSuiteID)
	e.WriteOpaqueFixed(r.WrapNonce, 16)
	e.WriteOpaque24(r.SealedRoutePrelude0)
}
