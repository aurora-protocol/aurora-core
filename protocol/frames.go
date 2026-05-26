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
		if err := ValidateKeyUpdateFrame(frame); err != nil {
			return err
		}
		if err := ValidateRouteFrame(frame); err != nil {
			return err
		}
		if err := ValidateFlowManagementFrame(frame); err != nil {
			return err
		}
	}
	return nil
}

func ValidateFrameBlockForDirection(block FrameBlock, direction uint8) error {
	if direction > 1 {
		return fmt.Errorf("protocol: reserved packet direction 0x%x", direction)
	}
	if err := ValidateFrameBlock(block); err != nil {
		return err
	}
	if direction == 1 {
		for _, frame := range block.Frames {
			if frame.FrameType == registry.FrameFlowOpen {
				return fmt.Errorf("protocol: FLOW_OPEN is malformed in backward direction")
			}
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

func DecodeKeyUpdateACK(r *wire.Reader) KeyUpdateACK {
	return KeyUpdateACK{
		RouteInstanceID: r.ReadVarint(),
		HopLayer:        r.ReadUint8(),
		AckedDirection:  r.ReadUint8(),
		AckedKeyPhase:   r.ReadUint8(),
		AckNonce:        r.ReadOpaque16(),
	}
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

func DecodeKeyUpdateRequest(r *wire.Reader) KeyUpdateRequest {
	return KeyUpdateRequest{
		RouteInstanceID:    r.ReadVarint(),
		HopLayer:           r.ReadUint8(),
		RequestedDirection: r.ReadUint8(),
		RequestNonce:       r.ReadOpaque16(),
		RequestReason:      r.ReadVarint(),
	}
}

func ValidateKeyUpdateFrame(frame AuroraFrame) error {
	r := wire.NewReader(frame.Payload)
	switch frame.FrameType {
	case registry.FrameKeyUpdate:
		update := DecodeKeyUpdate(r)
		if r.Err() != nil {
			return r.Err()
		}
		if !r.EOF() {
			return fmt.Errorf("protocol: trailing KEY_UPDATE payload bytes")
		}
		return ValidateKeyUpdate(update)
	case registry.FrameKeyUpdateAck:
		ack := DecodeKeyUpdateACK(r)
		if r.Err() != nil {
			return r.Err()
		}
		if !r.EOF() {
			return fmt.Errorf("protocol: trailing KEY_UPDATE_ACK payload bytes")
		}
		return ValidateKeyUpdateACK(ack)
	case registry.FrameKeyUpdateRequest:
		req := DecodeKeyUpdateRequest(r)
		if r.Err() != nil {
			return r.Err()
		}
		if !r.EOF() {
			return fmt.Errorf("protocol: trailing KEY_UPDATE_REQUEST payload bytes")
		}
		return ValidateKeyUpdateRequest(req)
	default:
		return nil
	}
}

func ValidateKeyUpdate(update KeyUpdate) error {
	if update.Direction > 1 {
		return fmt.Errorf("protocol: reserved KEY_UPDATE direction 0x%x", update.Direction)
	}
	if update.NewKeyPhase != update.OldKeyPhase+1 {
		return fmt.Errorf("protocol: skipped KEY_UPDATE phase %d -> %d", update.OldKeyPhase, update.NewKeyPhase)
	}
	return nil
}

func ValidateKeyUpdateACK(ack KeyUpdateACK) error {
	if ack.AckedDirection > 1 {
		return fmt.Errorf("protocol: reserved KEY_UPDATE_ACK direction 0x%x", ack.AckedDirection)
	}
	return nil
}

func ValidateKeyUpdateRequest(req KeyUpdateRequest) error {
	if req.RequestedDirection > 1 {
		return fmt.Errorf("protocol: reserved KEY_UPDATE_REQUEST direction 0x%x", req.RequestedDirection)
	}
	return nil
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

func ValidateFlowOpen(open FlowOpen) error {
	if open.FlowOpenVersion != registry.Version20 {
		return fmt.Errorf("protocol: unsupported flow_open_version 0x%x", open.FlowOpenVersion)
	}
	if open.FlowID == 0 {
		return fmt.Errorf("protocol: FLOW_OPEN has zero flow_id")
	}
	switch open.FlowKind {
	case 0x01, 0x02, 0x03:
	default:
		return fmt.Errorf("protocol: reserved flow_kind 0x%x", open.FlowKind)
	}
	switch open.TargetKind {
	case 0x01:
		if len(open.TargetHost) != 4 {
			return fmt.Errorf("protocol: FLOW_OPEN IPv4 target must be 4 bytes")
		}
	case 0x02:
		if len(open.TargetHost) != 16 {
			return fmt.Errorf("protocol: FLOW_OPEN IPv6 target must be 16 bytes")
		}
	case 0x03:
		if len(open.TargetHost) == 0 {
			return fmt.Errorf("protocol: FLOW_OPEN domain target is empty")
		}
	default:
		return fmt.Errorf("protocol: reserved target_kind 0x%x", open.TargetKind)
	}
	switch open.UDPFQDNMode {
	case 0x00, 0x01, 0x02, 0x03:
	default:
		return fmt.Errorf("protocol: reserved udp_fqdn_mode 0x%x", open.UDPFQDNMode)
	}
	if len(open.NameBindingID) != 16 {
		return fmt.Errorf("protocol: FLOW_OPEN name_binding_id must be 16 bytes")
	}
	if len(open.DNSAnswerSetHash) != 48 {
		return fmt.Errorf("protocol: FLOW_OPEN DNS answer hash must be 48 bytes")
	}
	switch open.LocalBindingMode {
	case 0x00, 0x01, 0x02, 0x03:
	default:
		return fmt.Errorf("protocol: reserved local_binding_mode 0x%x", open.LocalBindingMode)
	}
	switch open.PriorityClass {
	case 0x00, 0x01, 0x02, 0x03:
	default:
		return fmt.Errorf("protocol: reserved priority_class 0x%x", open.PriorityClass)
	}
	if err := ValidateExtensions(open.Extensions, nil); err != nil {
		return err
	}
	return nil
}

type UDPTargetConfirm struct {
	FlowID           uint64
	TargetKind       uint8
	SelectedIP       []byte
	SelectedPort     uint16
	DNSAnswerSetHash []byte
	TTLSeconds       uint32
	ResolutionSource uint8
	Extensions       []Extension
}

func (u UDPTargetConfirm) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(u.FlowID)
	e.WriteUint8(u.TargetKind)
	e.WriteOpaque16(u.SelectedIP)
	e.WriteUint16(u.SelectedPort)
	e.WritePreHash(u.DNSAnswerSetHash)
	e.WriteUint32(u.TTLSeconds)
	e.WriteUint8(u.ResolutionSource)
	EncodeExtensions(e, u.Extensions)
}

func DecodeUDPTargetConfirm(r *wire.Reader) UDPTargetConfirm {
	return UDPTargetConfirm{
		FlowID:           r.ReadVarint(),
		TargetKind:       r.ReadUint8(),
		SelectedIP:       r.ReadOpaque16(),
		SelectedPort:     r.ReadUint16(),
		DNSAnswerSetHash: r.ReadPreHash(),
		TTLSeconds:       r.ReadUint32(),
		ResolutionSource: r.ReadUint8(),
		Extensions:       DecodeExtensions(r),
	}
}

const (
	UDPResolutionNotResolvedByRelay uint8 = 0x00
	UDPResolutionClientSuppliedIP   uint8 = 0x01
	UDPResolutionRelayRecursiveDNS  uint8 = 0x02
	UDPResolutionRelaySystemDNS     uint8 = 0x03
	UDPResolutionEncryptedDNS       uint8 = 0x04
)

type FlowClose struct {
	FlowID                   uint64
	CloseCode                uint64
	FinalSequenceHintPresent bool
	FinalSequenceHint        uint64
	Reason                   []byte
	Extensions               []Extension
}

func (c FlowClose) EncodeTo(e *wire.Encoder) {
	e.WriteVarint(c.FlowID)
	e.WriteVarint(c.CloseCode)
	e.WriteBool(c.FinalSequenceHintPresent)
	if c.FinalSequenceHintPresent {
		e.WriteUint64(c.FinalSequenceHint)
	}
	e.WriteOpaque16(c.Reason)
	EncodeExtensions(e, c.Extensions)
}

func DecodeFlowClose(r *wire.Reader) FlowClose {
	out := FlowClose{
		FlowID:                   r.ReadVarint(),
		CloseCode:                r.ReadVarint(),
		FinalSequenceHintPresent: r.ReadBool(),
	}
	if out.FinalSequenceHintPresent {
		out.FinalSequenceHint = r.ReadUint64()
	}
	out.Reason = r.ReadOpaque16()
	out.Extensions = DecodeExtensions(r)
	return out
}

const (
	CloseNormal            uint64 = 0x00
	CloseIdleTimeout       uint64 = 0x01
	ClosePolicyDenied      uint64 = 0x02
	CloseTargetUnreachable uint64 = 0x03
	CloseResetByPeer       uint64 = 0x04
	CloseMalformedFlow     uint64 = 0x05
	CloseResourceLimit     uint64 = 0x06
)

func ValidateFlowManagementFrame(frame AuroraFrame) error {
	r := wire.NewReader(frame.Payload)
	var payloadFlowID uint64
	var extensions []Extension
	var closePayload FlowClose
	switch frame.FrameType {
	case registry.FrameFlowOpen:
		payload := DecodeFlowOpen(r)
		payloadFlowID = payload.FlowID
		extensions = payload.Extensions
		if err := ValidateFlowOpen(payload); err != nil {
			return err
		}
	case registry.FrameUDPTargetConfirm:
		payload := DecodeUDPTargetConfirm(r)
		payloadFlowID = payload.FlowID
		extensions = payload.Extensions
		if err := ValidateUDPTargetConfirm(payload); err != nil {
			return err
		}
	case registry.FrameFlowClose:
		payload := DecodeFlowClose(r)
		payloadFlowID = payload.FlowID
		extensions = payload.Extensions
		closePayload = payload
	default:
		return nil
	}
	if r.Err() != nil {
		return r.Err()
	}
	if !r.EOF() {
		return fmt.Errorf("protocol: trailing flow-management payload bytes")
	}
	if frame.FrameType == registry.FrameFlowClose {
		if err := ValidateFlowClose(closePayload); err != nil {
			return err
		}
	}
	if err := ValidateExtensions(extensions, nil); err != nil {
		return err
	}
	if payloadFlowID != frame.FlowID {
		return fmt.Errorf("protocol: frame flow_id %d does not match payload flow_id %d", frame.FlowID, payloadFlowID)
	}
	return nil
}

func ValidateUDPTargetConfirm(confirm UDPTargetConfirm) error {
	if confirm.FlowID == 0 {
		return fmt.Errorf("protocol: UDP target confirm has zero flow_id")
	}
	switch confirm.TargetKind {
	case 0x01:
		if len(confirm.SelectedIP) != 4 {
			return fmt.Errorf("protocol: UDP target confirm IPv4 target must be 4 bytes")
		}
	case 0x02:
		if len(confirm.SelectedIP) != 16 {
			return fmt.Errorf("protocol: UDP target confirm IPv6 target must be 16 bytes")
		}
	default:
		return fmt.Errorf("protocol: UDP target confirm target_kind must be IP, got 0x%x", confirm.TargetKind)
	}
	if len(confirm.DNSAnswerSetHash) != 48 {
		return fmt.Errorf("protocol: UDP target confirm DNS answer hash must be 48 bytes")
	}
	if confirm.TTLSeconds > 86400 {
		return fmt.Errorf("protocol: UDP target confirm ttl_seconds %d exceeds 86400", confirm.TTLSeconds)
	}
	switch confirm.ResolutionSource {
	case UDPResolutionNotResolvedByRelay,
		UDPResolutionClientSuppliedIP,
		UDPResolutionRelayRecursiveDNS,
		UDPResolutionRelaySystemDNS,
		UDPResolutionEncryptedDNS:
	default:
		return fmt.Errorf("protocol: reserved UDP resolution source 0x%x", confirm.ResolutionSource)
	}
	if err := ValidateExtensions(confirm.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func ValidateFlowClose(close FlowClose) error {
	if close.FlowID == 0 {
		return fmt.Errorf("protocol: FLOW_CLOSE has zero flow_id")
	}
	switch {
	case close.CloseCode <= CloseResourceLimit:
	case close.CloseCode >= 0x7000 && close.CloseCode <= 0x7eff:
	case close.CloseCode >= 0x7f00 && close.CloseCode <= 0x7fff:
	default:
		return fmt.Errorf("protocol: reserved flow close code 0x%x", close.CloseCode)
	}
	if err := ValidateExtensions(close.Extensions, nil); err != nil {
		return err
	}
	return nil
}

func NewUDPTargetConfirmFrame(confirm UDPTargetConfirm) (AuroraFrame, error) {
	if err := ValidateUDPTargetConfirm(confirm); err != nil {
		return AuroraFrame{}, err
	}
	confirm.SelectedIP = append([]byte(nil), confirm.SelectedIP...)
	confirm.DNSAnswerSetHash = append([]byte(nil), confirm.DNSAnswerSetHash...)
	payload, err := Encode(confirm)
	if err != nil {
		return AuroraFrame{}, err
	}
	frame := AuroraFrame{
		FrameType: registry.FrameUDPTargetConfirm,
		FlowID:    confirm.FlowID,
		Payload:   payload,
	}
	if err := ValidateFlowManagementFrame(frame); err != nil {
		return AuroraFrame{}, err
	}
	return frame, nil
}

func NewFlowCloseFrame(close FlowClose) (AuroraFrame, error) {
	if err := ValidateFlowClose(close); err != nil {
		return AuroraFrame{}, err
	}
	close.Reason = append([]byte(nil), close.Reason...)
	payload, err := Encode(close)
	if err != nil {
		return AuroraFrame{}, err
	}
	frame := AuroraFrame{
		FrameType: registry.FrameFlowClose,
		FlowID:    close.FlowID,
		Payload:   payload,
	}
	if err := ValidateFlowManagementFrame(frame); err != nil {
		return AuroraFrame{}, err
	}
	return frame, nil
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

func DecodeRouteForwardFrame(r *wire.Reader) RouteForwardFrame {
	return RouteForwardFrame{
		RouteInstanceID:                r.ReadVarint(),
		HopIndex:                       r.ReadUint8(),
		NextRelayDescriptorHash:        r.ReadPreHash(),
		PreviousHopRelayDescriptorHash: r.ReadPreHash(),
		NextRelayRoutingRecordID:       r.ReadOpaque16(),
		NextRelayLocatorType:           r.ReadVarint(),
		NextRelayLocator:               r.ReadOpaque16(),
		OpaqueNextHopPrelude:           r.ReadOpaque24(),
	}
}

func ValidateRouteFrame(frame AuroraFrame) error {
	switch frame.FrameType {
	case registry.FrameRouteForward:
		r := wire.NewReader(frame.Payload)
		forward := DecodeRouteForwardFrame(r)
		if r.Err() != nil {
			return r.Err()
		}
		if !r.EOF() {
			return fmt.Errorf("protocol: trailing ROUTE_FORWARD payload bytes")
		}
		return ValidateRouteForwardFrame(forward)
	default:
		return nil
	}
}

func ValidateRouteForwardFrame(forward RouteForwardFrame) error {
	switch forward.NextRelayLocatorType {
	case registry.LocatorIPv4Port:
		if len(forward.NextRelayLocator) != 6 {
			return fmt.Errorf("protocol: IPv4 locator must be 6 bytes")
		}
	case registry.LocatorIPv6Port:
		if len(forward.NextRelayLocator) != 18 {
			return fmt.Errorf("protocol: IPv6 locator must be 18 bytes")
		}
	case registry.LocatorAuthority:
		if err := validateAuthorityLocator(forward.NextRelayLocator); err != nil {
			return err
		}
	case registry.LocatorOpaque:
		if len(forward.NextRelayLocator) == 0 {
			return fmt.Errorf("protocol: route-forward locator is empty")
		}
	default:
		return fmt.Errorf("protocol: reserved route-forward locator type 0x%x", forward.NextRelayLocatorType)
	}
	return nil
}

func validateAuthorityLocator(locator []byte) error {
	r := wire.NewReader(locator)
	authority := r.ReadOpaque16()
	port := r.ReadUint16()
	if r.Err() != nil {
		return r.Err()
	}
	if !r.EOF() {
		return fmt.Errorf("protocol: trailing authority locator bytes")
	}
	if len(authority) == 0 {
		return fmt.Errorf("protocol: authority locator name is empty")
	}
	if port == 0 {
		return fmt.Errorf("protocol: authority locator port is zero")
	}
	return nil
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

func DecodeRoutePreludeEnvelope(r *wire.Reader) RoutePreludeEnvelope {
	return RoutePreludeEnvelope{
		RouteInstanceID:                r.ReadVarint(),
		HopIndex:                       r.ReadUint8(),
		PreviousHopRelayDescriptorHash: r.ReadPreHash(),
		NextRelayDescriptorHash:        r.ReadPreHash(),
		HintIssuerID:                   r.ReadOpaqueFixed(16),
		RelayBucketID:                  r.ReadOpaqueFixed(16),
		HintEpochID:                    r.ReadUint64(),
		HintSelector:                   r.ReadOpaqueFixed(16),
		WrapSuiteID:                    r.ReadVarint(),
		WrapNonce:                      r.ReadOpaqueFixed(16),
		SealedRoutePrelude0:            r.ReadOpaque24(),
	}
}
