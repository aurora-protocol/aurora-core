package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestDataFrameConstructorsCopyPayloads(t *testing.T) {
	data := []byte("hello")
	stream, err := NewStreamDataFrame(7, data, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := NewDatagramDataFrame(8, data, 0x02)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := NewDNSMessageFrame(9, data)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 'H'
	if stream.FrameType != registry.FrameStreamData || stream.FlowID != 7 || stream.Flags != 0x01 || !bytes.Equal(stream.Payload, []byte("hello")) {
		t.Fatalf("unexpected stream frame: %+v", stream)
	}
	if datagram.FrameType != registry.FrameDatagramData || datagram.FlowID != 8 || datagram.Flags != 0x02 || !bytes.Equal(datagram.Payload, []byte("hello")) {
		t.Fatalf("unexpected datagram frame: %+v", datagram)
	}
	if dns.FrameType != registry.FrameDNSMessage || dns.FlowID != 9 || dns.Flags != 0 || !bytes.Equal(dns.Payload, []byte("hello")) {
		t.Fatalf("unexpected DNS frame: %+v", dns)
	}
}

func TestValidateFrameBlockRejectsMalformedDataFrames(t *testing.T) {
	cases := []AuroraFrame{
		{FrameType: registry.FrameStreamData, FlowID: 0, Payload: []byte("data")},
		{FrameType: registry.FrameStreamData, FlowID: 1},
		{FrameType: registry.FrameDatagramData, FlowID: 0, Payload: []byte("data")},
		{FrameType: registry.FrameDatagramData, FlowID: 1},
		{FrameType: registry.FrameDNSMessage, FlowID: 0, Payload: []byte("data")},
		{FrameType: registry.FrameDNSMessage, FlowID: 1},
	}
	for _, frame := range cases {
		if err := ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{frame}}); err == nil {
			t.Fatalf("malformed data frame accepted: %+v", frame)
		}
	}
}

func TestFlowCloseEncodesOptionalFinalSequenceAndReason(t *testing.T) {
	close := FlowClose{
		FlowID:                   7,
		CloseCode:                CloseNormal,
		FinalSequenceHintPresent: true,
		FinalSequenceHint:        42,
		Reason:                   []byte("done"),
	}
	encoded, err := Encode(close)
	if err != nil {
		t.Fatal(err)
	}
	assertProtocolHex(t, encoded, "070001000000000000002a0004646f6e6500")
	got := DecodeFlowClose(bytesReader(encoded))
	if got.FlowID != 7 || got.CloseCode != CloseNormal || !got.FinalSequenceHintPresent || got.FinalSequenceHint != 42 || !bytes.Equal(got.Reason, []byte("done")) {
		t.Fatalf("decoded FlowClose mismatch: %+v", got)
	}
}

func TestValidateFrameBlockRejectsReservedFlowCloseCode(t *testing.T) {
	payload, err := Encode(FlowClose{
		FlowID:    8,
		CloseCode: 0x07,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{{
		FrameType: registry.FrameFlowClose,
		FlowID:    8,
		Payload:   payload,
	}}})
	if err == nil {
		t.Fatalf("reserved FlowClose close code accepted")
	}
}

func TestNewFlowCloseFrameWrapsPayloadAndCopiesReason(t *testing.T) {
	reason := []byte("done")
	frame, err := NewFlowCloseFrame(FlowClose{
		FlowID:    9,
		CloseCode: CloseNormal,
		Reason:    reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	reason[0] = 'D'
	if frame.FrameType != registry.FrameFlowClose || frame.FlowID != 9 || frame.Flags != 0 {
		t.Fatalf("unexpected FlowClose frame: %+v", frame)
	}
	got := DecodeFlowClose(bytesReader(frame.Payload))
	if !bytes.Equal(got.Reason, []byte("done")) {
		t.Fatalf("FlowClose reason was not copied: %q", got.Reason)
	}
	if err := ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{frame}}); err != nil {
		t.Fatalf("FlowClose frame did not validate: %v", err)
	}
}

func TestUDPTargetConfirmEncodesFullPayload(t *testing.T) {
	hash := bytes.Repeat([]byte{0xaa}, 48)
	confirm := UDPTargetConfirm{
		FlowID:           7,
		TargetKind:       0x01,
		SelectedIP:       []byte{203, 0, 113, 9},
		SelectedPort:     443,
		DNSAnswerSetHash: hash,
		TTLSeconds:       60,
		ResolutionSource: UDPResolutionClientSuppliedIP,
	}
	encoded, err := Encode(confirm)
	if err != nil {
		t.Fatal(err)
	}
	assertProtocolHex(t, encoded, "07010004cb00710901bbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000003c0100")
	got := DecodeUDPTargetConfirm(bytesReader(encoded))
	if got.FlowID != 7 || got.TargetKind != 0x01 || got.SelectedPort != 443 || got.TTLSeconds != 60 || got.ResolutionSource != UDPResolutionClientSuppliedIP {
		t.Fatalf("decoded UDP target confirm mismatch: %+v", got)
	}
	if !bytes.Equal(got.SelectedIP, []byte{203, 0, 113, 9}) || !bytes.Equal(got.DNSAnswerSetHash, hash) {
		t.Fatalf("decoded UDP target confirm bytes mismatch: %+v", got)
	}
}

func TestKeyUpdateControlPayloadsRoundTrip(t *testing.T) {
	ack := KeyUpdateACK{
		RouteInstanceID: 9,
		HopLayer:        1,
		AckedDirection:  0,
		AckedKeyPhase:   2,
		AckNonce:        bytes.Repeat([]byte{0x44}, 16),
	}
	encodedACK, err := Encode(ack)
	if err != nil {
		t.Fatal(err)
	}
	gotACK := DecodeKeyUpdateACK(bytesReader(encodedACK))
	if gotACK.RouteInstanceID != ack.RouteInstanceID || gotACK.HopLayer != ack.HopLayer || gotACK.AckedDirection != ack.AckedDirection || gotACK.AckedKeyPhase != ack.AckedKeyPhase || !bytes.Equal(gotACK.AckNonce, ack.AckNonce) {
		t.Fatalf("decoded KEY_UPDATE_ACK mismatch: %+v", gotACK)
	}

	req := KeyUpdateRequest{
		RouteInstanceID:    10,
		HopLayer:           2,
		RequestedDirection: 1,
		RequestNonce:       bytes.Repeat([]byte{0x55}, 16),
		RequestReason:      3,
	}
	encodedReq, err := Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	gotReq := DecodeKeyUpdateRequest(bytesReader(encodedReq))
	if gotReq.RouteInstanceID != req.RouteInstanceID || gotReq.HopLayer != req.HopLayer || gotReq.RequestedDirection != req.RequestedDirection || gotReq.RequestReason != req.RequestReason || !bytes.Equal(gotReq.RequestNonce, req.RequestNonce) {
		t.Fatalf("decoded KEY_UPDATE_REQUEST mismatch: %+v", gotReq)
	}
}

func TestRouteControlPayloadsRoundTrip(t *testing.T) {
	forward := RouteForwardFrame{
		RouteInstanceID:                11,
		HopIndex:                       1,
		NextRelayDescriptorHash:        bytes.Repeat([]byte{0x66}, 48),
		PreviousHopRelayDescriptorHash: bytes.Repeat([]byte{0x77}, 48),
		NextRelayRoutingRecordID:       bytes.Repeat([]byte{0x88}, 16),
		NextRelayLocatorType:           registry.LocatorAuthority,
		NextRelayLocator:               []byte("next.example"),
		OpaqueNextHopPrelude:           []byte("sealed"),
	}
	encodedForward, err := Encode(forward)
	if err != nil {
		t.Fatal(err)
	}
	gotForward := DecodeRouteForwardFrame(bytesReader(encodedForward))
	if gotForward.RouteInstanceID != forward.RouteInstanceID || gotForward.HopIndex != forward.HopIndex || gotForward.NextRelayLocatorType != forward.NextRelayLocatorType {
		t.Fatalf("decoded route forward scalar mismatch: %+v", gotForward)
	}
	if !bytes.Equal(gotForward.NextRelayDescriptorHash, forward.NextRelayDescriptorHash) ||
		!bytes.Equal(gotForward.PreviousHopRelayDescriptorHash, forward.PreviousHopRelayDescriptorHash) ||
		!bytes.Equal(gotForward.NextRelayRoutingRecordID, forward.NextRelayRoutingRecordID) ||
		!bytes.Equal(gotForward.NextRelayLocator, forward.NextRelayLocator) ||
		!bytes.Equal(gotForward.OpaqueNextHopPrelude, forward.OpaqueNextHopPrelude) {
		t.Fatalf("decoded route forward bytes mismatch: %+v", gotForward)
	}

	envelope := RoutePreludeEnvelope{
		RouteInstanceID:                12,
		HopIndex:                       2,
		PreviousHopRelayDescriptorHash: bytes.Repeat([]byte{0x99}, 48),
		NextRelayDescriptorHash:        bytes.Repeat([]byte{0xaa}, 48),
		HintIssuerID:                   bytes.Repeat([]byte{0xbb}, 16),
		RelayBucketID:                  bytes.Repeat([]byte{0xcc}, 16),
		HintEpochID:                    1700000000,
		HintSelector:                   bytes.Repeat([]byte{0xdd}, 16),
		WrapSuiteID:                    registry.WrapSuiteRouteV1,
		WrapNonce:                      bytes.Repeat([]byte{0xee}, 16),
		SealedRoutePrelude0:            []byte("route-prelude"),
	}
	encodedEnvelope, err := Encode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	gotEnvelope := DecodeRoutePreludeEnvelope(bytesReader(encodedEnvelope))
	if gotEnvelope.RouteInstanceID != envelope.RouteInstanceID || gotEnvelope.HopIndex != envelope.HopIndex || gotEnvelope.HintEpochID != envelope.HintEpochID || gotEnvelope.WrapSuiteID != envelope.WrapSuiteID {
		t.Fatalf("decoded route prelude envelope scalar mismatch: %+v", gotEnvelope)
	}
	if !bytes.Equal(gotEnvelope.PreviousHopRelayDescriptorHash, envelope.PreviousHopRelayDescriptorHash) ||
		!bytes.Equal(gotEnvelope.NextRelayDescriptorHash, envelope.NextRelayDescriptorHash) ||
		!bytes.Equal(gotEnvelope.HintIssuerID, envelope.HintIssuerID) ||
		!bytes.Equal(gotEnvelope.RelayBucketID, envelope.RelayBucketID) ||
		!bytes.Equal(gotEnvelope.HintSelector, envelope.HintSelector) ||
		!bytes.Equal(gotEnvelope.WrapNonce, envelope.WrapNonce) ||
		!bytes.Equal(gotEnvelope.SealedRoutePrelude0, envelope.SealedRoutePrelude0) {
		t.Fatalf("decoded route prelude envelope bytes mismatch: %+v", gotEnvelope)
	}
}

func TestNewUDPTargetConfirmFrameValidatesAndCopiesPayload(t *testing.T) {
	selectedIP := []byte{203, 0, 113, 10}
	hash := bytes.Repeat([]byte{0xbb}, 48)
	frame, err := NewUDPTargetConfirmFrame(UDPTargetConfirm{
		FlowID:           10,
		TargetKind:       0x01,
		SelectedIP:       selectedIP,
		SelectedPort:     443,
		DNSAnswerSetHash: hash,
		TTLSeconds:       300,
		ResolutionSource: UDPResolutionRelayRecursiveDNS,
	})
	if err != nil {
		t.Fatal(err)
	}
	selectedIP[0] = 0
	hash[0] = 0
	if frame.FrameType != registry.FrameUDPTargetConfirm || frame.FlowID != 10 || frame.Flags != 0 {
		t.Fatalf("unexpected UDP target confirm frame: %+v", frame)
	}
	got := DecodeUDPTargetConfirm(bytesReader(frame.Payload))
	if !bytes.Equal(got.SelectedIP, []byte{203, 0, 113, 10}) || got.DNSAnswerSetHash[0] != 0xbb {
		t.Fatalf("UDP target confirm payload was not copied: %+v", got)
	}
	if err := ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{frame}}); err != nil {
		t.Fatalf("UDP target confirm frame did not validate: %v", err)
	}
}

func TestValidateFrameBlockRejectsTrailingFlowManagementPayload(t *testing.T) {
	openPayload, err := Encode(FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           11,
		FlowKind:         0x01,
		TargetKind:       0x01,
		TargetHost:       []byte{93, 184, 216, 34},
		TargetPort:       443,
		NameBindingID:    bytes.Repeat([]byte{0x01}, 16),
		DNSAnswerSetHash: bytes.Repeat([]byte{0x02}, 48),
	})
	if err != nil {
		t.Fatal(err)
	}
	confirmPayload, err := Encode(UDPTargetConfirm{
		FlowID:           12,
		TargetKind:       0x01,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: bytes.Repeat([]byte{0x03}, 48),
		TTLSeconds:       60,
		ResolutionSource: UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	closePayload, err := Encode(FlowClose{FlowID: 13, CloseCode: CloseNormal})
	if err != nil {
		t.Fatal(err)
	}
	cases := []AuroraFrame{{
		FrameType: registry.FrameFlowOpen,
		FlowID:    11,
		Payload:   append(openPayload, 0xff),
	}, {
		FrameType: registry.FrameUDPTargetConfirm,
		FlowID:    12,
		Payload:   append(confirmPayload, 0xff),
	}, {
		FrameType: registry.FrameFlowClose,
		FlowID:    13,
		Payload:   append(closePayload, 0xff),
	}}
	for _, frame := range cases {
		if err := ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{frame}}); err == nil {
			t.Fatalf("flow-management frame accepted trailing payload byte: %+v", frame)
		}
	}
}

func TestValidateFrameBlockRejectsMalformedFlowOpenPayload(t *testing.T) {
	base := FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           21,
		FlowKind:         0x01,
		TargetKind:       0x01,
		TargetHost:       []byte{93, 184, 216, 34},
		TargetPort:       443,
		NameBindingID:    bytes.Repeat([]byte{0x01}, 16),
		DNSAnswerSetHash: bytes.Repeat([]byte{0x02}, 48),
		LocalBindingMode: 0x00,
		PriorityClass:    0x01,
	}
	cases := map[string]FlowOpen{
		"version": func() FlowOpen {
			open := base
			open.FlowOpenVersion = 0
			return open
		}(),
		"zero flow": func() FlowOpen {
			open := base
			open.FlowID = 0
			return open
		}(),
		"flow kind": func() FlowOpen {
			open := base
			open.FlowKind = 0xff
			return open
		}(),
		"target kind": func() FlowOpen {
			open := base
			open.TargetKind = 0xff
			return open
		}(),
	}
	for name, open := range cases {
		t.Run(name, func(t *testing.T) {
			payload, err := Encode(open)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateFrameBlock(FrameBlock{Frames: []AuroraFrame{{
				FrameType: registry.FrameFlowOpen,
				FlowID:    open.FlowID,
				Payload:   payload,
			}}}); err == nil {
				t.Fatalf("malformed FLOW_OPEN accepted: %+v", open)
			}
		})
	}
}

func TestValidateUDPTargetConfirmRejectsMalformedTarget(t *testing.T) {
	base := UDPTargetConfirm{
		FlowID:           10,
		TargetKind:       0x01,
		SelectedIP:       []byte{203, 0, 113, 10},
		SelectedPort:     443,
		DNSAnswerSetHash: bytes.Repeat([]byte{0xcc}, 48),
		TTLSeconds:       300,
		ResolutionSource: UDPResolutionRelayRecursiveDNS,
	}
	cases := []UDPTargetConfirm{
		{FlowID: base.FlowID, TargetKind: 0x03, SelectedIP: []byte("example.com"), SelectedPort: base.SelectedPort, DNSAnswerSetHash: base.DNSAnswerSetHash, TTLSeconds: base.TTLSeconds, ResolutionSource: base.ResolutionSource},
		{FlowID: base.FlowID, TargetKind: base.TargetKind, SelectedIP: []byte{203, 0, 113}, SelectedPort: base.SelectedPort, DNSAnswerSetHash: base.DNSAnswerSetHash, TTLSeconds: base.TTLSeconds, ResolutionSource: base.ResolutionSource},
		{FlowID: base.FlowID, TargetKind: base.TargetKind, SelectedIP: base.SelectedIP, SelectedPort: base.SelectedPort, DNSAnswerSetHash: []byte{0xcc}, TTLSeconds: base.TTLSeconds, ResolutionSource: base.ResolutionSource},
		{FlowID: base.FlowID, TargetKind: base.TargetKind, SelectedIP: base.SelectedIP, SelectedPort: base.SelectedPort, DNSAnswerSetHash: base.DNSAnswerSetHash, TTLSeconds: base.TTLSeconds, ResolutionSource: 0xff},
	}
	for _, confirm := range cases {
		if err := ValidateUDPTargetConfirm(confirm); err == nil {
			t.Fatalf("malformed UDP target confirm accepted: %+v", confirm)
		}
	}
}

func bytesReader(encoded []byte) *wire.Reader {
	return wire.NewReader(encoded)
}

func assertProtocolHex(t *testing.T, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded bytes = %x, want %x", got, want)
	}
}
