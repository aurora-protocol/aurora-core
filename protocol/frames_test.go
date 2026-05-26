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
