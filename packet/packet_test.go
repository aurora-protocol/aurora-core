package packet

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestProtectorSealOpen(t *testing.T) {
	flow := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           99,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
	}
	payload, err := protocol.Encode(flow)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameFlowOpen,
		FlowID:    99,
		Payload:   payload,
	}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x42,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	pkt, err := p.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := p.Open(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Frames) != 1 || opened.Frames[0].FlowID != 99 {
		t.Fatalf("unexpected opened frame block: %+v", opened)
	}
}

func TestProtectorRejectsMetadataMismatch(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	pkt, err := p.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	pkt.Direction = 1
	if _, err := p.Open(pkt); err == nil {
		t.Fatalf("expected metadata mismatch to fail")
	}
}

func TestFlowManagementMismatchFailsBeforeMutation(t *testing.T) {
	flow := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           7,
		FlowKind:         0x01,
		TargetKind:       0x01,
		TargetHost:       []byte{127, 0, 0, 1},
		TargetPort:       80,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
	}
	payload, err := protocol.Encode(flow)
	if err != nil {
		t.Fatal(err)
	}
	err = protocol.ValidateFlowManagementFrame(protocol.AuroraFrame{
		FrameType: registry.FrameFlowOpen,
		FlowID:    8,
		Payload:   payload,
	})
	if err == nil {
		t.Fatalf("expected flow_id mismatch to fail")
	}
}

func TestKeyUpdateDerivationAndACK(t *testing.T) {
	frame := protocol.KeyUpdate{
		RouteInstanceID: 0x42,
		HopLayer:        0,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xaa, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	res, err := ApplyReceivedKeyUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x55, 48), frame, bytesOf(0xbb, 16))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Next.Key) != 32 || len(res.Next.IV) != 12 || res.ACK == nil || res.ACK.AckedKeyPhase != 1 {
		t.Fatalf("unexpected key update result: %+v", res)
	}
	frame.NewKeyPhase = 3
	if _, err := ApplyReceivedKeyUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x55, 48), frame, bytesOf(0xbb, 16)); err == nil {
		t.Fatalf("expected skipped phase to fail")
	}
}

func TestAuroraPacketEncodeDecode(t *testing.T) {
	pkt := AuroraPacket{
		RouteInstanceID: 9,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        2,
		PacketNumber:    3,
		Ciphertext:      []byte{1, 2, 3},
		AuthTag:         bytesOf(0xee, 16),
	}
	encoded, err := protocol.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAuroraPacket(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Ciphertext, pkt.Ciphertext) || got.KeyPhase != pkt.KeyPhase || got.PacketNumber != pkt.PacketNumber {
		t.Fatalf("decoded packet mismatch: %+v", got)
	}
}
