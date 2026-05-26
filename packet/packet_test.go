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

func TestReceiverRejectsDuplicatePacketNumber(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	protector := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        2,
		Direction:       0,
		KeyPhase:        0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	pkt, err := protector.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	receiver := NewReceiver(ReceiverConfig{Protector: *protector, WindowSize: 64})
	if _, err := receiver.Open(pkt); err != nil {
		t.Fatalf("first packet open failed: %v", err)
	}
	if _, err := receiver.Open(pkt); err == nil {
		t.Fatalf("duplicate packet number accepted")
	}
}

func TestReceiverRejectsPacketsOutsideDrainWindow(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	protector := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        2,
		Direction:       0,
		KeyPhase:        0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	var packets []AuroraPacket
	for i := 0; i < 5; i++ {
		pkt, err := protector.Seal(block)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, pkt)
	}
	receiver := NewReceiver(ReceiverConfig{Protector: *protector, WindowSize: 2})
	for _, pkt := range packets[3:] {
		if _, err := receiver.Open(pkt); err != nil {
			t.Fatalf("new packet open failed: %v", err)
		}
	}
	if _, err := receiver.Open(packets[1]); err == nil {
		t.Fatalf("stale packet outside receiver window accepted")
	}
	if _, err := receiver.Open(packets[2]); err != nil {
		t.Fatalf("out-of-order packet inside receiver window rejected: %v", err)
	}
}

func TestSplit2OnionEntrySeesOnlyOpaqueForwardFrame(t *testing.T) {
	flow := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           100,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte("secret.example"),
		TargetPort:       443,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
	}
	payload, err := protocol.Encode(flow)
	if err != nil {
		t.Fatal(err)
	}
	exitBlock := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameFlowOpen,
		FlowID:    100,
		Payload:   payload,
	}}}
	entry := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 7,
		HopLayer:        0,
		Direction:       0,
		Key:             bytesOf(0x31, 32),
		StaticIV:        bytesOf(0x32, 12),
	}
	exit := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       0,
		Key:             bytesOf(0x41, 32),
		StaticIV:        bytesOf(0x42, 12),
	}
	outer, err := SealSplit2Onion(exitBlock, entry, exit)
	if err != nil {
		t.Fatal(err)
	}
	entryBlock, err := entry.Open(outer)
	if err != nil {
		t.Fatal(err)
	}
	if len(entryBlock.Frames) != 1 || entryBlock.Frames[0].FrameType != registry.FrameRouteForward {
		t.Fatalf("entry did not receive a single route-forward frame: %+v", entryBlock)
	}
	if bytes.Contains(entryBlock.Frames[0].Payload, []byte("secret.example")) {
		t.Fatalf("entry-visible route-forward payload leaked exit flow metadata")
	}
	if _, err := protocol.DecodeFrameBlock(entryBlock.Frames[0].Payload); err == nil {
		t.Fatalf("entry route-forward payload decoded as plaintext frame block")
	}
	inner, err := DecodeForwardedPacket(entryBlock)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := exit.Open(inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Frames) != 1 || opened.Frames[0].FlowID != 100 {
		t.Fatalf("exit did not recover original frame block: %+v", opened)
	}
}

func TestSplit2OnionMaintainsIndependentHopCounters(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	entry := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 8, HopLayer: 0, Key: bytesOf(0x51, 32), StaticIV: bytesOf(0x52, 12)}
	exit := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 8, HopLayer: 1, Key: bytesOf(0x61, 32), StaticIV: bytesOf(0x62, 12)}
	if _, err := SealSplit2Onion(block, entry, exit); err != nil {
		t.Fatal(err)
	}
	if _, err := SealSplit2Onion(block, entry, exit); err != nil {
		t.Fatal(err)
	}
	if entry.NextPacket != 2 || exit.NextPacket != 2 {
		t.Fatalf("entry/exit counters not independent: entry=%d exit=%d", entry.NextPacket, exit.NextPacket)
	}
}

func TestSplit2OnionWrongInnerHopLayerFails(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	entry := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 9, HopLayer: 0, Key: bytesOf(0x71, 32), StaticIV: bytesOf(0x72, 12)}
	exit := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 9, HopLayer: 1, Key: bytesOf(0x81, 32), StaticIV: bytesOf(0x82, 12)}
	outer, err := SealSplit2Onion(block, entry, exit)
	if err != nil {
		t.Fatal(err)
	}
	entryBlock, err := entry.Open(outer)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecodeForwardedPacket(entryBlock)
	if err != nil {
		t.Fatal(err)
	}
	inner.HopLayer = 2
	if _, err := exit.Open(inner); err == nil {
		t.Fatalf("exit accepted forwarded packet with wrong hop layer")
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

func TestProtectorRejectsUnknownReservedFrameType(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: 0x1234}}}
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
	if _, err := p.Open(pkt); err == nil {
		t.Fatalf("unknown reserved frame type accepted")
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
