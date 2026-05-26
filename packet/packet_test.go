package packet

import (
	"bytes"
	"testing"
	"time"

	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
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

func TestProtectorUsesChaChaSuiteAEAD(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768ChaCha20,
		RouteInstanceID: 0x43,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Key:             bytesOf(0x35, 32),
		StaticIV:        bytesOf(0x46, 12),
	}
	pkt, err := p.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := protocol.Encode(block)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := auroracrypto.PacketAD(p.Suite, p.RouteInstanceID, p.HopLayer, p.Direction, p.KeyPhase, pkt.PacketNumber)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := auroracrypto.XORNonce96(p.StaticIV, pkt.PacketNumber)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := auroracrypto.SealForSuite(p.Suite, p.Key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt.Ciphertext, sealed[:len(sealed)-16]) || !bytes.Equal(pkt.AuthTag, sealed[len(sealed)-16:]) {
		t.Fatalf("packet seal did not use suite AEAD")
	}
	if _, err := p.Open(pkt); err != nil {
		t.Fatal(err)
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

func TestProtectorRejectsReservedDirectionBeforeSeal(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Direction:       2,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	if _, err := p.Seal(block); err == nil {
		t.Fatalf("reserved packet direction was sealed")
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

func TestReceiverPacketNumbersAreIndependentPerKeyPhase(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	phase0 := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 3,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	phase1 := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 3,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        1,
		Key:             bytesOf(0x55, 32),
		StaticIV:        bytesOf(0x66, 12),
	}
	pkt0, err := phase0.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	pkt1, err := phase1.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	if pkt0.PacketNumber != 0 || pkt1.PacketNumber != 0 {
		t.Fatalf("test requires both phases to start at packet 0: phase0=%d phase1=%d", pkt0.PacketNumber, pkt1.PacketNumber)
	}
	receiver := NewReceiver(ReceiverConfig{Protector: *phase0, WindowSize: 64})
	if _, err := receiver.Open(pkt0); err != nil {
		t.Fatalf("phase 0 packet open failed: %v", err)
	}
	if _, err := receiver.Open(pkt0); err == nil {
		t.Fatalf("duplicate packet number in same key phase accepted")
	}
	receiver.protector = *phase1
	if _, err := receiver.Open(pkt1); err != nil {
		t.Fatalf("same packet number in new key phase rejected: %v", err)
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
	outer, err := SealSplit2Onion(exitBlock, entry, exit, routeForwardForPacketTest(t, 7, 1))
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
	forwardReader := wire.NewReader(entryBlock.Frames[0].Payload)
	forward := protocol.DecodeRouteForwardFrame(forwardReader)
	if forwardReader.Err() != nil || !forwardReader.EOF() {
		t.Fatalf("route-forward payload was not a canonical RouteForwardFrame: err=%v", forwardReader.Err())
	}
	if forward.RouteInstanceID != 7 || forward.HopIndex != 1 {
		t.Fatalf("route-forward metadata did not identify exit hop: %+v", forward)
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

func TestSplit2BackwardOnionClientPeelsEntryThenExitLayers(t *testing.T) {
	exitBlock := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameStreamData,
		FlowID:    100,
		Payload:   []byte("exit response payload"),
	}}}
	entryBackward := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 10,
		HopLayer:        0,
		Direction:       1,
		Key:             bytesOf(0x91, 32),
		StaticIV:        bytesOf(0x92, 12),
	}
	exitBackward := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 10,
		HopLayer:        1,
		Direction:       1,
		Key:             bytesOf(0xa1, 32),
		StaticIV:        bytesOf(0xa2, 12),
	}
	outer, err := SealSplit2BackwardOnion(exitBlock, entryBackward, exitBackward, routeForwardForPacketTest(t, 10, 1))
	if err != nil {
		t.Fatal(err)
	}
	entryBlock, err := entryBackward.Open(outer)
	if err != nil {
		t.Fatal(err)
	}
	if len(entryBlock.Frames) != 1 || entryBlock.Frames[0].FrameType != registry.FrameRouteForward {
		t.Fatalf("backward entry layer did not contain one opaque route frame: %+v", entryBlock)
	}
	if bytes.Contains(entryBlock.Frames[0].Payload, []byte("exit response payload")) {
		t.Fatalf("backward entry-visible payload leaked exit response")
	}
	inner, err := DecodeForwardedPacket(entryBlock)
	if err != nil {
		t.Fatal(err)
	}
	if inner.Direction != 1 || inner.HopLayer != 1 {
		t.Fatalf("backward inner packet metadata = direction %d hop %d", inner.Direction, inner.HopLayer)
	}
	opened, err := exitBackward.Open(inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Frames) != 1 || !bytes.Equal(opened.Frames[0].Payload, []byte("exit response payload")) {
		t.Fatalf("client did not recover backward exit block: %+v", opened)
	}
}

func TestSplit2OnionMaintainsIndependentHopCounters(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	entry := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 8, HopLayer: 0, Key: bytesOf(0x51, 32), StaticIV: bytesOf(0x52, 12)}
	exit := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 8, HopLayer: 1, Key: bytesOf(0x61, 32), StaticIV: bytesOf(0x62, 12)}
	if _, err := SealSplit2Onion(block, entry, exit, routeForwardForPacketTest(t, 8, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := SealSplit2Onion(block, entry, exit, routeForwardForPacketTest(t, 8, 1)); err != nil {
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
	outer, err := SealSplit2Onion(block, entry, exit, routeForwardForPacketTest(t, 9, 1))
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

func TestProtectorRejectsFlowOpenWithUnknownCriticalExtension(t *testing.T) {
	flow := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           21,
		FlowKind:         0x01,
		TargetKind:       0x01,
		TargetHost:       []byte{203, 0, 113, 21},
		TargetPort:       443,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
		Extensions: []protocol.Extension{{
			ExtensionType: 0x7002,
			Critical:      true,
			Body:          []byte("required"),
		}},
	}
	payload, err := protocol.Encode(flow)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameFlowOpen,
		FlowID:    21,
		Payload:   payload,
	}}}
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
		t.Fatalf("flow open with unknown critical extension accepted")
	}
}

func TestProtectorRejectsMalformedDataFrame(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameDatagramData,
		FlowID:    0,
		Payload:   []byte("udp"),
	}}}
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
		t.Fatalf("malformed datagram frame accepted")
	}
}

func TestProtectorRejectsFlowOpenInBackwardDirection(t *testing.T) {
	flow := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           44,
		FlowKind:         0x01,
		TargetKind:       0x01,
		TargetHost:       []byte{93, 184, 216, 34},
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
		FlowID:    44,
		Payload:   payload,
	}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        1,
		Direction:       1,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}
	pkt, err := p.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Open(pkt); err == nil {
		t.Fatalf("backward-direction FLOW_OPEN accepted")
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

func TestDirectionStateApplyReceivedUpdateValidatesStateBeforeMutation(t *testing.T) {
	state := DirectionState{
		RouteInstanceID: 0x42,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material: KeyMaterial{
			AppSecret: bytesOf(0x55, 48),
			Key:       bytesOf(0x56, 32),
			IV:        bytesOf(0x57, 12),
		},
	}
	original := state.Material
	wrongDirection := protocol.KeyUpdate{
		RouteInstanceID: 0x42,
		HopLayer:        1,
		Direction:       1,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xaa, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, wrongDirection, bytesOf(0xbb, 16)); err == nil {
		t.Fatalf("wrong-direction KEY_UPDATE accepted")
	}
	if state.KeyPhase != 0 || !bytes.Equal(state.Material.AppSecret, original.AppSecret) {
		t.Fatalf("wrong-direction KEY_UPDATE mutated state: %+v", state)
	}

	rightDirection := wrongDirection
	rightDirection.Direction = 0
	res, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, rightDirection, bytesOf(0xbc, 16))
	if err != nil {
		t.Fatalf("valid KEY_UPDATE rejected: %v", err)
	}
	if state.KeyPhase != 1 || bytes.Equal(state.Material.AppSecret, original.AppSecret) {
		t.Fatalf("valid KEY_UPDATE did not advance state: %+v", state)
	}
	if res.ACK == nil || res.ACK.AckedDirection != 0 || res.ACK.AckedKeyPhase != 1 {
		t.Fatalf("valid KEY_UPDATE did not produce matching ACK: %+v", res.ACK)
	}
	staleChanged := rightDirection
	staleChanged.UpdateNonce = bytesOf(0xbe, 16)
	if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, staleChanged, bytesOf(0xbd, 16)); err == nil {
		t.Fatalf("stale KEY_UPDATE old phase accepted after state advanced")
	}
}

func TestDirectionStateDuplicateKeyUpdateIsIdempotentOnlyWhileDraining(t *testing.T) {
	state := DirectionState{
		RouteInstanceID: 0x43,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material: KeyMaterial{
			AppSecret: bytesOf(0x61, 48),
			Key:       bytesOf(0x62, 32),
			IV:        bytesOf(0x63, 12),
		},
	}
	update := protocol.KeyUpdate{
		RouteInstanceID: 0x43,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xa1, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	first, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, update, bytesOf(0xb1, 16))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, update, bytesOf(0xb2, 16))
	if err != nil {
		t.Fatalf("byte-identical duplicate KEY_UPDATE was not idempotent: %v", err)
	}
	if state.KeyPhase != 1 {
		t.Fatalf("duplicate KEY_UPDATE advanced state again: %+v", state)
	}
	if duplicate.ACK == nil || !bytes.Equal(duplicate.ACK.AckNonce, first.ACK.AckNonce) {
		t.Fatalf("duplicate KEY_UPDATE produced a different ACK: first=%+v duplicate=%+v", first.ACK, duplicate.ACK)
	}
	changed := update
	changed.UpdateNonce = bytesOf(0xa2, 16)
	if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, changed, bytesOf(0xb3, 16)); err == nil {
		t.Fatalf("non-identical stale KEY_UPDATE was accepted")
	}
	state.DrainUntil = time.Now().Add(-time.Second)
	if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, update, bytesOf(0xb4, 16)); err == nil {
		t.Fatalf("duplicate KEY_UPDATE was accepted after drain expiry")
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

func routeForwardForPacketTest(t *testing.T, routeInstanceID uint64, hopIndex uint8) protocol.RouteForwardFrame {
	t.Helper()
	return protocol.RouteForwardFrame{
		RouteInstanceID:                routeInstanceID,
		HopIndex:                       hopIndex,
		NextRelayDescriptorHash:        bytesOf(0x91, 48),
		PreviousHopRelayDescriptorHash: bytesOf(0x92, 48),
		NextRelayRoutingRecordID:       bytesOf(0x93, 16),
		NextRelayLocatorType:           registry.LocatorAuthority,
		NextRelayLocator:               routeAuthorityLocatorForPacketTest(t, "exit.example", 443),
	}
}

func routeAuthorityLocatorForPacketTest(t *testing.T, authority string, port uint16) []byte {
	t.Helper()
	e := wire.NewEncoder()
	e.WriteOpaque16([]byte(authority))
	e.WriteUint16(port)
	out, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
