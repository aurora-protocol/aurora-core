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

func transactionalDirectionState() DirectionState {
	return DirectionState{
		RouteInstanceID: 0x50,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material: KeyMaterial{
			AppSecret: bytesOf(0x51, 48),
			Key:       bytesOf(0x52, 32),
			IV:        bytesOf(0x53, 12),
		},
	}
}

type directionStateSnapshot struct {
	routeInstanceID uint64
	hopLayer        uint8
	direction       uint8
	keyPhase        uint8
	material        KeyMaterial
	drainUntil      time.Time
	pending         protocol.KeyUpdate
	pendingMaterial KeyMaterial
	pendingActive   bool
}

func snapshotDirectionState(state *DirectionState, now time.Time) directionStateSnapshot {
	pending, pendingMaterial, pendingActive := state.PendingKeyUpdateRetransmission(now)
	return directionStateSnapshot{
		routeInstanceID: state.RouteInstanceID,
		hopLayer:        state.HopLayer,
		direction:       state.Direction,
		keyPhase:        state.KeyPhase,
		material:        cloneKeyMaterial(state.Material),
		drainUntil:      state.DrainUntil,
		pending:         pending,
		pendingMaterial: pendingMaterial,
		pendingActive:   pendingActive,
	}
}

func requireSameDirectionStateSnapshot(t *testing.T, got, want directionStateSnapshot) {
	t.Helper()
	if got.routeInstanceID != want.routeInstanceID || got.hopLayer != want.hopLayer || got.direction != want.direction || got.keyPhase != want.keyPhase || !got.drainUntil.Equal(want.drainUntil) || got.pendingActive != want.pendingActive {
		t.Fatalf("direction state metadata changed")
	}
	if !bytes.Equal(got.material.AppSecret, want.material.AppSecret) || !bytes.Equal(got.material.Key, want.material.Key) || !bytes.Equal(got.material.IV, want.material.IV) {
		t.Fatalf("direction state material changed")
	}
	if got.pending.RouteInstanceID != want.pending.RouteInstanceID || got.pending.HopLayer != want.pending.HopLayer || got.pending.Direction != want.pending.Direction || got.pending.OldKeyPhase != want.pending.OldKeyPhase || got.pending.NewKeyPhase != want.pending.NewKeyPhase || !bytes.Equal(got.pending.UpdateNonce, want.pending.UpdateNonce) || got.pending.AckRequired != want.pending.AckRequired || got.pending.UpdateReason != want.pending.UpdateReason {
		t.Fatalf("pending retransmission frame changed")
	}
	if !bytes.Equal(got.pendingMaterial.AppSecret, want.pendingMaterial.AppSecret) || !bytes.Equal(got.pendingMaterial.Key, want.pendingMaterial.Key) || !bytes.Equal(got.pendingMaterial.IV, want.pendingMaterial.IV) {
		t.Fatalf("pending retransmission material changed")
	}
}

type directDirectionStateSnapshot struct {
	routeInstanceID          uint64
	hopLayer                 uint8
	direction                uint8
	keyPhase                 uint8
	material                 KeyMaterial
	drainUntil               time.Time
	previousKeyPhase         uint8
	previousMaterial         KeyMaterial
	pendingSentUpdateActive  bool
	pendingSentUpdate        protocol.KeyUpdate
	lastReceivedUpdate       []byte
	lastReceivedUpdateResult KeyUpdateResult
}

func snapshotDirectionStateDirect(state *DirectionState) directDirectionStateSnapshot {
	return directDirectionStateSnapshot{
		routeInstanceID:          state.RouteInstanceID,
		hopLayer:                 state.HopLayer,
		direction:                state.Direction,
		keyPhase:                 state.KeyPhase,
		material:                 cloneKeyMaterial(state.Material),
		drainUntil:               state.DrainUntil,
		previousKeyPhase:         state.previousKeyPhase,
		previousMaterial:         cloneKeyMaterial(state.previousMaterial),
		pendingSentUpdateActive:  state.pendingSentUpdateActive,
		pendingSentUpdate:        cloneKeyUpdate(state.pendingSentUpdate),
		lastReceivedUpdate:       append([]byte(nil), state.lastReceivedUpdate...),
		lastReceivedUpdateResult: cloneKeyUpdateResult(state.lastReceivedUpdateResult),
	}
}

func requireSameDirectDirectionStateSnapshot(t *testing.T, got, want directDirectionStateSnapshot) {
	t.Helper()
	if got.routeInstanceID != want.routeInstanceID || got.hopLayer != want.hopLayer || got.direction != want.direction || got.keyPhase != want.keyPhase || !got.drainUntil.Equal(want.drainUntil) || got.previousKeyPhase != want.previousKeyPhase || got.pendingSentUpdateActive != want.pendingSentUpdateActive {
		t.Fatalf("direction state metadata changed")
	}
	if !bytes.Equal(got.material.AppSecret, want.material.AppSecret) || !bytes.Equal(got.material.Key, want.material.Key) || !bytes.Equal(got.material.IV, want.material.IV) || !bytes.Equal(got.previousMaterial.AppSecret, want.previousMaterial.AppSecret) || !bytes.Equal(got.previousMaterial.Key, want.previousMaterial.Key) || !bytes.Equal(got.previousMaterial.IV, want.previousMaterial.IV) {
		t.Fatalf("direction state material changed")
	}
	if got.pendingSentUpdate.RouteInstanceID != want.pendingSentUpdate.RouteInstanceID || got.pendingSentUpdate.HopLayer != want.pendingSentUpdate.HopLayer || got.pendingSentUpdate.Direction != want.pendingSentUpdate.Direction || got.pendingSentUpdate.OldKeyPhase != want.pendingSentUpdate.OldKeyPhase || got.pendingSentUpdate.NewKeyPhase != want.pendingSentUpdate.NewKeyPhase || !bytes.Equal(got.pendingSentUpdate.UpdateNonce, want.pendingSentUpdate.UpdateNonce) || got.pendingSentUpdate.AckRequired != want.pendingSentUpdate.AckRequired || got.pendingSentUpdate.UpdateReason != want.pendingSentUpdate.UpdateReason {
		t.Fatalf("pending sent update changed")
	}
	if !bytes.Equal(got.lastReceivedUpdate, want.lastReceivedUpdate) || !bytes.Equal(got.lastReceivedUpdateResult.Next.AppSecret, want.lastReceivedUpdateResult.Next.AppSecret) || !bytes.Equal(got.lastReceivedUpdateResult.Next.Key, want.lastReceivedUpdateResult.Next.Key) || !bytes.Equal(got.lastReceivedUpdateResult.Next.IV, want.lastReceivedUpdateResult.Next.IV) {
		t.Fatalf("last received update changed")
	}
	if (got.lastReceivedUpdateResult.ACK == nil) != (want.lastReceivedUpdateResult.ACK == nil) {
		t.Fatalf("last received acknowledgement changed")
	}
	if got.lastReceivedUpdateResult.ACK != nil {
		if got.lastReceivedUpdateResult.ACK.RouteInstanceID != want.lastReceivedUpdateResult.ACK.RouteInstanceID || got.lastReceivedUpdateResult.ACK.HopLayer != want.lastReceivedUpdateResult.ACK.HopLayer || got.lastReceivedUpdateResult.ACK.AckedDirection != want.lastReceivedUpdateResult.ACK.AckedDirection || got.lastReceivedUpdateResult.ACK.AckedKeyPhase != want.lastReceivedUpdateResult.ACK.AckedKeyPhase || !bytes.Equal(got.lastReceivedUpdateResult.ACK.AckNonce, want.lastReceivedUpdateResult.ACK.AckNonce) {
			t.Fatalf("last received acknowledgement changed")
		}
	}
}

func sealUncheckedForPacketTest(t *testing.T, p Protector, block protocol.FrameBlock) AuroraPacket {
	t.Helper()
	plaintext, err := protocol.Encode(block)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := auroracrypto.PacketAD(p.Suite, p.RouteInstanceID, p.HopLayer, p.Direction, p.KeyPhase, p.NextPacket)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := auroracrypto.XORNonce96(p.StaticIV, p.NextPacket)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := auroracrypto.SealForSuite(p.Suite, p.Key, nonce, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) < 16 {
		t.Fatalf("sealed payload too short")
	}
	return AuroraPacket{
		RouteInstanceID: p.RouteInstanceID,
		HopLayer:        p.HopLayer,
		Direction:       p.Direction,
		KeyPhase:        p.KeyPhase,
		PacketNumber:    p.NextPacket,
		Ciphertext:      append([]byte(nil), sealed[:len(sealed)-16]...),
		AuthTag:         append([]byte(nil), sealed[len(sealed)-16:]...),
	}
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

func TestDirectionStateCloneOwnsEveryMutableField(t *testing.T) {
	now := time.Now()
	state := transactionalDirectionState()
	update, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x91, 16), true, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, protocol.KeyUpdate{
		RouteInstanceID: state.RouteInstanceID,
		HopLayer:        state.HopLayer,
		Direction:       state.Direction,
		OldKeyPhase:     state.KeyPhase,
		NewKeyPhase:     state.KeyPhase + 1,
		UpdateNonce:     bytesOf(0x92, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}, bytesOf(0x93, 16), now); err != nil {
		t.Fatal(err)
	}
	state.pendingSentUpdate = update
	state.lastReceivedUpdate = bytesOf(0x94, 3)
	clone := state.Clone()
	want := snapshotDirectionStateDirect(&state)

	zeroKeyMaterialForTest(&state.Material)
	zeroKeyMaterialForTest(&state.previousMaterial)
	zeroKeyMaterialForTest(&state.lastReceivedUpdateResult.Next)
	state.pendingSentUpdate.UpdateNonce[0] ^= 0xff
	state.lastReceivedUpdate[0] ^= 0xff
	state.lastReceivedUpdateResult.ACK.AckNonce[0] ^= 0xff

	requireSameDirectDirectionStateSnapshot(t, snapshotDirectionStateDirect(&clone), want)
}

func TestDirectionStateDestroyZeroesMaterialAndClearsState(t *testing.T) {
	state := populatedDirectionStateForDestroy(t)
	held := [][]byte{
		state.Material.AppSecret,
		state.Material.Key,
		state.Material.IV,
		state.previousMaterial.AppSecret,
		state.previousMaterial.Key,
		state.previousMaterial.IV,
		state.lastReceivedUpdateResult.Next.AppSecret,
		state.lastReceivedUpdateResult.Next.Key,
		state.lastReceivedUpdateResult.Next.IV,
		state.pendingSentUpdate.UpdateNonce,
		state.lastReceivedUpdate,
		state.lastReceivedUpdateResult.ACK.AckNonce,
	}

	state.Destroy()

	for _, value := range held {
		for _, b := range value {
			if b != 0 {
				t.Fatalf("destroy did not zero held backing slice")
			}
		}
	}
	if state.RouteInstanceID != 0 || state.HopLayer != 0 || state.Direction != 0 || state.KeyPhase != 0 || !state.DrainUntil.IsZero() || state.pendingSentUpdateActive || state.previousKeyPhase != 0 || len(state.Material.AppSecret) != 0 || len(state.Material.Key) != 0 || len(state.Material.IV) != 0 || len(state.previousMaterial.AppSecret) != 0 || len(state.lastReceivedUpdate) != 0 || state.lastReceivedUpdateResult.ACK != nil {
		t.Fatalf("destroy did not clear direction state: %+v", state)
	}
}

func populatedDirectionStateForDestroy(t *testing.T) DirectionState {
	t.Helper()
	state := transactionalDirectionState()
	if _, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x95, 16), true, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := state.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, protocol.KeyUpdate{
		RouteInstanceID: state.RouteInstanceID,
		HopLayer:        state.HopLayer,
		Direction:       state.Direction,
		OldKeyPhase:     state.KeyPhase,
		NewKeyPhase:     state.KeyPhase + 1,
		UpdateNonce:     bytesOf(0x96, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}, bytesOf(0x97, 16), time.Now()); err != nil {
		t.Fatal(err)
	}
	return state
}

func zeroKeyMaterialForTest(material *KeyMaterial) {
	for _, value := range [][]byte{material.AppSecret, material.Key, material.IV} {
		for i := range value {
			value[i] = 0
		}
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

func TestProtectorRejectsMalformedFrameBlockBeforeSeal(t *testing.T) {
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           7,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
	}
	payload, err := protocol.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameFlowOpen,
		FlowID:    8,
		Payload:   payload,
	}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        1,
		Direction:       0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}

	if _, err := p.Seal(block); err == nil {
		t.Fatalf("malformed frame block was sealed")
	}
	if p.NextPacket != 0 {
		t.Fatalf("malformed frame block advanced packet counter to %d", p.NextPacket)
	}
}

func TestProtectorRejectsNonCanonicalFlowOpenDomainBeforeSeal(t *testing.T) {
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           9,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte("Example.COM"),
		TargetPort:       443,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
	}
	payload, err := protocol.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameFlowOpen,
		FlowID:    open.FlowID,
		Payload:   payload,
	}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}

	if _, err := p.Seal(block); err == nil {
		t.Fatalf("non-canonical FLOW_OPEN domain was sealed")
	}
	if p.NextPacket != 0 {
		t.Fatalf("rejected FLOW_OPEN domain advanced packet counter to %d", p.NextPacket)
	}
}

func TestProtectorRejectsKeyUpdateForOtherDirectionBeforeSeal(t *testing.T) {
	update := protocol.KeyUpdate{
		RouteInstanceID: 0x48,
		HopLayer:        1,
		Direction:       1,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xa8, 16),
		UpdateReason:    1,
	}
	payload, err := protocol.Encode(update)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameKeyUpdate,
		Payload:   payload,
	}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x48,
		HopLayer:        1,
		Direction:       0,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}

	if _, err := p.Seal(block); err == nil {
		t.Fatalf("KEY_UPDATE for other direction was sealed")
	}
	if p.NextPacket != 0 {
		t.Fatalf("rejected KEY_UPDATE advanced packet counter to %d", p.NextPacket)
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

func TestReceiverOpensOldAndNewKeyPhaseOnlyDuringDrain(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	original := KeyMaterial{
		AppSecret: bytesOf(0x21, 48),
		Key:       bytesOf(0x22, 32),
		IV:        bytesOf(0x23, 12),
	}
	state := DirectionState{
		RouteInstanceID: 4,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material:        original,
	}
	update := protocol.KeyUpdate{
		RouteInstanceID: 4,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0x24, 16),
		UpdateReason:    1,
	}
	if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, update, nil); err != nil {
		t.Fatal(err)
	}
	oldProtector := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 4,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Key:             original.Key,
		StaticIV:        original.IV,
	}
	oldDuring, err := oldProtector.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	oldAfterDrain, err := oldProtector.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	newProtector := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 4,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        1,
		Key:             state.Material.Key,
		StaticIV:        state.Material.IV,
	}
	newPacket, err := newProtector.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	receiver := NewReceiver(ReceiverConfig{WindowSize: 64})
	now := time.Now()
	if _, err := receiver.OpenWithDirectionState(oldDuring, &state, registry.SuiteHybrid768AESGCM, now); err != nil {
		t.Fatalf("old-phase packet rejected during drain: %v", err)
	}
	if _, err := receiver.OpenWithDirectionState(newPacket, &state, registry.SuiteHybrid768AESGCM, now); err != nil {
		t.Fatalf("new-phase packet rejected during drain: %v", err)
	}
	state.DrainUntil = time.Now().Add(-time.Second)
	if _, err := receiver.OpenWithDirectionState(oldAfterDrain, &state, registry.SuiteHybrid768AESGCM, time.Now()); err == nil {
		t.Fatalf("old-phase packet accepted after drain expiry")
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

func TestSplit2OnionRejectsMalformedRouteForwardBeforeCounters(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
	cases := map[string]func(protocol.RouteForwardFrame) protocol.RouteForwardFrame{
		"reserved locator": func(forward protocol.RouteForwardFrame) protocol.RouteForwardFrame {
			forward.NextRelayLocatorType = 0x05
			return forward
		},
		"short descriptor hash": func(forward protocol.RouteForwardFrame) protocol.RouteForwardFrame {
			forward.NextRelayDescriptorHash = bytesOf(0x91, 47)
			return forward
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			entry := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 8, HopLayer: 0, Key: bytesOf(0x51, 32), StaticIV: bytesOf(0x52, 12)}
			exit := &Protector{Suite: registry.SuiteHybrid768AESGCM, RouteInstanceID: 8, HopLayer: 1, Key: bytesOf(0x61, 32), StaticIV: bytesOf(0x62, 12)}
			forward := mutate(routeForwardForPacketTest(t, 8, 1))

			if _, err := SealSplit2Onion(block, entry, exit, forward); err == nil {
				t.Fatalf("malformed route-forward metadata was accepted")
			}
			if entry.NextPacket != 0 || exit.NextPacket != 0 {
				t.Fatalf("malformed route-forward advanced counters: entry=%d exit=%d", entry.NextPacket, exit.NextPacket)
			}
		})
	}
}

func TestDecodeForwardedPacketRejectsMalformedRouteForwardMetadata(t *testing.T) {
	inner := AuroraPacket{
		RouteInstanceID: 8,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		PacketNumber:    1,
		Ciphertext:      []byte{0x41},
		AuthTag:         bytesOf(0x42, 16),
	}
	encodedInner, err := protocol.Encode(inner)
	if err != nil {
		t.Fatal(err)
	}
	forward := routeForwardForPacketTest(t, 8, 1)
	forward.NextRelayLocatorType = 0x05
	forward.OpaqueNextHopPrelude = encodedInner
	payload, err := protocol.Encode(forward)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
		FrameType: registry.FrameRouteForward,
		Payload:   payload,
	}}}

	if _, err := DecodeForwardedPacket(block); err == nil {
		t.Fatalf("malformed route-forward metadata was accepted")
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
	pkt := sealUncheckedForPacketTest(t, *p, block)
	if _, err := p.Open(pkt); err == nil {
		t.Fatalf("unknown reserved frame type accepted")
	}
}

func TestProtectorRejectsUnknownLabOnlyFrameTypeBeforeSeal(t *testing.T) {
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: 0x7f00}}}
	p := &Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		Key:             bytesOf(0x33, 32),
		StaticIV:        bytesOf(0x44, 12),
	}

	if _, err := p.Seal(block); err == nil {
		t.Fatalf("unknown lab-only frame type was sealed")
	}
	if p.NextPacket != 0 {
		t.Fatalf("rejected lab-only frame advanced packet counter to %d", p.NextPacket)
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
	pkt := sealUncheckedForPacketTest(t, *p, block)
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
	pkt := sealUncheckedForPacketTest(t, *p, block)
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
	pkt := sealUncheckedForPacketTest(t, *p, block)
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

func TestDirectionStatePrepareDoesNotMutateAndFrameIsOwned(t *testing.T) {
	state := transactionalDirectionState()
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	before := snapshotDirectionState(&state, now)

	prepared, err := state.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa1, 16), true, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	requireSameDirectionStateSnapshot(t, snapshotDirectionState(&state, now), before)

	frame := prepared.Frame()
	frame.UpdateNonce[0] ^= 0xff
	frame.NewKeyPhase = 9
	owned := prepared.Frame()
	if owned.NewKeyPhase != 1 || !bytes.Equal(owned.UpdateNonce, bytesOf(0xa1, 16)) {
		t.Fatalf("prepared frame was changed through a returned clone")
	}

	if err := state.CommitPreparedUpdate(prepared, now); err != nil {
		t.Fatal(err)
	}
	pending, _, active := state.PendingKeyUpdateRetransmission(now)
	if !active || pending.NewKeyPhase != 1 || !bytes.Equal(pending.UpdateNonce, bytesOf(0xa1, 16)) {
		t.Fatalf("commit used a frame changed through a returned clone")
	}
}

func TestDirectionStatePrepareRejectsActiveDrainAndExhaustedPhaseWithoutMutation(t *testing.T) {
	t.Run("active drain", func(t *testing.T) {
		state := transactionalDirectionState()
		if _, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa2, 16), true, 7); err != nil {
			t.Fatal(err)
		}
		now := state.DrainUntil.Add(-time.Second)
		before := snapshotDirectionState(&state, now)
		if _, err := state.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa3, 16), true, 7, now); err == nil {
			t.Fatalf("prepare accepted an active drain")
		}
		requireSameDirectionStateSnapshot(t, snapshotDirectionState(&state, now), before)
	})

	t.Run("exhausted phase", func(t *testing.T) {
		state := transactionalDirectionState()
		state.KeyPhase = 255
		now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
		before := snapshotDirectionState(&state, now)
		if _, err := state.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa4, 16), false, 7, now); err == nil {
			t.Fatalf("prepare accepted an exhausted key phase")
		}
		requireSameDirectionStateSnapshot(t, snapshotDirectionState(&state, now), before)
	})
}

func TestDirectionStatePrepareRejectsExpiredDrainWithoutMutation(t *testing.T) {
	state := transactionalDirectionState()
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	state.KeyPhase = 255
	state.DrainUntil = now.Add(-time.Nanosecond)
	state.previousKeyPhase = 254
	state.previousMaterial = KeyMaterial{
		AppSecret: bytesOf(0x61, 48),
		Key:       bytesOf(0x62, 32),
		IV:        bytesOf(0x63, 12),
	}
	state.pendingSentUpdateActive = true
	state.pendingSentUpdate = protocol.KeyUpdate{
		RouteInstanceID: state.RouteInstanceID,
		HopLayer:        state.HopLayer,
		Direction:       state.Direction,
		OldKeyPhase:     254,
		NewKeyPhase:     255,
		UpdateNonce:     bytesOf(0xa4, 16),
		AckRequired:     true,
		UpdateReason:    7,
	}
	state.lastReceivedUpdate = []byte{1, 2, 3}
	state.lastReceivedUpdateResult = KeyUpdateResult{
		Next: KeyMaterial{
			AppSecret: bytesOf(0x71, 48),
			Key:       bytesOf(0x72, 32),
			IV:        bytesOf(0x73, 12),
		},
		ACK: &protocol.KeyUpdateACK{
			RouteInstanceID: state.RouteInstanceID,
			HopLayer:        state.HopLayer,
			AckedDirection:  state.Direction,
			AckedKeyPhase:   255,
			AckNonce:        bytesOf(0xb4, 16),
		},
	}
	before := snapshotDirectionStateDirect(&state)

	if _, err := state.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xc4, 16), false, 7, now); err == nil {
		t.Fatalf("prepare accepted an exhausted key phase")
	}
	requireSameDirectDirectionStateSnapshot(t, snapshotDirectionStateDirect(&state), before)
}

func TestDirectionStateCommitPreparedUpdateChangesStateExactlyOnce(t *testing.T) {
	state := transactionalDirectionState()
	original := cloneKeyMaterial(state.Material)
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	prepared, err := state.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa5, 16), true, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.CommitPreparedUpdate(prepared, now); err != nil {
		t.Fatal(err)
	}
	if state.KeyPhase != 1 || !state.DrainUntil.Equal(now.Add(MaxDrainWindow)) {
		t.Fatalf("commit did not advance the phase and start the drain window")
	}
	if bytes.Equal(state.Material.AppSecret, original.AppSecret) || bytes.Equal(state.Material.Key, original.Key) || bytes.Equal(state.Material.IV, original.IV) {
		t.Fatalf("commit did not replace active key material")
	}
	pending, pendingMaterial, active := state.PendingKeyUpdateRetransmission(now)
	if !active || pending.OldKeyPhase != 0 || pending.NewKeyPhase != 1 || !bytes.Equal(pending.UpdateNonce, bytesOf(0xa5, 16)) {
		t.Fatalf("commit did not retain the acknowledgement retransmission")
	}
	if !bytes.Equal(pendingMaterial.AppSecret, original.AppSecret) || !bytes.Equal(pendingMaterial.Key, original.Key) || !bytes.Equal(pendingMaterial.IV, original.IV) {
		t.Fatalf("commit did not retain the previous material for retransmission")
	}

	before := snapshotDirectionState(&state, now)
	if err := state.CommitPreparedUpdate(prepared, now); err == nil {
		t.Fatalf("same preparation committed twice")
	}
	requireSameDirectionStateSnapshot(t, snapshotDirectionState(&state, now), before)
}

func TestDirectionStateCommitPreparedUpdateRejectsChangedSourceWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*DirectionState)
	}{
		{"route", func(s *DirectionState) { s.RouteInstanceID++ }},
		{"hop", func(s *DirectionState) { s.HopLayer++ }},
		{"direction", func(s *DirectionState) { s.Direction = 1 }},
		{"phase", func(s *DirectionState) { s.KeyPhase++ }},
		{"app secret", func(s *DirectionState) { s.Material.AppSecret[0] ^= 0xff }},
		{"key", func(s *DirectionState) { s.Material.Key[0] ^= 0xff }},
		{"iv", func(s *DirectionState) { s.Material.IV[0] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := transactionalDirectionState()
			now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
			prepared, err := state.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa6, 16), false, 7, now)
			if err != nil {
				t.Fatal(err)
			}
			test.change(&state)
			before := snapshotDirectionState(&state, now)
			if err := state.CommitPreparedUpdate(prepared, now); err == nil {
				t.Fatalf("commit accepted changed %s source", test.name)
			}
			requireSameDirectionStateSnapshot(t, snapshotDirectionState(&state, now), before)
		})
	}
}

func TestDirectionStatePrepareAndCommitMatchesInitiateUpdate(t *testing.T) {
	legacy := transactionalDirectionState()
	preparedState := transactionalDirectionState()
	legacyFrame, err := legacy.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa7, 16), true, 7)
	if err != nil {
		t.Fatal(err)
	}
	now := legacy.DrainUntil.Add(-MaxDrainWindow)
	prepared, err := preparedState.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa7, 16), true, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	preparedFrame := prepared.Frame()
	if preparedFrame.RouteInstanceID != legacyFrame.RouteInstanceID || preparedFrame.HopLayer != legacyFrame.HopLayer || preparedFrame.Direction != legacyFrame.Direction || preparedFrame.OldKeyPhase != legacyFrame.OldKeyPhase || preparedFrame.NewKeyPhase != legacyFrame.NewKeyPhase || !bytes.Equal(preparedFrame.UpdateNonce, legacyFrame.UpdateNonce) || preparedFrame.AckRequired != legacyFrame.AckRequired || preparedFrame.UpdateReason != legacyFrame.UpdateReason {
		t.Fatalf("prepare produced a different update frame than initiate")
	}
	if err := preparedState.CommitPreparedUpdate(prepared, now); err != nil {
		t.Fatal(err)
	}
	requireSameDirectionStateSnapshot(t, snapshotDirectionState(&preparedState, legacy.DrainUntil), snapshotDirectionState(&legacy, legacy.DrainUntil))
}

func TestDirectionStateApplyReceivedUpdateAtUsesSuppliedTimeAndMatchesLegacyMethod(t *testing.T) {
	frame := protocol.KeyUpdate{
		RouteInstanceID: 0x50,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xa8, 16),
		AckRequired:     true,
		UpdateReason:    7,
	}
	ackNonce := bytesOf(0xb8, 16)

	t.Run("supplied time controls drain", func(t *testing.T) {
		state := transactionalDirectionState()
		now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
		first, err := state.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, ackNonce, now)
		if err != nil {
			t.Fatal(err)
		}
		if !state.DrainUntil.Equal(now.Add(MaxDrainWindow)) {
			t.Fatalf("received update did not use the supplied time for drain expiry")
		}
		duplicate, err := state.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, bytesOf(0xb9, 16), now.Add(MaxDrainWindow))
		if err != nil {
			t.Fatalf("duplicate update at drain boundary was rejected: %v", err)
		}
		if duplicate.ACK == nil || first.ACK == nil || !bytes.Equal(duplicate.ACK.AckNonce, first.ACK.AckNonce) {
			t.Fatalf("duplicate update did not return the original result")
		}
		before := snapshotDirectionState(&state, now.Add(MaxDrainWindow))
		if _, err := state.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, bytesOf(0xba, 16), now.Add(MaxDrainWindow+time.Nanosecond)); err == nil {
			t.Fatalf("duplicate update after drain expiry was accepted")
		}
		requireSameDirectionStateSnapshot(t, snapshotDirectionState(&state, now.Add(MaxDrainWindow)), before)
	})

	t.Run("legacy method", func(t *testing.T) {
		legacy := transactionalDirectionState()
		atState := transactionalDirectionState()
		legacyResult, err := legacy.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, frame, ackNonce)
		if err != nil {
			t.Fatal(err)
		}
		now := legacy.DrainUntil.Add(-MaxDrainWindow)
		atResult, err := atState.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, ackNonce, now)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(atResult.Next.AppSecret, legacyResult.Next.AppSecret) || !bytes.Equal(atResult.Next.Key, legacyResult.Next.Key) || !bytes.Equal(atResult.Next.IV, legacyResult.Next.IV) || atResult.ACK == nil || legacyResult.ACK == nil || !bytes.Equal(atResult.ACK.AckNonce, legacyResult.ACK.AckNonce) {
			t.Fatalf("ApplyReceivedUpdateAt returned a different result than ApplyReceivedUpdate")
		}
		requireSameDirectionStateSnapshot(t, snapshotDirectionState(&atState, legacy.DrainUntil), snapshotDirectionState(&legacy, legacy.DrainUntil))
	})
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

func TestDirectionStateRejectsKeyPhaseWrapBeforeMutation(t *testing.T) {
	t.Run("initiate", func(t *testing.T) {
		state := DirectionState{
			RouteInstanceID: 0x46,
			HopLayer:        1,
			Direction:       0,
			KeyPhase:        255,
			Material: KeyMaterial{
				AppSecret: bytesOf(0x51, 48),
				Key:       bytesOf(0x52, 32),
				IV:        bytesOf(0x53, 12),
			},
		}

		if _, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa6, 16), true, 1); err == nil {
			t.Fatalf("key phase wrap update was initiated")
		}
		if state.KeyPhase != 255 || !state.DrainUntil.IsZero() || state.pendingSentUpdateActive {
			t.Fatalf("key phase wrap mutated send state: %+v", state)
		}
	})

	t.Run("receive", func(t *testing.T) {
		state := DirectionState{
			RouteInstanceID: 0x47,
			HopLayer:        1,
			Direction:       0,
			KeyPhase:        255,
			Material: KeyMaterial{
				AppSecret: bytesOf(0x61, 48),
				Key:       bytesOf(0x62, 32),
				IV:        bytesOf(0x63, 12),
			},
		}
		update := protocol.KeyUpdate{
			RouteInstanceID: 0x47,
			HopLayer:        1,
			Direction:       0,
			OldKeyPhase:     255,
			NewKeyPhase:     0,
			UpdateNonce:     bytesOf(0xa7, 16),
			AckRequired:     true,
			UpdateReason:    1,
		}

		if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, update, bytesOf(0xb7, 16)); err == nil {
			t.Fatalf("key phase wrap update was received")
		}
		if state.KeyPhase != 255 || !state.DrainUntil.IsZero() || len(state.lastReceivedUpdate) != 0 {
			t.Fatalf("key phase wrap mutated receive state: %+v", state)
		}
	})
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

func TestDirectionStateKeepsOldReadMaterialOnlyUntilDrainExpiry(t *testing.T) {
	original := KeyMaterial{
		AppSecret: bytesOf(0x71, 48),
		Key:       bytesOf(0x72, 32),
		IV:        bytesOf(0x73, 12),
	}
	state := DirectionState{
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material:        original,
	}
	update := protocol.KeyUpdate{
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xa4, 16),
		UpdateReason:    1,
	}
	if _, err := state.ApplyReceivedUpdate(registry.SuiteHybrid768AESGCM, update, nil); err != nil {
		t.Fatal(err)
	}
	newMaterial, err := state.MaterialForPacket(AuroraPacket{
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        1,
	}, time.Now())
	if err != nil {
		t.Fatalf("current key phase material rejected: %v", err)
	}
	if bytes.Equal(newMaterial.AppSecret, original.AppSecret) {
		t.Fatalf("current key phase returned old material")
	}
	oldMaterial, err := state.MaterialForPacket(AuroraPacket{
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
	}, time.Now())
	if err != nil {
		t.Fatalf("old key phase was rejected during drain window: %v", err)
	}
	if !bytes.Equal(oldMaterial.Key, original.Key) || !bytes.Equal(oldMaterial.IV, original.IV) {
		t.Fatalf("old key phase did not return previous material")
	}
	state.DrainUntil = time.Now().Add(-time.Second)
	if _, err := state.MaterialForPacket(AuroraPacket{
		RouteInstanceID: 0x44,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
	}, time.Now()); err == nil {
		t.Fatalf("old key phase packet material was accepted after drain expiry")
	}
}

func TestDirectionStateBoundsLostKeyUpdateACKRetransmission(t *testing.T) {
	original := KeyMaterial{
		AppSecret: bytesOf(0x81, 48),
		Key:       bytesOf(0x82, 32),
		IV:        bytesOf(0x83, 12),
	}
	state := DirectionState{
		RouteInstanceID: 0x45,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material:        original,
	}
	sent, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa5, 16), true, 1)
	if err != nil {
		t.Fatal(err)
	}
	retransmit, material, ok := state.PendingKeyUpdateRetransmission(time.Now())
	if !ok {
		t.Fatalf("lost-ACK KEY_UPDATE retransmission was unavailable during drain")
	}
	if retransmit.RouteInstanceID != sent.RouteInstanceID || retransmit.OldKeyPhase != sent.OldKeyPhase || retransmit.NewKeyPhase != sent.NewKeyPhase || !bytes.Equal(retransmit.UpdateNonce, sent.UpdateNonce) {
		t.Fatalf("pending retransmission changed KEY_UPDATE: sent=%+v retransmit=%+v", sent, retransmit)
	}
	if !bytes.Equal(material.Key, original.Key) || !bytes.Equal(material.IV, original.IV) {
		t.Fatalf("pending retransmission did not return old write material")
	}
	if err := state.ApplyKeyUpdateACK(protocol.KeyUpdateACK{
		RouteInstanceID: 0x45,
		HopLayer:        1,
		AckedDirection:  0,
		AckedKeyPhase:   1,
		AckNonce:        bytesOf(0xb5, 16),
	}, time.Now()); err != nil {
		t.Fatalf("valid KEY_UPDATE_ACK rejected: %v", err)
	}
	if _, _, ok := state.PendingKeyUpdateRetransmission(time.Now()); ok {
		t.Fatalf("KEY_UPDATE retransmission remained available after ACK")
	}

	state = DirectionState{
		RouteInstanceID: 0x45,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material:        original,
	}
	if _, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa6, 16), true, 1); err != nil {
		t.Fatal(err)
	}
	state.DrainUntil = time.Now().Add(-time.Second)
	if _, _, ok := state.PendingKeyUpdateRetransmission(time.Now()); ok {
		t.Fatalf("lost-ACK KEY_UPDATE retransmission remained available after drain expiry")
	}
	if err := state.ApplyKeyUpdateACK(protocol.KeyUpdateACK{
		RouteInstanceID: 0x45,
		HopLayer:        1,
		AckedDirection:  0,
		AckedKeyPhase:   1,
		AckNonce:        bytesOf(0xb6, 16),
	}, time.Now()); err == nil {
		t.Fatalf("stale KEY_UPDATE_ACK accepted after drain expiry")
	}
}

func TestDirectionStateRejectsOverlappingWriteKeyUpdates(t *testing.T) {
	original := KeyMaterial{
		AppSecret: bytesOf(0x91, 48),
		Key:       bytesOf(0x92, 32),
		IV:        bytesOf(0x93, 12),
	}
	state := DirectionState{
		RouteInstanceID: 0x46,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material:        original,
	}
	first, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa7, 16), true, 1)
	if err != nil {
		t.Fatal(err)
	}
	phase1Material := cloneKeyMaterial(state.Material)
	if _, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa8, 16), true, 1); err == nil {
		t.Fatalf("second KEY_UPDATE was initiated while phase %d was still draining", first.OldKeyPhase)
	}
	if state.KeyPhase != 1 || !bytes.Equal(state.Material.AppSecret, phase1Material.AppSecret) {
		t.Fatalf("rejected overlapping update mutated active state: %+v", state)
	}
	if retransmit, _, ok := state.PendingKeyUpdateRetransmission(time.Now()); !ok || !bytes.Equal(retransmit.UpdateNonce, first.UpdateNonce) {
		t.Fatalf("rejected overlapping update replaced pending retransmission: %+v ok=%v", retransmit, ok)
	}
	state.DrainUntil = time.Now().Add(-time.Second)
	second, err := state.InitiateUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa9, 16), false, 1)
	if err != nil {
		t.Fatalf("second KEY_UPDATE after drain expiry was rejected: %v", err)
	}
	if second.OldKeyPhase != 1 || second.NewKeyPhase != 2 || state.KeyPhase != 2 {
		t.Fatalf("second KEY_UPDATE used wrong phases: frame=%+v state=%+v", second, state)
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
