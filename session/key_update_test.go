package session

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestApplicationKeyUpdateUsesOldPhaseThenResetsNewPhasePackets(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	updatePacket := nextApplicationPacket(t, client)
	updateHeader := decodeApplicationPacket(t, updatePacket)
	if updateHeader.KeyPhase != 0 || updateHeader.PacketNumber != 0 {
		t.Fatalf("update packet phase/number = %d/%d, want 0/0", updateHeader.KeyPhase, updateHeader.PacketNumber)
	}
	if got, err := relay.HandlePacket(context.Background(), time.Now(), updatePacket); err != nil || got != nil {
		t.Fatalf("HandlePacket(update) = %#v, %v; want nil, nil", got, err)
	}
	if relay.readState.KeyPhase != 1 || client.writeState.KeyPhase != 1 {
		t.Fatalf("key phases after update = client write %d, relay read %d", client.writeState.KeyPhase, relay.readState.KeyPhase)
	}

	want := testFrameBlock(t, 101, []byte("new phase data"))
	if err := client.QueueFrames(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	dataPacket := nextApplicationPacket(t, client)
	dataHeader := decodeApplicationPacket(t, dataPacket)
	if dataHeader.KeyPhase != 1 || dataHeader.PacketNumber != 0 {
		t.Fatalf("new-phase packet phase/number = %d/%d, want 1/0", dataHeader.KeyPhase, dataHeader.PacketNumber)
	}
	got, err := relay.HandlePacket(context.Background(), time.Now(), dataPacket)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []protocol.FrameBlock{want}) {
		t.Fatalf("new-phase blocks = %#v, want %#v", got, []protocol.FrameBlock{want})
	}

	ackPacket := nextApplicationPacket(t, relay)
	ackHeader := decodeApplicationPacket(t, ackPacket)
	if ackHeader.Direction != relay.write.Direction || ackHeader.KeyPhase != relay.write.KeyPhase {
		t.Fatalf("ACK packet direction/phase = %d/%d, want %d/%d", ackHeader.Direction, ackHeader.KeyPhase, relay.write.Direction, relay.write.KeyPhase)
	}
	if got, err := client.HandlePacket(context.Background(), time.Now(), ackPacket); err != nil || got != nil {
		t.Fatalf("HandlePacket(ACK) = %#v, %v; want nil, nil", got, err)
	}
	if !client.writeState.DrainUntil.IsZero() {
		t.Fatalf("ACK did not finish the write drain")
	}
}

func TestApplicationKeyUpdateUsesReservedControlCapacity(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	defer client.Close()

	for i := 0; i < client.limits.MaxQueuedPackets-client.limits.ControlReservedPackets; i++ {
		if err := client.QueueFrames(context.Background(), testFrameBlock(t, uint64(110+i), []byte("fill data queue"))); err != nil {
			t.Fatalf("QueueFrames(%d): %v", i, err)
		}
	}
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatalf("control update did not use reserved capacity: %v", err)
	}
	if client.writeState.KeyPhase != 1 || len(client.queue) != client.limits.MaxQueuedPackets-client.limits.ControlReservedPackets+1 {
		t.Fatalf("update did not commit through reserved capacity")
	}
}

func TestApplicationKeyUpdateBackpressureAndExhaustionDoNotMutate(t *testing.T) {
	t.Run("control capacity", func(t *testing.T) {
		client, _ := newKeyUpdateApplicationPair(t)
		defer client.Close()
		for i := 0; i < client.limits.MaxQueuedPackets; i++ {
			if err := client.queueBlock(context.Background(), paddingBlock(), true); err != nil {
				t.Fatalf("fill control queue %d: %v", i, err)
			}
		}
		before := client.writeState.Clone()
		defer before.Destroy()
		beforeNumbers := client.writePacketNumbers

		err := client.InitiateKeyUpdate(context.Background(), 1)
		if !errors.Is(err, ErrBackpressure) {
			t.Fatalf("InitiateKeyUpdate() error = %v, want ErrBackpressure", err)
		}
		requireDirectionStateEqual(t, client.writeState, before)
		if client.writePacketNumbers != beforeNumbers {
			t.Fatalf("backpressure advanced packet numbers")
		}
	})

	t.Run("phase exhaustion", func(t *testing.T) {
		client, _ := newKeyUpdateApplicationPair(t)
		defer client.Close()
		client.writeState.KeyPhase = 255
		client.write.KeyPhase = 255
		before := client.writeState.Clone()
		defer before.Destroy()

		if err := client.InitiateKeyUpdate(context.Background(), 1); err == nil {
			t.Fatalf("phase-exhausted update succeeded")
		}
		requireDirectionStateEqual(t, client.writeState, before)
		if len(client.queue) != 0 {
			t.Fatalf("phase-exhausted update queued a packet")
		}
	})

	t.Run("random source", func(t *testing.T) {
		clientConfig, _ := testApplicationConfigs()
		clientConfig.Random = bytes.NewReader(repeatedByte(0x71, 15))
		client, err := NewApplication(clientConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		before := client.writeState.Clone()
		defer before.Destroy()

		if err := client.InitiateKeyUpdate(context.Background(), 1); err == nil {
			t.Fatalf("short random source update succeeded")
		}
		requireDirectionStateEqual(t, client.writeState, before)
		if len(client.queue) != 0 {
			t.Fatalf("random failure queued a packet")
		}
	})
}

func TestApplicationQueueFramesRejectsSessionOwnedKeyControlsWithoutMutation(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	defer client.Close()
	update := protocol.KeyUpdate{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		Direction:       client.write.Direction,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0x72, 16),
		UpdateReason:    1,
	}
	ack := protocol.KeyUpdateACK{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		AckedDirection:  client.write.Direction,
		AckedKeyPhase:   1,
		AckNonce:        repeatedByte(0x73, 16),
	}
	requestPayload, err := protocol.Encode(protocol.KeyUpdateRequest{
		RouteInstanceID:    client.routeInstanceID,
		HopLayer:           client.hopLayer,
		RequestedDirection: client.readState.Direction,
		RequestNonce:       repeatedByte(0x74, 16),
		RequestReason:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocks := []protocol.FrameBlock{
		keyUpdateBlock(t, update),
		keyUpdateACKBlock(t, ack),
		{Frames: []protocol.AuroraFrame{{FrameType: registry.FrameKeyUpdateRequest, Payload: requestPayload}}},
	}
	before := client.writeState.Clone()
	defer before.Destroy()
	beforeNumbers := client.writePacketNumbers
	for _, block := range blocks {
		if err := client.QueueFrames(context.Background(), block); err == nil {
			t.Fatalf("QueueFrames accepted session-owned control 0x%x", block.Frames[0].FrameType)
		}
	}
	requireDirectionStateEqual(t, client.writeState, before)
	if len(client.queue) != 0 || client.writePacketNumbers != beforeNumbers {
		t.Fatalf("rejected key control mutated queue or packet numbers")
	}
}

func TestApplicationKeyUpdateDuplicateIsIdempotentAndACKStable(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()
	oldWrite := cloneApplicationProtector(client.write)
	defer destroyApplicationProtector(&oldWrite)
	relayWrite := cloneApplicationProtector(relay.write)
	defer destroyApplicationProtector(&relayWrite)

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	firstEncoded := nextApplicationPacket(t, client)
	firstBlock := openApplicationPacket(t, oldWrite, firstEncoded)
	if got, err := relay.HandlePacket(context.Background(), time.Now(), firstEncoded); err != nil || got != nil {
		t.Fatalf("first update = %#v, %v", got, err)
	}

	oldWrite.NextPacket = 1
	duplicateEncoded := sealApplicationPacket(t, &oldWrite, firstBlock)
	if got, err := relay.HandlePacket(context.Background(), time.Now(), duplicateEncoded); err != nil || got != nil {
		t.Fatalf("duplicate update = %#v, %v", got, err)
	}
	if relay.readState.KeyPhase != 1 {
		t.Fatalf("duplicate update advanced phase to %d", relay.readState.KeyPhase)
	}

	firstACK := decodeACKFromPacket(t, relayWrite, nextApplicationPacket(t, relay))
	relayWrite.NextPacket = 1
	duplicateACK := decodeACKFromPacket(t, relayWrite, nextApplicationPacket(t, relay))
	if !bytes.Equal(firstACK.AckNonce, duplicateACK.AckNonce) {
		t.Fatalf("duplicate update changed ACK nonce")
	}
}

func TestApplicationKeyUpdateRejectsChangedAndStaleControlsTerminally(t *testing.T) {
	t.Run("changed duplicate", func(t *testing.T) {
		client, relay := newKeyUpdateApplicationPair(t)
		defer client.Close()
		oldWrite := cloneApplicationProtector(client.write)
		defer destroyApplicationProtector(&oldWrite)
		if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		first := nextApplicationPacket(t, client)
		if _, err := relay.HandlePacket(context.Background(), time.Now(), first); err != nil {
			t.Fatal(err)
		}
		changed := decodeKeyUpdateFromBlock(t, openApplicationPacket(t, oldWrite, first))
		changed.UpdateNonce[0] ^= 0xff
		oldWrite.NextPacket = 1
		changedPacket := sealApplicationPacket(t, &oldWrite, keyUpdateBlock(t, changed))

		if _, err := relay.HandlePacket(context.Background(), time.Now(), changedPacket); err == nil {
			t.Fatalf("changed duplicate update succeeded")
		}
		requireTerminalApplication(t, relay)
	})

	t.Run("stale acknowledgement", func(t *testing.T) {
		client, relay := newKeyUpdateApplicationPair(t)
		defer client.Close()
		write := cloneApplicationProtector(client.write)
		defer destroyApplicationProtector(&write)
		ack := protocol.KeyUpdateACK{
			RouteInstanceID: client.routeInstanceID,
			HopLayer:        client.hopLayer,
			AckedDirection:  relay.write.Direction,
			AckedKeyPhase:   1,
			AckNonce:        repeatedByte(0x81, 16),
		}
		stalePacket := sealApplicationPacket(t, &write, keyUpdateACKBlock(t, ack))

		if _, err := relay.HandlePacket(context.Background(), time.Now(), stalePacket); err == nil {
			t.Fatalf("stale acknowledgement succeeded")
		}
		requireTerminalApplication(t, relay)
	})

	t.Run("update carried under wrong phase", func(t *testing.T) {
		client, relay := newKeyUpdateApplicationPair(t)
		defer client.Close()
		oldWrite := cloneApplicationProtector(client.write)
		defer destroyApplicationProtector(&oldWrite)
		if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.HandlePacket(context.Background(), time.Now(), nextApplicationPacket(t, client)); err != nil {
			t.Fatal(err)
		}
		wrongPhase := protocol.KeyUpdate{
			RouteInstanceID: client.routeInstanceID,
			HopLayer:        client.hopLayer,
			Direction:       client.write.Direction,
			OldKeyPhase:     1,
			NewKeyPhase:     2,
			UpdateNonce:     repeatedByte(0x83, 16),
			UpdateReason:    1,
		}
		oldWrite.NextPacket = 1
		encoded := sealApplicationPacket(t, &oldWrite, keyUpdateBlock(t, wrongPhase))

		if _, err := relay.HandlePacket(context.Background(), time.Now(), encoded); err == nil {
			t.Fatalf("update encrypted under a phase other than old_key_phase succeeded")
		}
		requireTerminalApplication(t, relay)
	})
}

func TestApplicationKeyUpdateFiltersControlsAndPreservesData(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()
	write := cloneApplicationProtector(client.write)
	defer destroyApplicationProtector(&write)
	update := protocol.KeyUpdate{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		Direction:       client.write.Direction,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0x82, 16),
		AckRequired:     false,
		UpdateReason:    1,
	}
	data := testFrameBlock(t, 120, []byte("mixed control data")).Frames[0]
	block := keyUpdateBlock(t, update)
	block.Frames = append(block.Frames, data)

	got, err := relay.HandlePacket(context.Background(), time.Now(), sealApplicationPacket(t, &write, block))
	if err != nil {
		t.Fatal(err)
	}
	want := []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{data}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered blocks = %#v, want %#v", got, want)
	}
	if len(relay.queue) != 0 {
		t.Fatalf("ack_required=false queued an ACK")
	}
}

func TestApplicationKeyUpdateOppositeDirectionsDoNotBlock(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := relay.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	clientUpdate := nextApplicationPacket(t, client)
	relayUpdate := nextApplicationPacket(t, relay)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), clientUpdate); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HandlePacket(context.Background(), time.Now(), relayUpdate); err != nil {
		t.Fatal(err)
	}
	clientACK := nextApplicationPacket(t, client)
	relayACK := nextApplicationPacket(t, relay)
	if decodeApplicationPacket(t, clientACK).KeyPhase != 1 || decodeApplicationPacket(t, relayACK).KeyPhase != 1 {
		t.Fatalf("simultaneous update ACK was not sent under current write phase")
	}
	if _, err := relay.HandlePacket(context.Background(), time.Now(), clientACK); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HandlePacket(context.Background(), time.Now(), relayACK); err != nil {
		t.Fatal(err)
	}
	if !client.writeState.DrainUntil.IsZero() || !relay.writeState.DrainUntil.IsZero() {
		t.Fatalf("simultaneous update ACKs did not finish both drains")
	}
}

func TestApplicationKeyUpdateACKBackpressureTerminatesSession(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	for i := 0; i < relay.limits.MaxQueuedPackets; i++ {
		if err := relay.queueBlock(context.Background(), paddingBlock(), true); err != nil {
			t.Fatalf("fill relay queue %d: %v", i, err)
		}
	}
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	if _, err := relay.HandlePacket(context.Background(), time.Now(), nextApplicationPacket(t, client)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("ACK backpressure error = %v, want ErrBackpressure", err)
	}
	requireTerminalApplication(t, relay)
}

func TestApplicationQueueFramesRejectsSessionOwnedKeyControls(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	defer client.Close()

	update := protocol.KeyUpdate{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		Direction:       client.write.Direction,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0xb1, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	ack := protocol.KeyUpdateACK{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		AckedDirection:  client.readState.Direction,
		AckedKeyPhase:   1,
		AckNonce:        repeatedByte(0xb2, 16),
	}
	requestPayload, err := protocol.Encode(protocol.KeyUpdateRequest{
		RouteInstanceID:    client.routeInstanceID,
		HopLayer:           client.hopLayer,
		RequestedDirection: client.write.Direction,
		RequestNonce:       repeatedByte(0xb3, 16),
		RequestReason:      1,
	})
	if err != nil {
		t.Fatal(err)
	}

	blocks := map[string]protocol.FrameBlock{
		"update":          keyUpdateBlock(t, update),
		"acknowledgement": keyUpdateACKBlock(t, ack),
		"request": {Frames: []protocol.AuroraFrame{{
			FrameType: registry.FrameKeyUpdateRequest,
			Payload:   requestPayload,
		}}},
	}
	for name, block := range blocks {
		t.Run(name, func(t *testing.T) {
			beforeNumbers := client.writePacketNumbers
			if err := client.QueueFrames(context.Background(), block); !errors.Is(err, ErrSessionControl) {
				t.Fatalf("QueueFrames() error = %v, want ErrSessionControl", err)
			}
			if len(client.queue) != 0 || client.writePacketNumbers != beforeNumbers || client.writeState.KeyPhase != 0 {
				t.Fatalf("rejected key control mutated application state")
			}
		})
	}
}

func TestApplicationAcceptsCanonicalShortKeyUpdateACKNonce(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), time.Now(), nextApplicationPacket(t, client)); err != nil {
		t.Fatal(err)
	}

	ack := protocol.KeyUpdateACK{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		AckedDirection:  client.write.Direction,
		AckedKeyPhase:   client.writeState.KeyPhase,
		AckNonce:        []byte{0x01},
	}
	ackWrite := cloneApplicationProtector(relay.write)
	defer destroyApplicationProtector(&ackWrite)
	ackWrite.NextPacket = relay.writePacketNumbers[ackWrite.KeyPhase]
	encoded := sealApplicationPacket(t, &ackWrite, keyUpdateACKBlock(t, ack))

	if got, err := client.HandlePacket(context.Background(), time.Now(), encoded); err != nil || got != nil {
		t.Fatalf("HandlePacket(short ACK nonce) = %#v, %v; want nil, nil", got, err)
	}
	if !client.writeState.DrainUntil.IsZero() {
		t.Fatalf("short canonical ACK nonce did not finish write drain")
	}
}

func TestScanKeyControlsAcceptsMixedControlsInEitherOrder(t *testing.T) {
	update := protocol.KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0xc1, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	ack := protocol.KeyUpdateACK{
		RouteInstanceID: 7,
		HopLayer:        1,
		AckedDirection:  1,
		AckedKeyPhase:   1,
		AckNonce:        repeatedByte(0xc2, 16),
	}
	updateFrame := keyUpdateBlock(t, update).Frames[0]
	ackFrame := keyUpdateACKBlock(t, ack).Frames[0]

	for name, frames := range map[string][]protocol.AuroraFrame{
		"update then ack": {updateFrame, ackFrame},
		"ack then update": {ackFrame, updateFrame},
	} {
		t.Run(name, func(t *testing.T) {
			controls, err := scanKeyControls(protocol.FrameBlock{Frames: frames})
			if err != nil {
				t.Fatal(err)
			}
			defer controls.Destroy()
			if controls.update == nil || controls.ack == nil || len(controls.frames) != 0 {
				t.Fatalf("mixed controls were not classified atomically: %+v", controls)
			}
		})
	}
}

func TestApplicationKeyUpdateACKRandomFailureTerminatesSession(t *testing.T) {
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Random = bytes.NewReader(repeatedByte(0x91, 256))
	relayConfig.Random = bytes.NewReader(repeatedByte(0xa1, 15))
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewApplication(relayConfig)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	if _, err := relay.HandlePacket(context.Background(), time.Now(), nextApplicationPacket(t, client)); err == nil {
		t.Fatalf("ACK random failure succeeded")
	}
	requireTerminalApplication(t, relay)
}

func newKeyUpdateApplicationPair(t *testing.T) (*Application, *Application) {
	t.Helper()
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Random = bytes.NewReader(repeatedByte(0x91, 256))
	relayConfig.Random = bytes.NewReader(repeatedByte(0xa1, 256))
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewApplication(relayConfig)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	return client, relay
}

func nextApplicationPacket(t *testing.T, app *Application) []byte {
	t.Helper()
	encoded, err := app.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeApplicationPacket(t *testing.T, encoded []byte) packet.AuroraPacket {
	t.Helper()
	pkt, err := packet.DecodeAuroraPacket(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func cloneApplicationProtector(in packet.Protector) packet.Protector {
	in.Key = append([]byte(nil), in.Key...)
	in.StaticIV = append([]byte(nil), in.StaticIV...)
	return in
}

func destroyApplicationProtector(p *packet.Protector) {
	zeroBytes(p.Key)
	zeroBytes(p.StaticIV)
	*p = packet.Protector{}
}

func sealApplicationPacket(t *testing.T, protector *packet.Protector, block protocol.FrameBlock) []byte {
	t.Helper()
	pkt, err := protector.Seal(block)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protocol.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func openApplicationPacket(t *testing.T, protector packet.Protector, encoded []byte) protocol.FrameBlock {
	t.Helper()
	pkt := decodeApplicationPacket(t, encoded)
	block, err := protector.Open(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func keyUpdateBlock(t *testing.T, update protocol.KeyUpdate) protocol.FrameBlock {
	t.Helper()
	payload, err := protocol.Encode(update)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FrameKeyUpdate, Payload: payload}}}
}

func keyUpdateACKBlock(t *testing.T, ack protocol.KeyUpdateACK) protocol.FrameBlock {
	t.Helper()
	payload, err := protocol.Encode(ack)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FrameKeyUpdateAck, Payload: payload}}}
}

func decodeKeyUpdateFromBlock(t *testing.T, block protocol.FrameBlock) protocol.KeyUpdate {
	t.Helper()
	if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameKeyUpdate {
		t.Fatalf("not a single KEY_UPDATE block: %+v", block)
	}
	r := wire.NewReader(block.Frames[0].Payload)
	update := protocol.DecodeKeyUpdate(r)
	if r.Err() != nil || !r.EOF() {
		t.Fatalf("invalid KEY_UPDATE payload: %v", r.Err())
	}
	return update
}

func decodeACKFromPacket(t *testing.T, protector packet.Protector, encoded []byte) protocol.KeyUpdateACK {
	t.Helper()
	block := openApplicationPacket(t, protector, encoded)
	if len(block.Frames) != 1 || block.Frames[0].FrameType != registry.FrameKeyUpdateAck {
		t.Fatalf("not a single KEY_UPDATE_ACK block: %+v", block)
	}
	r := wire.NewReader(block.Frames[0].Payload)
	ack := protocol.DecodeKeyUpdateACK(r)
	if r.Err() != nil || !r.EOF() {
		t.Fatalf("invalid KEY_UPDATE_ACK payload: %v", r.Err())
	}
	return ack
}

func paddingBlock() protocol.FrameBlock {
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}
}

func requireDirectionStateEqual(t *testing.T, got, want packet.DirectionState) {
	t.Helper()
	if got.RouteInstanceID != want.RouteInstanceID || got.HopLayer != want.HopLayer || got.Direction != want.Direction || got.KeyPhase != want.KeyPhase || !got.DrainUntil.Equal(want.DrainUntil) || !bytes.Equal(got.Material.AppSecret, want.Material.AppSecret) || !bytes.Equal(got.Material.Key, want.Material.Key) || !bytes.Equal(got.Material.IV, want.Material.IV) {
		t.Fatalf("direction state changed")
	}
}

func requireTerminalApplication(t *testing.T, app *Application) {
	t.Helper()
	if app.terminal == nil {
		t.Fatalf("application did not enter terminal state")
	}
	if len(app.queue) != 0 || app.queuedBytes != 0 || app.writeState.Material.AppSecret != nil || app.readState.Material.AppSecret != nil {
		t.Fatalf("terminal application retained queue or key material")
	}
	if _, err := app.NextPacket(context.Background()); err == nil {
		t.Fatalf("terminal application emitted a packet")
	}
}
