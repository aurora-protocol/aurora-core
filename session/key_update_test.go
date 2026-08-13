package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
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
	if client.writeState.KeyPhase != 0 || !client.pendingWriteUpdate || len(client.queue) != client.limits.MaxQueuedPackets-client.limits.ControlReservedPackets+1 {
		t.Fatalf("update did not enter the emission barrier through reserved capacity")
	}
}

func TestApplicationKeyUpdateDrainStartsAtCarrierHandoff(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	defer client.Close()
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if client.writeState.KeyPhase != 0 || !client.writeState.DrainUntil.IsZero() || !client.pendingWriteUpdate {
		t.Fatalf("queued update started its drain before carrier handoff")
	}
	before := time.Now()
	_ = nextApplicationPacket(t, client)
	if client.writeState.KeyPhase != 1 || client.pendingWriteUpdate {
		t.Fatalf("carrier handoff did not commit the queued update")
	}
	if !client.writeState.DrainUntil.After(before.Add(packet.MaxDrainWindow - time.Second)) {
		t.Fatalf("drain deadline did not start at carrier handoff: %s", client.writeState.DrainUntil)
	}
}

func TestApplicationAutomaticRekeyTriggersBeforeDataQueueing(t *testing.T) {
	block := testFrameBlock(t, 102, []byte("automatic rekey payload"))
	reservation, err := encodedPacketReservation(block)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		policy     RekeyPolicy
		queueFirst bool
		expireAge  bool
	}{
		"packet limit": {
			policy:     RekeyPolicy{MaxAge: time.Hour, MaxBytes: 1 << 20, MaxPackets: 1},
			queueFirst: true,
		},
		"byte limit": {
			policy:     RekeyPolicy{MaxAge: time.Hour, MaxBytes: uint64(reservation), MaxPackets: 100},
			queueFirst: true,
		},
		"age limit": {
			policy:    RekeyPolicy{MaxAge: time.Second, MaxBytes: 1 << 20, MaxPackets: 100},
			expireAge: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clientConfig, _ := testApplicationConfigs()
			clientConfig.Rekey = tc.policy
			clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xd2, 64)))
			client, err := NewApplication(clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			if tc.queueFirst {
				if err := client.QueueFrames(context.Background(), block); err != nil {
					t.Fatalf("initial QueueFrames: %v", err)
				}
				_ = nextApplicationPacket(t, client)
			}
			if tc.expireAge {
				client.mu.Lock()
				client.writePhaseStartedAt = time.Now().Add(-2 * tc.policy.MaxAge)
				client.mu.Unlock()
			}

			if err := client.QueueFrames(context.Background(), block); !errors.Is(err, ErrBackpressure) {
				t.Fatalf("triggering QueueFrames error = %v, want ErrBackpressure", err)
			}
			if !client.pendingWriteUpdate || client.writeState.KeyPhase != 0 {
				t.Fatalf("automatic rekey did not enter emission barrier")
			}
			updateHeader := decodeApplicationPacket(t, nextApplicationPacket(t, client))
			if updateHeader.KeyPhase != 0 {
				t.Fatalf("automatic update used phase %d, want 0", updateHeader.KeyPhase)
			}
			if err := client.QueueFrames(context.Background(), block); err != nil {
				t.Fatalf("QueueFrames after automatic update: %v", err)
			}
			dataHeader := decodeApplicationPacket(t, nextApplicationPacket(t, client))
			if dataHeader.KeyPhase != 1 || dataHeader.PacketNumber != 0 {
				t.Fatalf("post-update data phase/number = %d/%d, want 1/0", dataHeader.KeyPhase, dataHeader.PacketNumber)
			}
		})
	}
}

func TestApplicationRejectsPacketLargerThanConfiguredRekeyByteLimit(t *testing.T) {
	block := testFrameBlock(t, 103, []byte("larger than phase budget"))
	reservation, err := encodedPacketReservation(block)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, _ := testApplicationConfigs()
	clientConfig.Rekey = RekeyPolicy{MaxAge: time.Hour, MaxBytes: uint64(reservation - 1), MaxPackets: 100}
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.QueueFrames(context.Background(), block); err == nil || errors.Is(err, ErrBackpressure) {
		t.Fatalf("oversized phase packet error = %v, want non-retryable limit error", err)
	}
	if client.pendingWriteUpdate || len(client.queue) != 0 {
		t.Fatalf("impossible byte budget started a rekey loop")
	}
}

func TestApplicationAutomaticallyUpdatesKeysAtConfiguredLimits(t *testing.T) {
	cases := map[string]func(*Application, int){
		"packet count": func(app *Application, _ int) {
			app.rekey.MaxPackets = 1
		},
		"encoded bytes": func(app *Application, nextReservation int) {
			app.rekey.MaxBytes = app.writePhaseBytes + uint64(nextReservation) - 1
		},
		"phase age": func(app *Application, _ int) {
			app.writePhaseStartedAt = time.Now().Add(-2 * app.rekey.MaxAge)
		},
	}

	for name, reachLimit := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, _ := testApplicationConfigs()
			cfg.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x75, 64)))
			cfg.Rekey = RekeyPolicy{
				MaxAge:     time.Hour,
				MaxBytes:   1 << 20,
				MaxPackets: 100,
			}
			app, err := NewApplication(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()

			first := testFrameBlock(t, 107, []byte("before automatic update"))
			if err := app.QueueFrames(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			second := testFrameBlock(t, 108, []byte("after automatic update"))
			secondReservation, err := encodedPacketReservation(second)
			if err != nil {
				t.Fatal(err)
			}
			reachLimit(app, secondReservation)

			if err := app.QueueFrames(context.Background(), second); !errors.Is(err, ErrBackpressure) {
				t.Fatalf("threshold QueueFrames error = %v, want ErrBackpressure", err)
			}
			if !app.pendingWriteUpdate || app.writeState.KeyPhase != 0 || len(app.queue) != 2 {
				t.Fatalf("threshold did not queue an update behind existing data")
			}

			firstPacket := decodeApplicationPacket(t, nextApplicationPacket(t, app))
			if firstPacket.KeyPhase != 0 || firstPacket.PacketNumber != 0 || !app.pendingWriteUpdate {
				t.Fatalf("pre-update packet phase/number = %d/%d", firstPacket.KeyPhase, firstPacket.PacketNumber)
			}
			updatePacket := decodeApplicationPacket(t, nextApplicationPacket(t, app))
			if updatePacket.KeyPhase != 0 || updatePacket.PacketNumber != 1 || app.pendingWriteUpdate || app.writeState.KeyPhase != 1 {
				t.Fatalf("automatic update handoff state is inconsistent")
			}

			if err := app.QueueFrames(context.Background(), second); err != nil {
				t.Fatalf("retry QueueFrames after automatic update: %v", err)
			}
			secondPacket := decodeApplicationPacket(t, nextApplicationPacket(t, app))
			if secondPacket.KeyPhase != 1 || secondPacket.PacketNumber != 0 {
				t.Fatalf("post-update packet phase/number = %d/%d, want 1/0", secondPacket.KeyPhase, secondPacket.PacketNumber)
			}
		})
	}
}

func TestApplicationPendingKeyUpdateBlocksDataWithoutMutation(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	defer client.Close()
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	beforeNumbers := client.writePacketNumbers
	beforeQueuedBytes := client.queuedBytes

	err := client.QueueFrames(context.Background(), testFrameBlock(t, 109, []byte("must wait for update handoff")))
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("QueueFrames while update pending = %v, want ErrBackpressure", err)
	}
	if client.writePacketNumbers != beforeNumbers || client.queuedBytes != beforeQueuedBytes || len(client.queue) != 1 {
		t.Fatalf("backpressured data mutated packet numbers or queue")
	}
}

func TestApplicationCloseDestroysQueuedKeyUpdate(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	queuedUpdate := client.queue[0].update
	before := queuedUpdate.prepared.Frame()
	defer zeroBytes(before.UpdateNonce)
	if before.NewKeyPhase != 1 || len(before.UpdateNonce) == 0 {
		t.Fatalf("queued update was not prepared")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	after := queuedUpdate.prepared.Frame()
	if !reflect.DeepEqual(after, protocol.KeyUpdate{}) {
		t.Fatalf("close retained staged key update metadata: %+v", after)
	}
	requireTerminalApplication(t, client)
}

func TestApplicationKeyUpdateCommitFailureEmitsNothingAndTerminates(t *testing.T) {
	client, _ := newKeyUpdateApplicationPair(t)
	defer client.Close()
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	queuedUpdate := client.queue[0].update
	client.writeState.Material.Key[0] ^= 0xff

	if encoded, err := client.NextPacket(context.Background()); err == nil || encoded != nil {
		t.Fatalf("NextPacket after source change = %x, %v; want nil and error", encoded, err)
	}
	if after := queuedUpdate.prepared.Frame(); !reflect.DeepEqual(after, protocol.KeyUpdate{}) {
		t.Fatalf("failed commit retained staged key update metadata: %+v", after)
	}
	requireTerminalApplication(t, client)
}

func TestApplicationKeyUpdateBackpressureAndExhaustionDoNotMutate(t *testing.T) {
	t.Run("control capacity", func(t *testing.T) {
		client, _ := newKeyUpdateApplicationPair(t)
		defer client.Close()
		for i := 0; i < client.limits.MaxQueuedPackets; i++ {
			if err := client.queueBlock(context.Background(), paddingBlock(), true, false); err != nil {
				t.Fatalf("fill control queue %d: %v", i, err)
			}
		}
		before := client.writeState.Clone()
		defer before.Destroy()
		beforeNumbers := client.writePacketNumbers
		beforeRandom := remainingReaderEntropy(t, client.entropy)

		err := client.InitiateKeyUpdate(context.Background(), 1)
		if !errors.Is(err, ErrBackpressure) {
			t.Fatalf("InitiateKeyUpdate() error = %v, want ErrBackpressure", err)
		}
		requireDirectionStateEqual(t, client.writeState, before)
		if client.writePacketNumbers != beforeNumbers {
			t.Fatalf("backpressure advanced packet numbers")
		}
		if remainingReaderEntropy(t, client.entropy) != beforeRandom {
			t.Fatalf("backpressure consumed key-update entropy")
		}
	})

	t.Run("phase exhaustion", func(t *testing.T) {
		client, _ := newKeyUpdateApplicationPair(t)
		defer client.Close()
		client.writeState.KeyPhase = 255
		client.write.KeyPhase = 255
		before := client.writeState.Clone()
		defer before.Destroy()
		beforeRandom := remainingReaderEntropy(t, client.entropy)

		if err := client.InitiateKeyUpdate(context.Background(), 1); err == nil {
			t.Fatalf("phase-exhausted update succeeded")
		}
		requireDirectionStateEqual(t, client.writeState, before)
		if len(client.queue) != 0 {
			t.Fatalf("phase-exhausted update queued a packet")
		}
		if remainingReaderEntropy(t, client.entropy) != beforeRandom {
			t.Fatalf("phase exhaustion consumed key-update entropy")
		}
	})

	t.Run("random source", func(t *testing.T) {
		clientConfig, _ := testApplicationConfigs()
		clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x71, 15)))
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

func TestApplicationKeyUpdateEntropyReadDoesNotHoldSessionLock(t *testing.T) {
	clientConfig, _ := testApplicationConfigs()
	random := newBlockingNonceReader()
	defer random.unblock()
	clientConfig.Entropy = random
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- client.InitiateKeyUpdate(context.Background(), 1)
	}()
	<-random.started

	block := testFrameBlock(t, 130, []byte("queue while entropy blocks"))
	queueResult := make(chan error, 1)
	go func() {
		queueResult <- client.QueueFrames(context.Background(), block)
	}()
	select {
	case err := <-queueResult:
		if err != nil {
			t.Fatalf("QueueFrames while entropy blocked: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("entropy reader held the session lock")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("InitiateKeyUpdate after close = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("Close did not cancel blocked key-update entropy")
	}
}

func TestApplicationKeyUpdateCancellationReleasesBlockedEntropyAndReservation(t *testing.T) {
	clientConfig, _ := testApplicationConfigs()
	random := newBlockingNonceReader()
	defer random.unblock()
	clientConfig.Entropy = random
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- client.InitiateKeyUpdate(ctx, 1)
	}()
	<-random.started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("InitiateKeyUpdate cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("context cancellation did not release blocked key-update entropy")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.reservedPackets != 0 || client.reservedBytes != 0 || client.pendingWriteUpdate || len(client.queue) != 0 {
		t.Fatalf("canceled entropy retained reservation or queued state: packets=%d bytes=%d pending=%v queue=%d", client.reservedPackets, client.reservedBytes, client.pendingWriteUpdate, len(client.queue))
	}
}

func TestApplicationConcurrentReservationsReleaseOnlyTheirOwner(t *testing.T) {
	clientConfig, _ := testApplicationConfigs()
	random := newBlockingNonceReader()
	defer random.unblock()
	clientConfig.Entropy = random
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	wantBytes, err := keyUpdateReservation(client.writeState, 1)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- client.InitiateKeyUpdate(context.Background(), 1)
	}()
	<-random.started
	if err := client.QueueFrames(context.Background(), testFrameBlock(t, 131, []byte("concurrent reservation"))); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	gotPackets, gotBytes := client.reservedPackets, client.reservedBytes
	client.mu.Unlock()
	if gotPackets != 1 || gotBytes != wantBytes {
		t.Fatalf("remaining reservation = %d packets/%d bytes, want 1/%d", gotPackets, gotBytes, wantBytes)
	}
	random.unblock()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
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
		if err := client.QueueFrames(context.Background(), block); !errors.Is(err, ErrSessionControl) {
			t.Fatalf("QueueFrames control 0x%x error = %v, want ErrSessionControl", block.Frames[0].FrameType, err)
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

func TestApplicationReceivedUpdateQueuesACKBeforeLocalUpdate(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := relay.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	relayUpdate := nextApplicationPacket(t, relay)
	if got, err := client.HandlePacket(context.Background(), time.Now(), relayUpdate); err != nil || got != nil {
		t.Fatalf("received update while local update pending = %#v, %v; want nil, nil", got, err)
	}
	if client.terminal != nil || client.readState.KeyPhase != 1 || !client.pendingWriteUpdate || len(client.queue) != 2 {
		t.Fatalf("received update did not preserve the local emission barrier")
	}

	clientACK := nextApplicationPacket(t, client)
	ackHeader := decodeApplicationPacket(t, clientACK)
	if ackHeader.KeyPhase != 0 || ackHeader.PacketNumber != 1 || !client.pendingWriteUpdate || client.writeState.KeyPhase != 0 {
		t.Fatalf("prioritized ACK phase/number = %d/%d", ackHeader.KeyPhase, ackHeader.PacketNumber)
	}
	if got, err := relay.HandlePacket(context.Background(), time.Now(), clientACK); err != nil || got != nil {
		t.Fatalf("HandlePacket(prioritized ACK) = %#v, %v; want nil, nil", got, err)
	}
	if !relay.writeState.DrainUntil.IsZero() {
		t.Fatalf("prioritized ACK did not finish the peer write drain")
	}

	localUpdate := nextApplicationPacket(t, client)
	localHeader := decodeApplicationPacket(t, localUpdate)
	if localHeader.KeyPhase != 0 || localHeader.PacketNumber != 0 {
		t.Fatalf("local update phase/number = %d/%d, want 0/0", localHeader.KeyPhase, localHeader.PacketNumber)
	}
	if got, err := relay.HandlePacket(context.Background(), time.Now(), localUpdate); err != nil || got != nil {
		t.Fatalf("HandlePacket(local update) = %#v, %v; want nil, nil", got, err)
	}
	if client.writeState.KeyPhase != 1 || relay.readState.KeyPhase != 1 {
		t.Fatalf("local update did not advance both endpoints")
	}
}

func TestApplicationKeyUpdateACKBackpressureLeavesReplayRetryable(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	for i := 0; i < relay.limits.MaxQueuedPackets; i++ {
		if err := relay.queueBlock(context.Background(), paddingBlock(), true, false); err != nil {
			t.Fatalf("fill relay queue %d: %v", i, err)
		}
	}
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	updatePacket := nextApplicationPacket(t, client)
	beforeRandom := remainingReaderEntropy(t, relay.entropy)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), updatePacket); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("ACK backpressure error = %v, want ErrBackpressure", err)
	}
	if relay.terminal != nil || relay.readState.KeyPhase != 0 {
		t.Fatalf("retryable ACK backpressure terminated or mutated the session")
	}
	if remainingReaderEntropy(t, relay.entropy) != beforeRandom {
		t.Fatalf("ACK backpressure consumed acknowledgement entropy")
	}
	_ = nextApplicationPacket(t, relay)
	if got, err := relay.HandlePacket(context.Background(), time.Now(), updatePacket); err != nil || got != nil {
		t.Fatalf("retry after capacity release = %#v, %v; want nil, nil", got, err)
	}
	if relay.readState.KeyPhase != 1 {
		t.Fatalf("retry did not commit the received update")
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
			ownedFrames := make([]protocol.AuroraFrame, len(frames))
			for i, frame := range frames {
				ownedFrames[i] = frame
				ownedFrames[i].Payload = append([]byte(nil), frame.Payload...)
			}
			block := protocol.FrameBlock{Frames: ownedFrames}
			controls, err := scanKeyControls(&block)
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

func TestApplicationAppliesMixedKeyUpdateAndACKAtomically(t *testing.T) {
	for name, updateFirst := range map[string]bool{
		"update then ack": true,
		"ack then update": false,
	} {
		t.Run(name, func(t *testing.T) {
			client, relay := newKeyUpdateApplicationPair(t)
			defer client.Close()
			defer relay.Close()
			if err := relay.InitiateKeyUpdate(context.Background(), 1); err != nil {
				t.Fatal(err)
			}
			_ = nextApplicationPacket(t, relay)

			update := protocol.KeyUpdate{
				RouteInstanceID: client.routeInstanceID,
				HopLayer:        client.hopLayer,
				Direction:       client.write.Direction,
				OldKeyPhase:     0,
				NewKeyPhase:     1,
				UpdateNonce:     repeatedByte(0xc3, 16),
				AckRequired:     true,
				UpdateReason:    1,
			}
			ack := protocol.KeyUpdateACK{
				RouteInstanceID: relay.routeInstanceID,
				HopLayer:        relay.hopLayer,
				AckedDirection:  relay.write.Direction,
				AckedKeyPhase:   relay.writeState.KeyPhase,
				AckNonce:        repeatedByte(0xc4, 16),
			}
			updateFrame := keyUpdateBlock(t, update).Frames[0]
			ackFrame := keyUpdateACKBlock(t, ack).Frames[0]
			frames := []protocol.AuroraFrame{ackFrame, updateFrame}
			if updateFirst {
				frames[0], frames[1] = frames[1], frames[0]
			}
			write := cloneApplicationProtector(client.write)
			defer destroyApplicationProtector(&write)
			encoded := sealApplicationPacket(t, &write, protocol.FrameBlock{Frames: frames})

			if got, err := relay.HandlePacket(context.Background(), time.Now(), encoded); err != nil || got != nil {
				t.Fatalf("HandlePacket(mixed controls) = %#v, %v; want nil, nil", got, err)
			}
			if relay.readState.KeyPhase != 1 || !relay.writeState.DrainUntil.IsZero() || len(relay.queue) != 1 {
				t.Fatalf("mixed controls did not atomically update read and acknowledge write")
			}
			response := decodeApplicationPacket(t, nextApplicationPacket(t, relay))
			if response.KeyPhase != 1 || response.PacketNumber != 0 {
				t.Fatalf("mixed-control response phase/number = %d/%d, want 1/0", response.KeyPhase, response.PacketNumber)
			}
		})
	}
}

func TestScanKeyControlsRejectsDuplicateStateChangingControls(t *testing.T) {
	update := protocol.KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0xc5, 16),
	}
	ack := protocol.KeyUpdateACK{
		RouteInstanceID: 7,
		HopLayer:        1,
		AckedDirection:  1,
		AckedKeyPhase:   1,
	}
	for name, frame := range map[string]protocol.AuroraFrame{
		"updates":          keyUpdateBlock(t, update).Frames[0],
		"acknowledgements": keyUpdateACKBlock(t, ack).Frames[0],
	} {
		t.Run(name, func(t *testing.T) {
			block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame, frame}}
			if _, err := scanKeyControls(&block); err == nil {
				t.Fatalf("duplicate %s succeeded", name)
			}
		})
	}
}

func TestKeyControlsDestroyZeroesCopiedFramePayloads(t *testing.T) {
	payload := []byte("copied application payload")
	controls := keyControls{frames: []protocol.AuroraFrame{{Payload: payload}}}
	controls.Destroy()
	for _, value := range payload {
		if value != 0 {
			t.Fatalf("destroy retained copied frame payload")
		}
	}
	if controls.frames != nil {
		t.Fatalf("destroy retained frame metadata")
	}
}

func TestApplicationConsumesRepeatedValidKeyUpdateRequests(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()
	requestPayload, err := protocol.Encode(protocol.KeyUpdateRequest{
		RouteInstanceID:    client.routeInstanceID,
		HopLayer:           client.hopLayer,
		RequestedDirection: relay.write.Direction,
		RequestNonce:       repeatedByte(0xc6, 16),
		RequestReason:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.AuroraFrame{FrameType: registry.FrameKeyUpdateRequest, Payload: requestPayload}
	write := cloneApplicationProtector(client.write)
	defer destroyApplicationProtector(&write)
	encoded := sealApplicationPacket(t, &write, protocol.FrameBlock{Frames: []protocol.AuroraFrame{request, request}})

	if got, err := relay.HandlePacket(context.Background(), time.Now(), encoded); err != nil || got != nil {
		t.Fatalf("HandlePacket(repeated requests) = %#v, %v; want nil, nil", got, err)
	}
	if relay.readState.KeyPhase != 0 || len(relay.queue) != 0 {
		t.Fatalf("advisory requests mutated key state or queued a response")
	}
}

func TestApplicationKeyUpdateACKRandomFailureLeavesReplayRetryable(t *testing.T) {
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayRandom := bytes.NewBuffer(repeatedByte(0xa1, 15))
	relayConfig.Entropy = newReaderEntropy(relayRandom)
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

	updatePacket := nextApplicationPacket(t, client)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), updatePacket); err == nil {
		t.Fatalf("ACK random failure succeeded")
	}
	if relay.terminal != nil || relay.readState.KeyPhase != 0 {
		t.Fatalf("retryable ACK random failure terminated or mutated the session")
	}
	if _, err := relayRandom.Write(repeatedByte(0xa2, 16)); err != nil {
		t.Fatal(err)
	}
	if got, err := relay.HandlePacket(context.Background(), time.Now(), updatePacket); err != nil || got != nil {
		t.Fatalf("retry after random refill = %#v, %v; want nil, nil", got, err)
	}
	if relay.readState.KeyPhase != 1 {
		t.Fatalf("retry did not commit the received update")
	}
}

func TestApplicationLostKeyUpdateACKExpiresIdleDrainAndReplayState(t *testing.T) {
	clock := newManualApplicationClock(time.Now())
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xa1, 256)))
	client, err := newApplicationWithClock(clientConfig, clock)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newApplicationWithClock(relayConfig, clock)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	updatePacket := nextApplicationPacket(t, client)
	if got, err := relay.HandlePacket(context.Background(), clock.Now(), updatePacket); err != nil || got != nil {
		t.Fatalf("HandlePacket(update) = %#v, %v; want nil, nil", got, err)
	}
	if client.writeState.DrainUntil.IsZero() || relay.readState.DrainUntil.IsZero() {
		t.Fatalf("key update did not start both drain windows")
	}
	before := relay.receiver.Stats()
	if before.PacketNumberSpaces != 1 || before.SeenPackets != 1 {
		t.Fatalf("receiver state before expiry = %+v, want one packet in one space", before)
	}

	clock.Advance(packet.MaxDrainWindow + time.Nanosecond)
	if !client.writeState.DrainUntil.IsZero() || !relay.readState.DrainUntil.IsZero() {
		t.Fatalf("idle drain retained expired traffic keys")
	}
	if after := relay.receiver.Stats(); after.PacketNumberSpaces != 0 || after.SeenPackets != 0 {
		t.Fatalf("receiver state after expiry = %+v, want empty", after)
	}
}

func TestApplicationDelayedReadDrainPurgesReplayBeforeNextUpdate(t *testing.T) {
	clock := newManualApplicationClock(time.Now())
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xa1, 256)))
	client, err := newApplicationWithClock(clientConfig, clock)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newApplicationWithClock(relayConfig, clock)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), clock.Now(), nextApplicationPacket(t, client)); err != nil {
		t.Fatal(err)
	}
	clock.AdvanceWithoutCallbacks(packet.MaxDrainWindow + time.Nanosecond)
	if err := client.InitiateKeyUpdate(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), clock.Now(), nextApplicationPacket(t, client)); err != nil {
		t.Fatal(err)
	}
	if got := relay.receiver.Stats(); got.PacketNumberSpaces != 1 || got.SeenPackets != 1 {
		t.Fatalf("receiver state after delayed drain and next update = %+v, want one current space", got)
	}
}

func TestApplicationConsecutiveReadUpdatesPurgeSupersededReplaySpace(t *testing.T) {
	clock := newManualApplicationClock(time.Now())
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xa1, 256)))
	client, err := newApplicationWithClock(clientConfig, clock)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newApplicationWithClock(relayConfig, clock)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), clock.Now(), nextApplicationPacket(t, client)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HandlePacket(context.Background(), clock.Now(), nextApplicationPacket(t, relay)); err != nil {
		t.Fatal(err)
	}
	if err := client.InitiateKeyUpdate(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), clock.Now(), nextApplicationPacket(t, client)); err != nil {
		t.Fatal(err)
	}
	if got := relay.receiver.Stats(); got.PacketNumberSpaces != 1 || got.SeenPackets != 1 {
		t.Fatalf("receiver state after consecutive updates = %+v, want one current space", got)
	}
}

func TestApplicationDrainTimerDefersWhileAuthenticatedUpdateWaitsForEntropy(t *testing.T) {
	clock := newManualApplicationClock(time.Now())
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xa1, 256)))
	client, err := newApplicationWithClock(clientConfig, clock)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newApplicationWithClock(relayConfig, clock)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	oldWrite := cloneApplicationProtector(client.write)
	defer destroyApplicationProtector(&oldWrite)
	updatePacket := nextApplicationPacket(t, client)
	updateBlock := openApplicationPacket(t, oldWrite, updatePacket)
	defer zeroFrameBlock(updateBlock)
	oldWrite.NextPacket = decodeApplicationPacket(t, updatePacket).PacketNumber + 1
	duplicatePacket := sealApplicationPacket(t, &oldWrite, updateBlock)
	if _, err := relay.HandlePacket(context.Background(), clock.Now(), updatePacket); err != nil {
		t.Fatal(err)
	}

	blockedEntropy := newBlockingNonceReader()
	defer blockedEntropy.unblock()
	relay.mu.Lock()
	relay.entropy = blockedEntropy
	relay.mu.Unlock()
	receivedAt := clock.Now()
	result := make(chan error, 1)
	go func() {
		_, err := relay.HandlePacket(context.Background(), receivedAt, duplicatePacket)
		result <- err
	}()
	awaitSessionSignal(t, blockedEntropy.started, "duplicate update entropy")
	clock.Advance(packet.MaxDrainWindow + time.Nanosecond)
	blockedEntropy.unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("authenticated duplicate update after delayed entropy: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("duplicate update did not finish after entropy release")
	}
	if relay.terminal != nil {
		t.Fatalf("drain timer made authenticated duplicate terminal: %v", relay.terminal)
	}
}

func TestApplicationDrainTimerDefersWriteACKWhileEntropyBlocks(t *testing.T) {
	clock := newManualApplicationClock(time.Now())
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xa1, 256)))
	client, err := newApplicationWithClock(clientConfig, clock)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newApplicationWithClock(relayConfig, clock)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer client.Close()
	defer relay.Close()

	if err := relay.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	_ = nextApplicationPacket(t, relay)
	update := protocol.KeyUpdate{
		RouteInstanceID: client.routeInstanceID,
		HopLayer:        client.hopLayer,
		Direction:       client.write.Direction,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0xd3, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	ack := protocol.KeyUpdateACK{
		RouteInstanceID: relay.routeInstanceID,
		HopLayer:        relay.hopLayer,
		AckedDirection:  relay.write.Direction,
		AckedKeyPhase:   relay.writeState.KeyPhase,
		AckNonce:        repeatedByte(0xd4, 16),
	}
	updateFrame := keyUpdateBlock(t, update).Frames[0]
	ackFrame := keyUpdateACKBlock(t, ack).Frames[0]
	write := cloneApplicationProtector(client.write)
	defer destroyApplicationProtector(&write)
	encoded := sealApplicationPacket(t, &write, protocol.FrameBlock{Frames: []protocol.AuroraFrame{updateFrame, ackFrame}})

	blockedEntropy := newBlockingNonceReader()
	defer blockedEntropy.unblock()
	relay.mu.Lock()
	relay.entropy = blockedEntropy
	relay.mu.Unlock()
	receivedAt := clock.Now()
	result := make(chan error, 1)
	go func() {
		_, err := relay.HandlePacket(context.Background(), receivedAt, encoded)
		result <- err
	}()
	awaitSessionSignal(t, blockedEntropy.started, "mixed control entropy")
	clock.Advance(packet.MaxDrainWindow + time.Nanosecond)
	blockedEntropy.unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("authenticated write acknowledgement after delayed entropy: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("mixed controls did not finish after entropy release")
	}
	if relay.terminal != nil || !relay.writeState.DrainUntil.IsZero() || relay.readState.KeyPhase != 1 {
		t.Fatalf("drain timer invalidated mixed controls: terminal=%v write_drain=%s read_phase=%d", relay.terminal, relay.writeState.DrainUntil, relay.readState.KeyPhase)
	}
}

func TestApplicationCloseCancelsDrainTimers(t *testing.T) {
	clock := newManualApplicationClock(time.Now())
	clientConfig, _ := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	client, err := newApplicationWithClock(clientConfig, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	_ = nextApplicationPacket(t, client)
	if got := clock.ActiveTimers(); got != 1 {
		t.Fatalf("active drain timers = %d, want 1", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := clock.ActiveTimers(); got != 0 {
		t.Fatalf("active drain timers after Close = %d, want 0", got)
	}
}

func newKeyUpdateApplicationPair(t *testing.T) (*Application, *Application) {
	t.Helper()
	clientConfig, relayConfig := testApplicationConfigs()
	clientConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0x91, 256)))
	relayConfig.Entropy = newReaderEntropy(bytes.NewReader(repeatedByte(0xa1, 256)))
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

type blockingNonceReader struct {
	started     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (r *blockingNonceReader) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func newBlockingNonceReader() *blockingNonceReader {
	return &blockingNonceReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *blockingNonceReader) ReadContext(ctx context.Context, p []byte) error {
	r.once.Do(func() { close(r.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.release:
	}
	for i := range p {
		p[i] = 0xd1
	}
	return nil
}

type readerEntropy struct{ reader io.Reader }

func newReaderEntropy(reader io.Reader) *readerEntropy {
	return &readerEntropy{reader: reader}
}

func (r *readerEntropy) ReadContext(ctx context.Context, p []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := io.ReadFull(r.reader, p); err != nil {
		return err
	}
	return ctx.Err()
}

func remainingReaderEntropy(t *testing.T, source EntropySource) int {
	t.Helper()
	reader, ok := source.(*readerEntropy)
	if !ok {
		t.Fatalf("entropy source type = %T, want *readerEntropy", source)
	}
	remaining, ok := reader.reader.(interface{ Len() int })
	if !ok {
		t.Fatalf("entropy reader type = %T, want Len", reader.reader)
	}
	return remaining.Len()
}

type manualApplicationClock struct {
	mu     sync.Mutex
	now    time.Time
	nextID uint64
	timers map[uint64]manualApplicationTimer
}

type manualApplicationTimer struct {
	deadline time.Time
	callback func()
}

func newManualApplicationClock(now time.Time) *manualApplicationClock {
	return &manualApplicationClock{now: now, timers: make(map[uint64]manualApplicationTimer)}
}

func (c *manualApplicationClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualApplicationClock) AfterFunc(delay time.Duration, callback func()) func() bool {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.timers[id] = manualApplicationTimer{deadline: c.now.Add(delay), callback: callback}
	c.mu.Unlock()
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, ok := c.timers[id]; !ok {
			return false
		}
		delete(c.timers, id)
		return true
	}
}

func (c *manualApplicationClock) Advance(elapsed time.Duration) {
	c.AdvanceWithoutCallbacks(elapsed)
	c.RunDueTimers()
}

func (c *manualApplicationClock) AdvanceWithoutCallbacks(elapsed time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(elapsed)
	c.mu.Unlock()
}

func (c *manualApplicationClock) RunDueTimers() {
	for {
		var callback func()
		c.mu.Lock()
		for id, timer := range c.timers {
			if !timer.deadline.After(c.now) {
				callback = timer.callback
				delete(c.timers, id)
				break
			}
		}
		c.mu.Unlock()
		if callback == nil {
			return
		}
		callback()
	}
}

func (c *manualApplicationClock) ActiveTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}
