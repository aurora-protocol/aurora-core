package session

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestNewApplicationRejectsInvalidConfig(t *testing.T) {
	client, _ := testApplicationConfigs()

	cases := map[string]func(*Config){
		"unsupported suite": func(cfg *Config) {
			cfg.Suite = 0x1234
		},
		"reserved write direction": func(cfg *Config) {
			cfg.Write.Direction = 2
		},
		"matching directions": func(cfg *Config) {
			cfg.Read.Direction = cfg.Write.Direction
		},
		"short write secret": func(cfg *Config) {
			cfg.Write.Secret = cfg.Write.Secret[:47]
		},
		"short read key": func(cfg *Config) {
			cfg.Read.Key = cfg.Read.Key[:31]
		},
		"short write IV": func(cfg *Config) {
			cfg.Write.IV = cfg.Write.IV[:11]
		},
		"partial limits": func(cfg *Config) {
			cfg.Limits = Limits{MaxQueuedPackets: 8}
		},
		"partial rekey policy": func(cfg *Config) {
			cfg.Rekey = RekeyPolicy{MaxAge: time.Minute}
		},
		"negative rekey age": func(cfg *Config) {
			cfg.Rekey = RekeyPolicy{MaxAge: -time.Minute, MaxBytes: 1, MaxPackets: 1}
		},
		"too many packets": func(cfg *Config) {
			cfg.Limits.MaxQueuedPackets = 4097
		},
		"too few reserved packets": func(cfg *Config) {
			cfg.Limits.ControlReservedPackets = 1
		},
		"reserved bytes reach maximum": func(cfg *Config) {
			cfg.Limits.ControlReservedBytes = cfg.Limits.MaxQueuedBytes
		},
		"small replay window": func(cfg *Config) {
			cfg.Limits.ReplayWindow = 63
		},
		"typed nil entropy source": func(cfg *Config) {
			var source *blockingNonceReader
			cfg.Entropy = source
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := cloneConfig(client)
			mutate(&cfg)
			if app, err := NewApplication(cfg); err == nil || app != nil {
				t.Fatalf("NewApplication() = %v, %v; want nil application and error", app, err)
			}
		})
	}
}

func TestNewApplicationNormalizesDefaultPolicies(t *testing.T) {
	client, _ := testApplicationConfigs()
	client.Limits = Limits{}

	app, err := NewApplication(client)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	want := Limits{
		MaxQueuedPackets:       256,
		MaxQueuedBytes:         4 << 20,
		ControlReservedPackets: 2,
		ControlReservedBytes:   16 << 10,
		ReplayWindow:           1024,
	}
	if app.limits != want {
		t.Fatalf("default limits = %+v, want %+v", app.limits, want)
	}
	wantRekey := RekeyPolicy{
		MaxAge:     30 * time.Minute,
		MaxBytes:   8 << 30,
		MaxPackets: (1 << 32) - (1 << 16),
	}
	if app.rekey != wantRekey {
		t.Fatalf("default rekey policy = %+v, want %+v", app.rekey, wantRekey)
	}
}

func TestApplicationOwnsConfigurationMaterial(t *testing.T) {
	clientConfig, relayConfig := testApplicationConfigs()
	relay, err := NewApplication(relayConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client, err := NewApplication(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	zeroDirectionConfig(&clientConfig.Write)
	zeroDirectionConfig(&clientConfig.Read)

	want := testFrameBlock(t, 1, []byte("owned material"))
	if err := client.QueueFrames(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	encoded, err := client.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opened, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, []protocol.FrameBlock{want}) {
		t.Fatalf("opened blocks = %#v, want %#v", opened, []protocol.FrameBlock{want})
	}
}

func TestApplicationTryNextPacketDoesNotBlock(t *testing.T) {
	app, err := NewApplication(testApplicationConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	if packet, err := app.TryNextPacket(); !errors.Is(err, ErrNoPacket) || packet != nil {
		t.Fatalf("TryNextPacket() = %x, %v; want no packet", packet, err)
	}
	block := testFrameBlock(t, 1, []byte("nonblocking packet"))
	if err := app.QueueFrames(context.Background(), block); err != nil {
		t.Fatal(err)
	}
	packet, err := app.TryNextPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) == 0 {
		t.Fatal("TryNextPacket returned an empty encrypted packet")
	}
	if packet, err := app.TryNextPacket(); !errors.Is(err, ErrNoPacket) || packet != nil {
		t.Fatalf("TryNextPacket after drain = %x, %v; want no packet", packet, err)
	}
}

func TestApplicationPrioritizesDNSFramesWithBoundedBurst(t *testing.T) {
	client, relay := newApplicationPair(t)
	defer client.Close()
	defer relay.Close()
	normal := testFrameBlock(t, 1, []byte("queued data"))
	if err := client.QueueFrames(context.Background(), normal); err != nil {
		t.Fatal(err)
	}
	for flowID := uint64(2); flowID <= maximumHighPriorityBurst+2; flowID++ {
		dns, err := protocol.NewDNSMessageFrame(flowID, []byte{0x12, 0x34, 0x01, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{dns}}); err != nil {
			t.Fatal(err)
		}
	}
	for index := uint64(0); index <= maximumHighPriorityBurst; index++ {
		encoded, err := client.NextPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		wantNumber := index + 1
		if index == maximumHighPriorityBurst {
			wantNumber = 0
		}
		if number := packetNumberForTest(t, encoded); number != wantNumber {
			t.Fatalf("packet %d number = %d, want %d", index, number, wantNumber)
		}
		blocks, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
		if err != nil {
			t.Fatal(err)
		}
		if index < maximumHighPriorityBurst {
			if len(blocks) != 1 || len(blocks[0].Frames) != 1 || blocks[0].Frames[0].FrameType != registry.FrameDNSMessage {
				t.Fatalf("prioritized packet blocks = %#v", blocks)
			}
			continue
		}
		if !reflect.DeepEqual(blocks, []protocol.FrameBlock{normal}) {
			t.Fatalf("fairly scheduled packet blocks = %#v, want %#v", blocks, []protocol.FrameBlock{normal})
		}
	}
}

func TestApplicationRoundTripOwnsFrameInput(t *testing.T) {
	client, relay := newApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	block := testFrameBlock(t, 7, []byte("original frame payload"))
	want := cloneFrameBlockForTest(block)
	if err := client.QueueFrames(context.Background(), block); err != nil {
		t.Fatal(err)
	}
	block.Frames[0].Payload[0] ^= 0xff

	encoded, err := client.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opened, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, []protocol.FrameBlock{want}) {
		t.Fatalf("opened blocks = %#v, want %#v", opened, []protocol.FrameBlock{want})
	}
}

func TestApplicationRejectsReplayAndMetadataMismatch(t *testing.T) {
	metadata := []struct {
		name   string
		mutate func(*packet.AuroraPacket)
	}{
		{
			name: "route",
			mutate: func(pkt *packet.AuroraPacket) {
				pkt.RouteInstanceID++
			},
		},
		{
			name: "direction",
			mutate: func(pkt *packet.AuroraPacket) {
				pkt.Direction = 2
			},
		},
		{
			name: "key phase",
			mutate: func(pkt *packet.AuroraPacket) {
				pkt.KeyPhase++
			},
		},
	}

	for _, tc := range metadata {
		t.Run(tc.name, func(t *testing.T) {
			client, relay := newApplicationPair(t)
			defer client.Close()
			defer relay.Close()

			encoded, want := nextEncodedTestPacket(t, client, 11)
			decoded, err := packet.DecodeAuroraPacket(encoded)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&decoded)
			wrong, err := protocol.Encode(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := relay.HandlePacket(context.Background(), time.Now(), wrong); err == nil {
				t.Fatalf("metadata mismatch was accepted")
			}
			opened, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
			if err != nil {
				t.Fatalf("valid packet after metadata rejection: %v", err)
			}
			if !reflect.DeepEqual(opened, []protocol.FrameBlock{want}) {
				t.Fatalf("opened blocks = %#v, want %#v", opened, []protocol.FrameBlock{want})
			}
		})
	}

	client, relay := newApplicationPair(t)
	defer client.Close()
	defer relay.Close()
	encoded, _ := nextEncodedTestPacket(t, client, 12)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), time.Now(), encoded); err == nil {
		t.Fatalf("packet replay was accepted")
	}
}

func TestApplicationRejectsMalformedAndFailedOpenWithoutReplayMutation(t *testing.T) {
	client, relay := newApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if _, err := relay.HandlePacket(context.Background(), time.Now(), []byte{0}); err == nil {
		t.Fatalf("malformed canonical packet was accepted")
	}
	tooLarge := make([]byte, relay.limits.MaxQueuedBytes+1)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), tooLarge); err == nil {
		t.Fatalf("over-limit packet was accepted")
	}

	encoded, want := nextEncodedTestPacket(t, client, 13)
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := relay.HandlePacket(context.Background(), time.Now(), tampered); err == nil {
		t.Fatalf("tampered packet was accepted")
	}
	opened, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
	if err != nil {
		t.Fatalf("valid packet after failed open: %v", err)
	}
	if !reflect.DeepEqual(opened, []protocol.FrameBlock{want}) {
		t.Fatalf("opened blocks = %#v, want %#v", opened, []protocol.FrameBlock{want})
	}
}

func TestApplicationStagesReadStateUntilPacketOpenSucceeds(t *testing.T) {
	_, relay := newApplicationPair(t)
	defer relay.Close()

	expiredAt := time.Now().Add(-packet.MaxDrainWindow - time.Second)
	update := protocol.KeyUpdate{
		RouteInstanceID: relay.routeInstanceID,
		HopLayer:        relay.hopLayer,
		Direction:       relay.readState.Direction,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeatedByte(0x72, 16),
		UpdateReason:    1,
	}
	result, err := relay.readState.ApplyReceivedUpdateAt(relay.suite, update, nil, expiredAt)
	if err != nil {
		t.Fatal(err)
	}
	result.Destroy()
	before := relay.readState

	protector := packet.Protector{
		Suite:           relay.suite,
		RouteInstanceID: relay.routeInstanceID,
		HopLayer:        relay.hopLayer,
		Direction:       relay.readState.Direction,
		KeyPhase:        relay.readState.KeyPhase,
		Key:             append([]byte(nil), relay.readState.Material.Key...),
		StaticIV:        append([]byte(nil), relay.readState.Material.IV...),
	}
	pkt, err := protector.Seal(testFrameBlock(t, 90, []byte("staged read state")))
	if err != nil {
		t.Fatal(err)
	}
	bad := pkt
	bad.AuthTag = append([]byte(nil), pkt.AuthTag...)
	bad.AuthTag[len(bad.AuthTag)-1] ^= 0x80
	badEncoded, err := protocol.Encode(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), time.Now(), badEncoded); err == nil {
		t.Fatalf("bad packet was accepted")
	}
	if !reflect.DeepEqual(relay.readState, before) {
		t.Fatalf("failed packet mutated live read state")
	}

	encoded, err := protocol.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.HandlePacket(context.Background(), time.Now(), encoded); err != nil {
		t.Fatalf("valid packet after failed open: %v", err)
	}
	if reflect.DeepEqual(relay.readState, before) {
		t.Fatalf("successful packet did not commit read-state expiry")
	}
	if !relay.readState.DrainUntil.IsZero() {
		t.Fatalf("successful packet did not expire the drain state")
	}
}

func TestApplicationRejectsPacketAboveCanonicalDecodeLimit(t *testing.T) {
	_, relayConfig := testApplicationConfigs()
	relayConfig.Limits.MaxQueuedBytes = 32 << 20
	relay, err := NewApplication(relayConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	overLimit := make([]byte, maxPacketCiphertextBytes+maxPacketEncodingOverhead+1)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), overLimit); err == nil || !strings.Contains(err.Error(), "packet exceeds configured limit") {
		t.Fatalf("pre-decode oversized packet error = %v, want configured-limit rejection", err)
	}
}

func TestApplicationMaintainsPacketNumbersAcrossQueueOperations(t *testing.T) {
	client, _ := newApplicationPair(t)
	defer client.Close()

	for i := uint64(0); i < 2; i++ {
		if err := client.QueueFrames(context.Background(), testFrameBlock(t, i+20, []byte("packet number"))); err != nil {
			t.Fatal(err)
		}
	}
	for want := uint64(0); want < 2; want++ {
		encoded, err := client.NextPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := packet.DecodeAuroraPacket(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.PacketNumber != want {
			t.Fatalf("packet number = %d, want %d", decoded.PacketNumber, want)
		}
	}
}

func TestApplicationBackpressureReservesControlCapacityAndDoesNotAdvancePacketNumber(t *testing.T) {
	client, _ := newApplicationPair(t)
	defer client.Close()

	for i := 0; i < 6; i++ {
		if err := client.QueueFrames(context.Background(), testFrameBlock(t, uint64(i+30), []byte("fill packet capacity"))); err != nil {
			t.Fatalf("QueueFrames(%d): %v", i, err)
		}
	}
	if err := client.QueueFrames(context.Background(), testFrameBlock(t, 40, []byte("reserved capacity"))); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("full data queue error = %v, want ErrBackpressure", err)
	}

	encoded, err := client.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := packetNumberForTest(t, encoded); got != 0 {
		t.Fatalf("first packet number after rejected queue = %d, want 0", got)
	}
	if err := client.QueueFrames(context.Background(), testFrameBlock(t, 41, []byte("progress after dequeue"))); err != nil {
		t.Fatalf("QueueFrames after dequeue: %v", err)
	}
	for want := uint64(1); want <= 6; want++ {
		encoded, err := client.NextPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := packetNumberForTest(t, encoded); got != want {
			t.Fatalf("packet number after rejected queue = %d, want %d", got, want)
		}
	}

	byteLimited, _ := newApplicationPair(t)
	defer byteLimited.Close()
	large := bytes.Repeat([]byte{0x5a}, 60<<10)
	if err := byteLimited.QueueFrames(context.Background(), testFrameBlock(t, 50, large)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("byte-limited queue error = %v, want ErrBackpressure", err)
	}
	if err := byteLimited.QueueFrames(context.Background(), testFrameBlock(t, 51, []byte("fits after byte rejection"))); err != nil {
		t.Fatal(err)
	}
	encoded, err = byteLimited.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := packetNumberForTest(t, encoded); got != 0 {
		t.Fatalf("packet number after byte rejection = %d, want 0", got)
	}
}

func TestApplicationStatsTrackCurrentAndPeakQueueUsage(t *testing.T) {
	client, _ := newApplicationPair(t)
	defer client.Close()
	if got := client.Stats(); got != (Stats{}) {
		t.Fatalf("initial stats = %+v, want zero", got)
	}
	if err := client.QueueFrames(context.Background(), testFrameBlock(t, 45, []byte("first stats packet"))); err != nil {
		t.Fatal(err)
	}
	first := client.Stats()
	if first.QueuedPackets != 1 || first.QueuedBytes <= 0 || first.PeakQueuedPackets != 1 || first.PeakQueuedBytes != first.QueuedBytes {
		t.Fatalf("first queue stats = %+v", first)
	}
	if err := client.QueueFrames(context.Background(), testFrameBlock(t, 46, []byte("second stats packet"))); err != nil {
		t.Fatal(err)
	}
	peak := client.Stats()
	if peak.QueuedPackets != 2 || peak.QueuedBytes <= first.QueuedBytes || peak.PeakQueuedPackets != 2 || peak.PeakQueuedBytes != peak.QueuedBytes {
		t.Fatalf("peak queue stats = %+v", peak)
	}
	if _, err := client.NextPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := client.Stats()
	if after.QueuedPackets != 1 || after.QueuedBytes >= peak.QueuedBytes || after.PeakQueuedPackets != peak.PeakQueuedPackets || after.PeakQueuedBytes != peak.PeakQueuedBytes {
		t.Fatalf("dequeue stats = %+v, peak was %+v", after, peak)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := client.Stats(); got.QueuedPackets != 0 || got.QueuedBytes != 0 || got.PeakQueuedPackets != peak.PeakQueuedPackets || got.PeakQueuedBytes != peak.PeakQueuedBytes {
		t.Fatalf("closed stats = %+v, peak was %+v", got, peak)
	}
}

func TestApplicationNextPacketCancellationAndCloseWakeWaiters(t *testing.T) {
	app, err := NewApplication(testApplicationConfig())
	if err != nil {
		t.Fatal(err)
	}

	canceledBase, cancel := context.WithCancel(context.Background())
	canceled := newObservedContext(canceledBase)
	canceledResults := make(chan error, 1)
	go func() {
		_, err := app.NextPacket(canceled)
		canceledResults <- err
	}()
	<-canceled.observed
	requireNoNextPacketResult(t, canceledResults, "cancellation")
	cancel()
	if err := <-canceledResults; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled NextPacket error = %v, want context.Canceled", err)
	}

	const waiters = 8
	observed := make([]*observedContext, 0, waiters)
	results := make(chan error, waiters)
	for range waiters {
		ctx := newObservedContext(context.Background())
		observed = append(observed, ctx)
		go func() {
			_, err := app.NextPacket(ctx)
			results <- err
		}()
	}
	for _, ctx := range observed {
		<-ctx.observed
	}
	requireNoNextPacketResult(t, results, "close")
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for range waiters {
		if err := <-results; !errors.Is(err, ErrClosed) {
			t.Fatalf("waiting NextPacket error = %v, want ErrClosed", err)
		}
	}
	if err := app.QueueFrames(context.Background(), testFrameBlock(t, 60, []byte("closed"))); !errors.Is(err, ErrClosed) {
		t.Fatalf("QueueFrames after Close = %v, want ErrClosed", err)
	}
	if _, err := app.HandlePacket(context.Background(), time.Now(), []byte{0}); !errors.Is(err, ErrClosed) {
		t.Fatalf("HandlePacket after Close = %v, want ErrClosed", err)
	}
	requireZeroedApplicationMaterial(t, app)
}

func TestApplicationCloseDestroysDirectionalKeyHistory(t *testing.T) {
	app, err := NewApplication(testApplicationConfig())
	if err != nil {
		t.Fatal(err)
	}
	rotateDirectionStateForClose(t, &app.writeState, app.suite)
	rotateDirectionStateForClose(t, &app.readState, app.suite)

	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	requireDestroyedDirectionState(t, app.writeState)
	requireDestroyedDirectionState(t, app.readState)
}

func TestApplicationQueueDequeueCloseRace(t *testing.T) {
	app, err := NewApplication(testApplicationConfig())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			<-start
			for n := 0; n < 100; n++ {
				err := app.QueueFrames(ctx, testFrameBlock(t, uint64(70+id), []byte("race")))
				if err != nil && !errors.Is(err, ErrBackpressure) && !errors.Is(err, ErrClosed) && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("QueueFrames: %v", err)
					return
				}
			}
		}(i)
	}
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for {
				_, err := app.NextPacket(ctx)
				if err == nil {
					continue
				}
				if !errors.Is(err, ErrClosed) && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("NextPacket: %v", err)
				}
				return
			}
		}()
	}
	close(start)
	time.Sleep(10 * time.Millisecond)
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
}

func testApplicationConfigs() (Config, Config) {
	clientWrite := DirectionConfig{
		Direction: 0,
		Secret:    repeatedByte(0x11, 48),
		Key:       repeatedByte(0x12, 32),
		IV:        repeatedByte(0x13, 12),
	}
	clientRead := DirectionConfig{
		Direction: 1,
		Secret:    repeatedByte(0x21, 48),
		Key:       repeatedByte(0x22, 32),
		IV:        repeatedByte(0x23, 12),
	}
	limits := Limits{
		MaxQueuedPackets:       8,
		MaxQueuedBytes:         64 << 10,
		ControlReservedPackets: 2,
		ControlReservedBytes:   8 << 10,
		ReplayWindow:           64,
	}
	return Config{
			Suite:           registry.SuiteHybrid768AESGCM,
			RouteInstanceID: 0x42,
			HopLayer:        1,
			Write:           cloneDirectionConfigForTest(clientWrite),
			Read:            cloneDirectionConfigForTest(clientRead),
			Limits:          limits,
		}, Config{
			Suite:           registry.SuiteHybrid768AESGCM,
			RouteInstanceID: 0x42,
			HopLayer:        1,
			Write:           cloneDirectionConfigForTest(clientRead),
			Read:            cloneDirectionConfigForTest(clientWrite),
			Limits:          limits,
		}
}

func testApplicationConfig() Config {
	client, _ := testApplicationConfigs()
	return client
}

func newApplicationPair(t *testing.T) (*Application, *Application) {
	t.Helper()
	clientConfig, relayConfig := testApplicationConfigs()
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

func nextEncodedTestPacket(t *testing.T, app *Application, flowID uint64) ([]byte, protocol.FrameBlock) {
	t.Helper()
	want := testFrameBlock(t, flowID, []byte("packet payload"))
	if err := app.QueueFrames(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	encoded, err := app.NextPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return encoded, want
}

func packetNumberForTest(t *testing.T, encoded []byte) uint64 {
	t.Helper()
	pkt, err := packet.DecodeAuroraPacket(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return pkt.PacketNumber
}

func requireNoNextPacketResult(t *testing.T, results <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-results:
		t.Fatalf("empty NextPacket waiter returned before %s: %v", operation, err)
	default:
	}
}

type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func newObservedContext(ctx context.Context) *observedContext {
	return &observedContext{
		Context:  ctx,
		observed: make(chan struct{}),
	}
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.observed)
	})
	return c.Context.Done()
}

func rotateDirectionStateForClose(t *testing.T, state *packet.DirectionState, suite uint64) {
	t.Helper()
	result, err := state.ApplyReceivedUpdateAt(suite, protocol.KeyUpdate{
		RouteInstanceID: state.RouteInstanceID,
		HopLayer:        state.HopLayer,
		Direction:       state.Direction,
		OldKeyPhase:     state.KeyPhase,
		NewKeyPhase:     state.KeyPhase + 1,
		UpdateNonce:     repeatedByte(0x81, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}, repeatedByte(0x82, 16), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	result.Destroy()
}

func requireDestroyedDirectionState(t *testing.T, state packet.DirectionState) {
	t.Helper()
	if state.RouteInstanceID != 0 || state.HopLayer != 0 || state.Direction != 0 || state.KeyPhase != 0 || !state.DrainUntil.IsZero() || len(state.Material.AppSecret) != 0 || len(state.Material.Key) != 0 || len(state.Material.IV) != 0 {
		t.Fatalf("direction state was not destroyed: %+v", state)
	}
}

func testFrameBlock(t *testing.T, flowID uint64, payload []byte) protocol.FrameBlock {
	t.Helper()
	frame, err := protocol.NewStreamDataFrame(flowID, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
}

func cloneConfig(in Config) Config {
	return Config{
		Suite:           in.Suite,
		RouteInstanceID: in.RouteInstanceID,
		HopLayer:        in.HopLayer,
		Write:           cloneDirectionConfigForTest(in.Write),
		Read:            cloneDirectionConfigForTest(in.Read),
		Limits:          in.Limits,
		Rekey:           in.Rekey,
		Entropy:         in.Entropy,
	}
}

func cloneDirectionConfigForTest(in DirectionConfig) DirectionConfig {
	return DirectionConfig{
		Direction: in.Direction,
		Secret:    append([]byte(nil), in.Secret...),
		Key:       append([]byte(nil), in.Key...),
		IV:        append([]byte(nil), in.IV...),
	}
}

func cloneFrameBlockForTest(in protocol.FrameBlock) protocol.FrameBlock {
	out := protocol.FrameBlock{Frames: make([]protocol.AuroraFrame, len(in.Frames))}
	for i, frame := range in.Frames {
		out.Frames[i] = protocol.AuroraFrame{
			FrameType: frame.FrameType,
			FlowID:    frame.FlowID,
			Flags:     frame.Flags,
			Payload:   append([]byte(nil), frame.Payload...),
		}
	}
	return out
}

func zeroDirectionConfig(cfg *DirectionConfig) {
	for _, b := range [][]byte{cfg.Secret, cfg.Key, cfg.IV} {
		for i := range b {
			b[i] = 0
		}
	}
}

func requireZeroedApplicationMaterial(t *testing.T, app *Application) {
	t.Helper()
	for _, b := range [][]byte{
		app.write.Key,
		app.write.StaticIV,
		app.writeState.Material.AppSecret,
		app.writeState.Material.Key,
		app.writeState.Material.IV,
		app.readState.Material.AppSecret,
		app.readState.Material.Key,
		app.readState.Material.IV,
	} {
		for _, v := range b {
			if v != 0 {
				t.Fatalf("application material was not zeroed")
			}
		}
	}
}

func repeatedByte(value byte, length int) []byte {
	return bytes.Repeat([]byte{value}, length)
}
