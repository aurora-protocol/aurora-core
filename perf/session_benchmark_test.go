package perf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
)

func TestApplicationSessionAllocations(t *testing.T) {
	client, relay := newPerformanceSessionPair(t, 8, 256<<10)
	defer client.Close()
	defer relay.Close()
	block := performanceFrameBlock(t, 1, 1200)
	var runErr error
	allocations := testing.AllocsPerRun(100, func() {
		if runErr != nil {
			return
		}
		if err := client.QueueFrames(context.Background(), block); err != nil {
			runErr = err
			return
		}
		encoded, err := client.NextPacket(context.Background())
		if err != nil {
			runErr = err
			return
		}
		blocks, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
		zeroPerformanceBytes(encoded)
		if err != nil {
			runErr = err
			return
		}
		destroyPerformanceBlocks(blocks)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if allocations > 40 {
		t.Fatalf("application queue/open allocations = %.2f, want <= 40", allocations)
	}
}

func TestRecordRoundTripAllocations(t *testing.T) {
	payload := bytes.Repeat([]byte{0x51}, 1200)
	var encoded bytes.Buffer
	encoded.Grow(len(payload) + 3)
	writer, err := transport.NewRecordWriter(&encoded, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var runErr error
	allocations := testing.AllocsPerRun(100, func() {
		if runErr != nil {
			return
		}
		encoded.Reset()
		if err := writer.Write(payload); err != nil {
			runErr = err
			return
		}
		reader, err := transport.NewRecordReader(bytes.NewReader(encoded.Bytes()), 2048)
		if err != nil {
			runErr = err
			return
		}
		got, err := reader.Read()
		if err != nil {
			runErr = err
			return
		}
		if !bytes.Equal(got, payload) {
			runErr = errors.New("record round trip mismatch")
		}
		zeroPerformanceBytes(got)
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if allocations > 6 {
		t.Fatalf("record round-trip allocations = %.2f, want <= 6", allocations)
	}
}

func BenchmarkApplicationQueueAndOpen1200(b *testing.B) {
	client, relay := newPerformanceSessionPair(b, 8, 256<<10)
	defer client.Close()
	defer relay.Close()
	block := performanceFrameBlock(b, 1, 1200)
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.QueueFrames(context.Background(), block); err != nil {
			b.Fatal(err)
		}
		encoded, err := client.NextPacket(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		blocks, err := relay.HandlePacket(context.Background(), time.Now(), encoded)
		zeroPerformanceBytes(encoded)
		if err != nil {
			b.Fatal(err)
		}
		destroyPerformanceBlocks(blocks)
	}
}

func BenchmarkApplicationBidirectional64K(b *testing.B) {
	client, relay := newPerformanceSessionPair(b, 8, 2<<20)
	defer client.Close()
	defer relay.Close()
	clientBlock := performanceFrameBlock(b, 1, 64<<10)
	relayBlock := performanceFrameBlock(b, 2, 64<<10)
	b.SetBytes(2 * 64 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.QueueFrames(context.Background(), clientBlock); err != nil {
			b.Fatal(err)
		}
		if err := relay.QueueFrames(context.Background(), relayBlock); err != nil {
			b.Fatal(err)
		}
		clientPacket, err := client.NextPacket(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		relayPacket, err := relay.NextPacket(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		relayBlocks, relayErr := relay.HandlePacket(context.Background(), time.Now(), clientPacket)
		clientBlocks, clientErr := client.HandlePacket(context.Background(), time.Now(), relayPacket)
		zeroPerformanceBytes(clientPacket)
		zeroPerformanceBytes(relayPacket)
		if relayErr != nil {
			b.Fatal(relayErr)
		}
		if clientErr != nil {
			b.Fatal(clientErr)
		}
		destroyPerformanceBlocks(relayBlocks)
		destroyPerformanceBlocks(clientBlocks)
	}
}

func BenchmarkRecordRoundTrip1200(b *testing.B) {
	payload := bytes.Repeat([]byte{0x52}, 1200)
	var encoded bytes.Buffer
	encoded.Grow(len(payload) + 3)
	writer, err := transport.NewRecordWriter(&encoded, 2048)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded.Reset()
		if err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
		reader, err := transport.NewRecordReader(bytes.NewReader(encoded.Bytes()), 2048)
		if err != nil {
			b.Fatal(err)
		}
		got, err := reader.Read()
		if err != nil {
			b.Fatal(err)
		}
		zeroPerformanceBytes(got)
	}
}

func BenchmarkPacketDuplexParallel(b *testing.B) {
	client, relay := newPerformanceSessionPair(b, 4096, 64<<20)
	defer client.Close()
	defer relay.Close()
	clientToRelayReader, clientToRelayWriter := io.Pipe()
	relayToClientReader, relayToClientWriter := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var received atomic.Int64
	var failure atomic.Pointer[benchmarkFailure]
	handler := func(_ context.Context, _ protocol.FrameBlock) error {
		received.Add(1)
		return nil
	}
	pumpResults := make(chan error, 2)
	runPump := func(run func() error) {
		err := run()
		if err != nil && !errors.Is(err, context.Canceled) {
			failure.CompareAndSwap(nil, &benchmarkFailure{err: err})
			cancel()
		}
		pumpResults <- err
	}
	go runPump(func() error {
		return transport.RunPacketDuplex(ctx, relayToClientReader, clientToRelayWriter, client, func(context.Context, protocol.FrameBlock) error { return nil }, 2048)
	})
	go runPump(func() error {
		return transport.RunPacketDuplex(ctx, clientToRelayReader, relayToClientWriter, relay, handler, 2048)
	})
	block := performanceFrameBlock(b, 1, 1200)
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for {
				if failure.Load() != nil {
					return
				}
				err := client.QueueFrames(ctx, block)
				if err == nil {
					break
				}
				if errors.Is(err, session.ErrBackpressure) {
					runtime.Gosched()
					continue
				}
				failure.CompareAndSwap(nil, &benchmarkFailure{err: err})
				cancel()
				return
			}
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for failure.Load() == nil && received.Load() < int64(b.N) {
		if time.Now().After(deadline) {
			failure.CompareAndSwap(nil, &benchmarkFailure{err: errors.New("duplex receive deadline exceeded")})
			cancel()
			break
		}
		runtime.Gosched()
	}
	b.StopTimer()
	cancel()
	for i := 0; i < 2; i++ {
		err := <-pumpResults
		if err != nil && !errors.Is(err, context.Canceled) {
			failure.CompareAndSwap(nil, &benchmarkFailure{err: err})
		}
	}
	if failed := failure.Load(); failed != nil {
		b.Fatalf("duplex benchmark failed after receiving %d of %d packets: %v", received.Load(), b.N, failed.err)
	}
}

type benchmarkFailure struct{ err error }

type performanceTesting interface {
	Helper()
	Fatal(...any)
}

func newPerformanceSessionPair(t performanceTesting, queuePackets, queueBytes int) (*session.Application, *session.Application) {
	t.Helper()
	forward := session.DirectionConfig{
		Direction: 0,
		Secret:    bytes.Repeat([]byte{0x61}, 48),
		Key:       bytes.Repeat([]byte{0x62}, 32),
		IV:        bytes.Repeat([]byte{0x63}, 12),
	}
	backward := session.DirectionConfig{
		Direction: 1,
		Secret:    bytes.Repeat([]byte{0x71}, 48),
		Key:       bytes.Repeat([]byte{0x72}, 32),
		IV:        bytes.Repeat([]byte{0x73}, 12),
	}
	defer destroyPerformanceDirection(&forward)
	defer destroyPerformanceDirection(&backward)
	limits := session.Limits{
		MaxQueuedPackets:       queuePackets,
		MaxQueuedBytes:         queueBytes,
		ControlReservedPackets: 2,
		ControlReservedBytes:   8 << 10,
		ReplayWindow:           1024,
	}
	client, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x61,
		HopLayer:        1,
		Write:           forward,
		Read:            backward,
		Limits:          limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x61,
		HopLayer:        1,
		Write:           backward,
		Read:            forward,
		Limits:          limits,
	})
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	return client, relay
}

func performanceFrameBlock(t performanceTesting, flowID uint64, payloadBytes int) protocol.FrameBlock {
	t.Helper()
	payload := bytes.Repeat([]byte{0x81}, payloadBytes)
	frame, err := protocol.NewStreamDataFrame(flowID, payload, 0)
	zeroPerformanceBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
}

func destroyPerformanceBlocks(blocks []protocol.FrameBlock) {
	for i := range blocks {
		for j := range blocks[i].Frames {
			zeroPerformanceBytes(blocks[i].Frames[j].Payload)
		}
	}
}

func destroyPerformanceDirection(direction *session.DirectionConfig) {
	zeroPerformanceBytes(direction.Secret)
	zeroPerformanceBytes(direction.Key)
	zeroPerformanceBytes(direction.IV)
	*direction = session.DirectionConfig{}
}

func zeroPerformanceBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
