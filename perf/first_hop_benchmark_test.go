package perf

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/session"
)

func BenchmarkLiveFirstHopApplicationPacket(b *testing.B) {
	client, relay := newPerformanceSessionPair(b, 32, 256<<10)
	defer client.Close()
	defer relay.Close()
	block := performanceFrameBlock(b, 1, 1200)
	ctx := context.Background()
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.QueueFrames(ctx, block); err != nil {
			b.Fatal(err)
		}
		encoded, err := client.NextPacket(ctx)
		if err != nil {
			b.Fatal(err)
		}
		blocks, err := relay.HandlePacket(ctx, time.Now(), encoded)
		zeroPerformanceBytes(encoded)
		if err != nil {
			b.Fatal(err)
		}
		destroyPerformanceBlocks(blocks)
	}
}

func BenchmarkLiveFirstHopApplicationParallel64(b *testing.B) {
	const sessionCount = 64
	type pair struct {
		client *session.Application
		relay  *session.Application
	}
	pairs := make([]pair, sessionCount)
	for i := range pairs {
		pairs[i].client, pairs[i].relay = newPerformanceSessionPair(b, 64, 1<<20)
	}
	defer func() {
		for i := range pairs {
			_ = pairs[i].client.Close()
			_ = pairs[i].relay.Close()
		}
	}()
	block := performanceFrameBlock(b, 1, 1200)
	ctx := context.Background()
	var next atomic.Uint64
	var failure atomic.Pointer[benchmarkFailure]
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(iterations *testing.PB) {
		for iterations.Next() {
			if failure.Load() != nil {
				return
			}
			selected := &pairs[(next.Add(1)-1)%sessionCount]
			if err := selected.client.QueueFrames(ctx, block); err != nil {
				failure.CompareAndSwap(nil, &benchmarkFailure{err: err})
				return
			}
			encoded, err := selected.client.NextPacket(ctx)
			if err != nil {
				failure.CompareAndSwap(nil, &benchmarkFailure{err: err})
				return
			}
			blocks, err := selected.relay.HandlePacket(ctx, time.Now(), encoded)
			zeroPerformanceBytes(encoded)
			if err != nil {
				failure.CompareAndSwap(nil, &benchmarkFailure{err: err})
				return
			}
			destroyPerformanceBlocks(blocks)
		}
	})
	if failed := failure.Load(); failed != nil {
		b.Fatal(failed.err)
	}
}
