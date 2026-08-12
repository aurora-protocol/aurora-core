package flow

import (
	"bytes"
	"testing"
)

func BenchmarkSchedulerEnqueueDequeue1200(b *testing.B) {
	chunk := StreamChunk{
		FlowID:        7,
		PriorityClass: PriorityInteractive,
		Data:          bytes.Repeat([]byte{0x5a}, 1200),
	}
	scheduler := NewScheduler(SchedulerOptions{MaxBufferedBytes: 1200})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := scheduler.Enqueue(chunk); err != nil {
			b.Fatal(err)
		}
		dequeued, ok := scheduler.Next()
		if !ok || len(dequeued.Data) != 1200 {
			b.Fatal("scheduler dequeue failed")
		}
	}
}
