package flow

import (
	"math"
	"strings"
	"testing"
)

func TestSchedulerBufferLimitFailsClosedWithoutIntegerOverflow(t *testing.T) {
	scheduler := NewScheduler(SchedulerOptions{MaxBufferedBytes: math.MaxInt})
	scheduler.bufferedBytes = math.MaxInt

	err := scheduler.Enqueue(StreamChunk{Data: []byte{1}})
	if err == nil || !strings.Contains(err.Error(), "buffer limit exceeded") {
		t.Fatalf("Enqueue at exhausted maximum error = %v", err)
	}
	if scheduler.bufferedBytes != math.MaxInt || len(scheduler.bulk) != 0 {
		t.Fatal("rejected chunk changed scheduler state")
	}
}

func TestSchedulerReusesDrainedQueueSlotWithoutRetainingChunk(t *testing.T) {
	scheduler := NewScheduler(SchedulerOptions{MaxBufferedBytes: 64})
	chunk := StreamChunk{
		FlowID:        7,
		PriorityClass: PriorityInteractive,
		Data:          []byte("owned packet payload"),
		Flags:         9,
	}
	if err := scheduler.Enqueue(chunk); err != nil {
		t.Fatal(err)
	}
	firstSlot := &scheduler.interactive[0]

	dequeued, ok := scheduler.Next()
	if !ok || string(dequeued.Data) != string(chunk.Data) {
		t.Fatalf("dequeued chunk = %+v, ok = %v", dequeued, ok)
	}
	if len(scheduler.interactive) != 0 || cap(scheduler.interactive) == 0 {
		t.Fatalf("drained queue length/capacity = %d/%d, want 0 with reusable capacity", len(scheduler.interactive), cap(scheduler.interactive))
	}
	cleared := scheduler.interactive[:1][0]
	if cleared.FlowID != 0 || cleared.PriorityClass != 0 || cleared.Data != nil || cleared.Flags != 0 {
		t.Fatalf("drained queue retained chunk fields: %+v", cleared)
	}

	if err := scheduler.Enqueue(chunk); err != nil {
		t.Fatal(err)
	}
	if nextSlot := &scheduler.interactive[0]; nextSlot != firstSlot {
		t.Fatal("drained queue did not reuse its existing storage")
	}
}
