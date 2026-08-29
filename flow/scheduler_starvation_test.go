package flow

import "testing"

// A flow that keeps its priority class saturated must not shut the lower
// classes out of the tunnel entirely.
func TestSchedulerDoesNotStarveLowerPriorityClasses(t *testing.T) {
	s := NewScheduler(SchedulerOptions{MaxBufferedBytes: 1 << 20})
	if err := s.Enqueue(StreamChunk{FlowID: 2, PriorityClass: PriorityInteractive, Data: []byte("interactive")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(StreamChunk{FlowID: 3, PriorityClass: PriorityBulk, Data: []byte("bulk")}); err != nil {
		t.Fatal(err)
	}
	served := make(map[uint64]int)
	for i := 0; i < 32; i++ {
		// The realtime flow always has another chunk ready to send.
		if err := s.Enqueue(StreamChunk{FlowID: 1, PriorityClass: PriorityRealtime, Data: []byte("realtime")}); err != nil {
			t.Fatal(err)
		}
		chunk, ok := s.Next()
		if !ok {
			t.Fatalf("scheduler returned no chunk at iteration %d", i)
		}
		served[chunk.FlowID]++
	}
	if served[2] == 0 {
		t.Fatalf("interactive flow starved by the realtime flood: %v", served)
	}
	if served[3] == 0 {
		t.Fatalf("bulk flow starved by the realtime flood: %v", served)
	}
	if served[1] < 16 {
		t.Fatalf("realtime flow lost its priority share: %v", served)
	}
}
