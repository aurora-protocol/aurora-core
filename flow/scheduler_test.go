package flow

import "testing"

func TestSchedulerPrioritizesInteractiveBeforeBulk(t *testing.T) {
	s := NewScheduler(SchedulerOptions{MaxBufferedBytes: 1024})
	if err := s.Enqueue(StreamChunk{FlowID: 1, PriorityClass: PriorityBulk, Data: []byte("bulk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(StreamChunk{FlowID: 2, PriorityClass: PriorityInteractive, Data: []byte("interactive")}); err != nil {
		t.Fatal(err)
	}
	next, ok := s.Next()
	if !ok {
		t.Fatalf("scheduler returned no chunk")
	}
	if next.FlowID != 2 {
		t.Fatalf("interactive chunk was not scheduled first: %+v", next)
	}
}

func TestSchedulerAppliesBackpressureAndReleasesCapacity(t *testing.T) {
	s := NewScheduler(SchedulerOptions{MaxBufferedBytes: 4})
	if err := s.Enqueue(StreamChunk{FlowID: 1, PriorityClass: PriorityBulk, Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(StreamChunk{FlowID: 2, PriorityClass: PriorityBulk, Data: []byte("de")}); err == nil {
		t.Fatalf("scheduler accepted data past buffer limit")
	}
	if _, ok := s.Next(); !ok {
		t.Fatalf("scheduler did not return buffered chunk")
	}
	if err := s.Enqueue(StreamChunk{FlowID: 2, PriorityClass: PriorityBulk, Data: []byte("de")}); err != nil {
		t.Fatalf("scheduler did not release capacity after dequeue: %v", err)
	}
}
