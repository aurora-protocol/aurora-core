package flow

// Adversarial white-box coverage for four branches of flow/scheduler.go that
// the existing scheduler_test.go suite never reaches. scheduler.go is pure
// stdlib (only "fmt") and every branch below is driven directly with crafted
// StreamChunk inputs — no network, no goroutine, no clock.
//
// Targets covered:
//
//   - Enqueue:29-31 — the `len(chunk.Data) == 0` guard. The existing suite
//     always enqueues non-empty Data, so "empty stream chunk" is unreached.
//   - Enqueue:42-43 — the PriorityRealtime case. The existing suite only
//     enqueues bulk and interactive chunks, so the realtime append branch is
//     unreached.
//   - Next:55-58 — the realtime-dequeue branch. The existing suite never
//     enqueues a realtime chunk, so popChunk(&s.realtime) is never the winning
//     branch (the interactive/bulk branches at 59/63 are covered instead).
//   - Next:67 — the empty-queue return. The existing suite always calls Next()
//     with at least one queued chunk, so the final `return StreamChunk{}, false`
//     is unreached.
//
// The PriorityInteractive case (44-45), the default/PriorityBulk case (46-48),
// the buffer-limit guard (32-33), and the interactive/bulk dequeue branches
// (59-61, 63-65) are all covered by the existing
// TestSchedulerPrioritizesInteractiveBeforeBulk and
// TestSchedulerAppliesBackpressureAndReleasesCapacity; they are not retried.
//
// No new package-level helpers or types are introduced (only test functions),
// so there is nothing for staticcheck U1000. No context.Context (no SA1012
// surface), no goroutines, no real network or filesystem.

import (
	"strings"
	"testing"
)

func TestSchedulerRejectsEmptyStreamChunk(t *testing.T) {
	s := NewScheduler(SchedulerOptions{MaxBufferedBytes: 1024})
	// An empty Data slice hits the first guard before the priority switch.
	if err := s.Enqueue(StreamChunk{FlowID: 1, PriorityClass: PriorityRealtime}); err == nil ||
		!strings.Contains(err.Error(), "empty stream chunk") {
		t.Fatalf("Enqueue(empty) err = %v, want substring \"empty stream chunk\"", err)
	}
	// A nil Data slice must hit the same guard.
	if err := s.Enqueue(StreamChunk{FlowID: 1, Data: nil}); err == nil ||
		!strings.Contains(err.Error(), "empty stream chunk") {
		t.Fatalf("Enqueue(nil data) err = %v, want substring \"empty stream chunk\"", err)
	}
}

func TestSchedulerPrioritizesRealtimeBeforeInteractiveAndBulk(t *testing.T) {
	// Enqueue one of each priority. The realtime case (Enqueue:42-43) is
	// exercised by the first Enqueue, and the realtime-dequeue branch
	// (Next:55-58) is exercised by the first Next() — realtime must come out
	// before interactive and bulk.
	s := NewScheduler(SchedulerOptions{MaxBufferedBytes: 1024})
	if err := s.Enqueue(StreamChunk{FlowID: 1, PriorityClass: PriorityBulk, Data: []byte("bulk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(StreamChunk{FlowID: 2, PriorityClass: PriorityInteractive, Data: []byte("interactive")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(StreamChunk{FlowID: 3, PriorityClass: PriorityRealtime, Data: []byte("realtime")}); err != nil {
		t.Fatal(err)
	}
	next, ok := s.Next()
	if !ok {
		t.Fatalf("scheduler returned no chunk")
	}
	if next.FlowID != 3 || next.PriorityClass != PriorityRealtime {
		t.Fatalf("realtime chunk was not scheduled first: %+v", next)
	}
	// Sanity: interactive and bulk follow in priority order.
	if next, ok := s.Next(); !ok || next.FlowID != 2 {
		t.Fatalf("interactive chunk was not scheduled second: %+v ok=%v", next, ok)
	}
	if next, ok := s.Next(); !ok || next.FlowID != 1 {
		t.Fatalf("bulk chunk was not scheduled third: %+v ok=%v", next, ok)
	}
}

func TestSchedulerNextReturnsFalseWhenEmpty(t *testing.T) {
	// Next() on a fresh scheduler with no queued chunks reaches the final
	// `return StreamChunk{}, false` (Next:67), after popChunk returns false for
	// all three queues.
	s := NewScheduler(SchedulerOptions{MaxBufferedBytes: 1024})
	if _, ok := s.Next(); ok {
		t.Fatal("Next() on empty scheduler returned ok, want false")
	}
	// After draining, Next() must also report empty.
	if err := s.Enqueue(StreamChunk{FlowID: 1, PriorityClass: PriorityBulk, Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Next(); !ok {
		t.Fatal("Next() after enqueue returned false")
	}
	if _, ok := s.Next(); ok {
		t.Fatal("Next() after draining returned ok, want false")
	}
}
