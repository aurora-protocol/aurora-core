package session

// Adversarial white-box coverage for the count-0 stale-generation supersession
// guards inside the async AfterFunc drain callbacks in scheduleWriteDrainLocked
// and scheduleReadDrainLocked (clock.go).
//
//   - clock.go:36 scheduleWriteDrainLocked AfterFunc callback
//     if a.terminal != nil || generation != a.writeDrainGeneration { return }
//   - clock.go:67 scheduleReadDrainLocked AfterFunc callback
//     if a.terminal != nil || generation != a.readDrainGeneration { return }
//
// Each callback captures the write/read drain generation at schedule time
// (:28/:59) and, when fired, re-locks a.mu (:34/:65) and checks whether the
// session has terminated or a NEWER drain timer has superseded this one
// (generation mismatch). If so, the stale callback returns at :37/:68 WITHOUT
// expiring the drain — a stale timer must never drain. These are
// supersession/termination LOGIC guards (not nil-safety: proceeding past them
// does not nil-deref), but they are count-0 and protect a real correctness
// property, so they are worth covering.
//
// The existing session drain tests (application_test.go / key_update_test.go)
// drive the full key-update pipeline and Advance the manualApplicationClock,
// but the callbacks always fire with a MATCHING generation and a nil terminal,
// so they proceed to :39+/:70+ and the :36/:67 guard body (the :37/:68 return)
// stays count-0 — measured: clock.go:33.53,36.64 3 3 / :64.52,67.63 3 2
// (conditions evaluated) but :36.64,38.4 1 0 / :67.63,69.4 1 0 (the bodies,
// COUNT 0).
//
// Proof (white-box generation bump, no deadlock): build a minimal Application
// whose clock is a manualApplicationClock and whose writeState/readState
// DrainUntil is a fixed future time. Holding a.mu, call scheduleWriteDrainLocked
// / scheduleReadDrainLocked (a "Locked"-suffix method: caller holds a.mu) —
// this bumps the generation, captures it in the callback closure, and registers
// a timer via clock.AfterFunc. Then bump the generation AGAIN in-package
// (a.writeDrainGeneration++ / a.readDrainGeneration++) so the captured
// generation is now STALE. Release a.mu, then clock.Advance the delay —
// RunDueTimers fires the callback while NOT holding the clock mutex, and the
// test is NOT holding a.mu, so the callback's a.mu.Lock() at :34/:65 does not
// deadlock. The stale callback sees generation != a.write/readDrainGeneration,
// returns at :37/:68 before :43/:74 ExpireDrainAt, so DrainUntil stays non-zero —
// the asserted correctness property (a stale timer must not expire the drain).
//
// No context is involved, so there is no SA1012 surface. No network, no file IO,
// no goroutine beyond the manualApplicationClock's synchronous RunDueTimers
// (which runs callbacks on the test goroutine). In-package (package session)
// because Application.writeDrainGeneration / readDrainGeneration / schedule*Locked
// are unexported, and the manualApplicationClock stub lives in this package's
// test files.
//
// This test file adds only TestXxx entry points and references existing
// in-package (Application, manualApplicationClock, schedule*Locked, the
// write/readDrainGeneration fields) symbols plus the packet.DirectionState type
// and the standard library testing / time packages, so it adds no U1000 surface.

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/packet"
)

func TestScheduleWriteDrainLockedStaleGenerationGuard(t *testing.T) {
	// 36: a stale write-drain callback (captured generation superseded by a newer
	// scheduleWriteDrainLocked) returns at :37 before :43 ExpireDrainAt, so the
	// drain is NOT expired by a stale timer.
	base := time.Unix(1000, 0)
	clock := newManualApplicationClock(base)
	a := &Application{
		clock:      clock,
		writeState: packet.DirectionState{DrainUntil: base.Add(time.Second)},
	}
	// scheduleWriteDrainLocked is a "Locked"-suffix method: caller holds a.mu.
	a.mu.Lock()
	a.scheduleWriteDrainLocked() // generation 0->1; callback captures gen=1; AfterFunc registers timer
	// White-box: supersede so the captured generation (1) is now stale vs current (2).
	a.writeDrainGeneration++
	a.mu.Unlock()
	// Advance fires the stale callback. RunDueTimers runs the callback off the
	// clock mutex, and a.mu is released, so the callback's :34 a.mu.Lock() is
	// deadlock-free. The stale gen (1) != writeDrainGeneration (2) -> :37 return.
	clock.Advance(time.Second)
	if a.writeState.DrainUntil.IsZero() {
		t.Fatal("stale write-drain callback must not expire the drain (guard :36 should suppress before :43 ExpireDrainAt)")
	}
}

func TestScheduleReadDrainLockedStaleGenerationGuard(t *testing.T) {
	// 67: a stale read-drain callback (captured generation superseded by a newer
	// scheduleReadDrainLocked) returns at :68 before :74 expireReadDrainLocked, so
	// the drain is NOT expired by a stale timer.
	base := time.Unix(2000, 0)
	clock := newManualApplicationClock(base)
	a := &Application{
		clock:     clock,
		readState: packet.DirectionState{DrainUntil: base.Add(time.Second)},
	}
	a.mu.Lock()
	a.scheduleReadDrainLocked() // generation 0->1; callback captures gen=1; AfterFunc registers timer
	a.readDrainGeneration++     // white-box: supersede so captured gen (1) is stale vs current (2)
	a.mu.Unlock()
	clock.Advance(time.Second) // fires stale callback: gen 1 != readDrainGeneration 2 -> :68 return
	if a.readState.DrainUntil.IsZero() {
		t.Fatal("stale read-drain callback must not expire the drain (guard :67 should suppress before :74 expireReadDrainLocked)")
	}
}
