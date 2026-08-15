package policy

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestActivateBlockSuspectCooldownIdempotentWhileActive covers the branch where a
// tuple already has an active cooldown: a second trigger must not extend or
// reset the existing cooldown window (line 24-25).
func TestActivateBlockSuspectCooldownIdempotentWhileActive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	active := PathScoreRecord{BlockSuspectScore: 0.9, CooldownUntil: now.Add(5 * time.Minute)}
	out := ActivateBlockSuspectCooldown(active, now, 10*time.Minute)
	if !out.CooldownUntil.Equal(active.CooldownUntil) {
		t.Fatalf("idempotent call moved cooldown: got %v, want %v", out.CooldownUntil, active.CooldownUntil)
	}
}

// TestActivateBlockSuspectCooldownDefaultsWindowWhenNonPositive covers the
// window<=0 fallback to DefaultTupleCooldown (line 27-28).
func TestActivateBlockSuspectCooldownDefaultsWindowWhenNonPositive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, window := range []time.Duration{0, -1 * time.Second} {
		out := ActivateBlockSuspectCooldown(PathScoreRecord{BlockSuspectScore: 0.9}, now, window)
		want := now.Add(DefaultTupleCooldown)
		if !out.CooldownUntil.Equal(want) {
			t.Fatalf("window=%v: cooldown = %v, want %v (DefaultTupleCooldown)", window, out.CooldownUntil, want)
		}
	}
}

// TestObserveQUICBlockedHoldsWindowForDifferentTarget covers the hold-window
// branch (line 59-60): while inside the hold window, a block observation aimed
// at a different target is suppressed (current carrier kept, no extra
// transition). It also confirms a switch resumes once the window elapses.
func TestObserveQUICBlockedHoldsWindowForDifferentTarget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewCarrierDowngradeController(registry.MethodWebH3ExtDgram, 30*time.Second)

	if got := c.ObserveQUICBlocked(registry.MethodWebH2Stream, now); got != registry.MethodWebH2Stream {
		t.Fatalf("first downgrade = 0x%x, want H2", got)
	}
	if c.Transitions() != 1 {
		t.Fatalf("transitions = %d, want 1", c.Transitions())
	}

	// Within the hold window, a different target is suppressed.
	got := c.ObserveQUICBlocked(registry.MethodWebH1WS, now.Add(10*time.Second))
	if got != registry.MethodWebH2Stream {
		t.Fatalf("hold-window observation returned 0x%x, want H2 (kept)", got)
	}
	if c.Transitions() != 1 {
		t.Fatalf("transitions = %d, want 1 (hold window should not add a transition)", c.Transitions())
	}

	// After the hold window elapses, a different target switches.
	got = c.ObserveQUICBlocked(registry.MethodWebH1WS, now.Add(60*time.Second))
	if got != registry.MethodWebH1WS {
		t.Fatalf("post-window observation returned 0x%x, want H1WS (switched)", got)
	}
	if c.Transitions() != 2 {
		t.Fatalf("transitions = %d, want 2", c.Transitions())
	}
}