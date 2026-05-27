package policy

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestActivateBlockSuspectCooldownParksTupleOnTrigger(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	blocked := PathScoreRecord{P50RTTMS: 60, GoodputMbps: 50, HandshakeSuccessRate: 1, SessionSurvivalRate: 1, BlockSuspectScore: 0.9}
	parked := ActivateBlockSuspectCooldown(blocked, now, DefaultTupleCooldown)
	if parked.CooldownUntil.IsZero() || !parked.CooldownUntil.After(now) {
		t.Fatalf("cooldown not activated: %v", parked.CooldownUntil)
	}
	if parked.Score(now) != 0 {
		t.Fatalf("parked tuple should score zero, got %.3f", parked.Score(now))
	}
}

func TestActivateBlockSuspectCooldownNoOpBelowThreshold(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	benign := PathScoreRecord{P50RTTMS: 60, GoodputMbps: 50, HandshakeSuccessRate: 1, SessionSurvivalRate: 1, BlockSuspectScore: 0.1}
	out := ActivateBlockSuspectCooldown(benign, now, DefaultTupleCooldown)
	if !out.CooldownUntil.IsZero() {
		t.Fatalf("benign tuple should not be parked, got %v", out.CooldownUntil)
	}
	if out.Score(now) <= 0 {
		t.Fatalf("benign tuple should remain selectable, score %.3f", out.Score(now))
	}
}

func TestCarrierDowngradeControllerDowngradesOnceUnderSustainedBlock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewCarrierDowngradeController(registry.MethodWebH3ExtDgram, 30*time.Second)
	for i := 0; i < 10; i++ {
		c.ObserveQUICBlocked(registry.MethodWebH2Stream, now.Add(time.Duration(i)*time.Second))
	}
	if c.CurrentMethodID() != registry.MethodWebH2Stream {
		t.Fatalf("expected downgrade to H2, got 0x%x", c.CurrentMethodID())
	}
	if c.Transitions() != 1 {
		t.Fatalf("sustained block must downgrade once (no reconnect storm), got %d transitions", c.Transitions())
	}
}
