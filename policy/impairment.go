package policy

import "time"

// BlockSuspectCooldownThreshold is the block-suspect score above which a tuple
// is parked under a cooldown instead of being retried.
const BlockSuspectCooldownThreshold = 0.65

// DefaultTupleCooldown is the default park window applied when a block-suspect
// trigger fires.
const DefaultTupleCooldown = 10 * time.Minute

// ActivateBlockSuspectCooldown parks a tuple under a cooldown when its
// block-suspect score crosses the threshold (Milestone P10: "tuple cooldown
// activates after block-suspect triggers"). A cooled-down tuple scores zero
// (see PathScoreRecord.Score), so the selector stops choosing it and the client
// does not hammer a suspected-blocked path — the mechanism that prevents
// retry/reconnect storms. The call is idempotent while a cooldown is active and
// a no-op below the threshold.
func ActivateBlockSuspectCooldown(record PathScoreRecord, now time.Time, window time.Duration) PathScoreRecord {
	if record.BlockSuspectScore <= BlockSuspectCooldownThreshold {
		return record
	}
	if !record.CooldownUntil.IsZero() && now.Before(record.CooldownUntil) {
		return record
	}
	if window <= 0 {
		window = DefaultTupleCooldown
	}
	record.CooldownUntil = now.Add(window)
	return record
}

// CarrierDowngradeController applies hysteresis to QUIC->H2/H1 downgrades so a
// flapping or blocked QUIC path triggers a single downgrade rather than a
// reconnect storm (Milestone P10: "PAL downgrades QUIC to H2/H1 without
// reconnect storms"). Once downgraded it holds the lower carrier for HoldWindow
// before any re-upgrade is permitted.
type CarrierDowngradeController struct {
	current     uint64
	holdWindow  time.Duration
	lastSwitch  time.Time
	switched    bool
	transitions int
}

// NewCarrierDowngradeController starts on the initial carrier method id.
func NewCarrierDowngradeController(initialMethodID uint64, holdWindow time.Duration) *CarrierDowngradeController {
	return &CarrierDowngradeController{current: initialMethodID, holdWindow: holdWindow}
}

// ObserveQUICBlocked downgrades to downgradeTargetMethodID. Repeated calls while
// already on the target (or within the hold window of the last switch) are
// no-ops, so N block observations cause at most one transition.
func (c *CarrierDowngradeController) ObserveQUICBlocked(downgradeTargetMethodID uint64, now time.Time) uint64 {
	if c.current == downgradeTargetMethodID {
		return c.current
	}
	if c.switched && now.Sub(c.lastSwitch) < c.holdWindow {
		return c.current
	}
	c.current = downgradeTargetMethodID
	c.lastSwitch = now
	c.switched = true
	c.transitions++
	return c.current
}

// CurrentMethodID returns the carrier method currently selected.
func (c *CarrierDowngradeController) CurrentMethodID() uint64 { return c.current }

// Transitions returns how many carrier switches have occurred. A value greater
// than one for a single sustained block event indicates a reconnect storm.
func (c *CarrierDowngradeController) Transitions() int { return c.transitions }
