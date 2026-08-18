package policy

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestProfileByNameResolvesAllAndRejectsUnknown covers ProfileByName (0%): each
// registered profile name resolves to the profile with that Name, and an
// unknown name errors. The oracle is the allProfiles registry cross-checked by
// ID so a name-to-ID mismatch is caught.
func TestProfileByNameResolvesAllAndRejectsUnknown(t *testing.T) {
	wantByName := map[string]uint64{
		"fast-web":               registry.PolicyFastWeb,
		"balanced-web":           registry.PolicyBalancedWeb,
		"adversarial-dpi":        registry.PolicyAdversarialDPI,
		"adversarial-dpi-strict": registry.PolicyAdversarialStrict,
		"emergency-web":          registry.PolicyEmergencyWeb,
		"lab":                    registry.PolicyLab,
	}
	for name, wantID := range wantByName {
		p, err := ProfileByName(name)
		if err != nil {
			t.Fatalf("ProfileByName(%q): %v", name, err)
		}
		if p.ID != wantID {
			t.Fatalf("ProfileByName(%q).ID = 0x%x, want 0x%x", name, p.ID, wantID)
		}
		if p.Name != name {
			t.Fatalf("ProfileByName(%q).Name = %q", name, p.Name)
		}
	}
	if _, err := ProfileByName("bogus-profile"); err == nil {
		t.Fatal("ProfileByName accepted unknown name")
	}
}

// TestProfileByIDResolvesAllAndRejectsUnknown covers the ProfileByID error
// branch (75% -> 100%): each registered ID resolves, and an unknown ID errors.
func TestProfileByIDResolvesAllAndRejectsUnknown(t *testing.T) {
	ids := []uint64{
		registry.PolicyFastWeb,
		registry.PolicyBalancedWeb,
		registry.PolicyAdversarialDPI,
		registry.PolicyAdversarialStrict,
		registry.PolicyEmergencyWeb,
		registry.PolicyLab,
	}
	for _, id := range ids {
		p, err := ProfileByID(id)
		if err != nil {
			t.Fatalf("ProfileByID(0x%x): %v", id, err)
		}
		if p.ID != id {
			t.Fatalf("ProfileByID(0x%x).ID = 0x%x", id, p.ID)
		}
	}
	if _, err := ProfileByID(0xdead); err == nil {
		t.Fatal("ProfileByID accepted unknown id")
	}
}

// TestSmartProfileDispatchPerPathClass covers SmartProfile (33% -> 100%): each
// path class resolves to the expected policy via ProfileByID, which is the
// oracle. clean->FastWeb, strict/severe->AdversarialStrict, default->AdversarialDPI.
func TestSmartProfileDispatchPerPathClass(t *testing.T) {
	cases := []struct {
		pathClass string
		wantID    uint64
	}{
		{"clean", registry.PolicyFastWeb},
		{"strict", registry.PolicyAdversarialStrict},
		{"severe", registry.PolicyAdversarialStrict},
		{"normal", registry.PolicyAdversarialDPI},
		{"", registry.PolicyAdversarialDPI},
	}
	for _, tc := range cases {
		got := SmartProfile(tc.pathClass)
		if got.ID != tc.wantID {
			t.Fatalf("SmartProfile(%q).ID = 0x%x, want 0x%x", tc.pathClass, got.ID, tc.wantID)
		}
	}
}

// TestComputePACEDefaultAndEachBranch covers ComputePACE (52.6%): the base
// output (no triggers) and each branch in isolation. ComputePACE applies
// branches sequentially, so each case activates exactly one trigger with the
// others held inert, and asserts the branch-specific overrides plus the
// untouched base fields.
func TestComputePACEDefaultAndEachBranch(t *testing.T) {
	// Base: no triggers fire.
	base := ComputePACE(PaceInput{GoodputMbps: 20, PolicyID: registry.PolicyFastWeb})
	if base.Mode != "pace.bbr-web" || base.BurstLimitPackets != 16 || base.SendWindowPackets != 64 ||
		base.PaddingBudgetPercent != 3 || base.ProbeInterval != 30*time.Second || base.FECRate != 0 ||
		base.BackupPath || base.MethodSwitch {
		t.Fatalf("base PACE output unexpected: %+v", base)
	}
	if base.PacingRateMbps != 19 { // max(0.1, 20*0.95)
		t.Fatalf("base pacing rate = %v, want 19", base.PacingRateMbps)
	}

	// Branch: queue delay > 80 -> delay-web.
	d := ComputePACE(PaceInput{QueueDelayMS: 100, GoodputMbps: 20, PolicyID: registry.PolicyFastWeb})
	if d.Mode != "pace.delay-web" || d.BurstLimitPackets != 6 || d.PaddingBudgetPercent != 1 || d.PacingRateMbps != 15 {
		t.Fatalf("delay-web branch unexpected: %+v", d)
	}

	// Branch: loss rescue (loss>0.03, block-suspect<0.5).
	l := ComputePACE(PaceInput{LossRate: 0.05, BlockSuspectScore: 0.2, GoodputMbps: 20, PolicyID: registry.PolicyFastWeb})
	if l.Mode != "pace.loss-rescue" || l.FECRate != 0.05 || l.BurstLimitPackets != 4 {
		t.Fatalf("loss-rescue branch unexpected: %+v", l)
	}

	// Branch: strict/emergency policy -> strict padding/probe.
	for _, pid := range []uint64{registry.PolicyAdversarialStrict, registry.PolicyEmergencyWeb} {
		s := ComputePACE(PaceInput{GoodputMbps: 20, PolicyID: pid})
		if s.Mode != "pace.strict" || s.PaddingBudgetPercent != 8 || s.ProbeInterval != 2*time.Minute {
			t.Fatalf("strict branch (policy 0x%x) unexpected: %+v", pid, s)
		}
	}

	// Branch: block-suspect > 0.65 -> backup + method switch + zero padding.
	b := ComputePACE(PaceInput{BlockSuspectScore: 0.8, GoodputMbps: 20, PolicyID: registry.PolicyFastWeb})
	if !b.BackupPath || !b.MethodSwitch || b.PaddingBudgetPercent != 0 {
		t.Fatalf("block-suspect branch unexpected: %+v", b)
	}

	// Pacing rate floor: tiny goodput still >= 0.1.
	floor := ComputePACE(PaceInput{GoodputMbps: 0, PolicyID: registry.PolicyFastWeb})
	if floor.PacingRateMbps < 0.1 {
		t.Fatalf("pacing rate floor = %v, want >= 0.1", floor.PacingRateMbps)
	}
}

// TestClamp01 covers clamp01 (80% -> 100%): below, above, and in-range.
func TestClamp01(t *testing.T) {
	if clamp01(-1) != 0 {
		t.Fatal("clamp01(-1) != 0")
	}
	if clamp01(2) != 1 {
		t.Fatal("clamp01(2) != 1")
	}
	if clamp01(0.5) != 0.5 {
		t.Fatal("clamp01(0.5) != 0.5")
	}
}

// TestScoreCooldownAndBlockSuspectReturnZero covers the two Score early-return
// branches (90.9%): an active cooldown returns 0, and a high block-suspect or
// fingerprint-risk score returns 0. A normal record returns a positive score.
func TestScoreCooldownAndBlockSuspectReturnZero(t *testing.T) {
	now := time.Now()
	cooldown := PathScoreRecord{P50RTTMS: 80, CooldownUntil: now.Add(time.Hour)}
	if got := cooldown.Score(now); got != 0 {
		t.Fatalf("active cooldown score = %v, want 0", got)
	}
	block := PathScoreRecord{P50RTTMS: 80, BlockSuspectScore: 0.9}
	if got := block.Score(now); got != 0 {
		t.Fatalf("block-suspect score = %v, want 0", got)
	}
	fp := PathScoreRecord{P50RTTMS: 80, FingerprintRiskScore: 0.9}
	if got := fp.Score(now); got != 0 {
		t.Fatalf("fingerprint-risk score = %v, want 0", got)
	}
	normal := PathScoreRecord{P50RTTMS: 80, LossPercent: 0.2, JitterMS: 10, GoodputMbps: 50,
		HandshakeSuccessRate: 0.99, SessionSurvivalRate: 0.98, CarrierAffinityScore: 0.5, QueueDelayMS: 10}
	if got := normal.Score(now); got <= 0 {
		t.Fatalf("normal score = %v, want > 0", got)
	}
}

// TestAllowsMASQUEPerProfile covers AllowsMASQUE (80% -> 100%): a stealth-gated
// profile denies MASQUE; FastWeb and Lab allow it; any other non-stealth profile
// falls back to VisibleProxySemanticsAllowed. (All built-in non-stealth profiles
// are fast-web/lab, which hit the explicit case, so the default branch is only
// reachable via a custom profile with StealthGate=false.)
func TestAllowsMASQUEPerProfile(t *testing.T) {
	if AllowsMASQUE(allProfilesByID(registry.PolicyAdversarialDPI)) {
		t.Fatal("stealth-gated profile allowed MASQUE")
	}
	if !AllowsMASQUE(allProfilesByID(registry.PolicyFastWeb)) {
		t.Fatal("fast-web denied MASQUE")
	}
	if !AllowsMASQUE(allProfilesByID(registry.PolicyLab)) {
		t.Fatal("lab denied MASQUE")
	}
	if !AllowsMASQUE(Profile{Name: "custom", VisibleProxySemanticsAllowed: true}) {
		t.Fatal("custom profile with visible-proxy semantics denied MASQUE")
	}
	if AllowsMASQUE(Profile{Name: "custom"}) {
		t.Fatal("custom profile without visible-proxy semantics allowed MASQUE")
	}
}

// allProfilesByID looks up a profile by ID (test helper).
func allProfilesByID(id uint64) Profile {
	for _, p := range allProfiles {
		if p.ID == id {
			return p
		}
	}
	panic("unknown profile id")
}

// TestPassesStealthGateBranches covers the remaining PassesStealthGate branches
// (86.7% -> 100%): MASQUE under a MASQUE-denying profile, DirectQUICLab under a
// non-lab profile, the !StealthGate short-circuit, and the QUIC-residual-block
// H3 rejection.
func TestPassesStealthGateBranches(t *testing.T) {
	fastWeb := allProfilesByID(registry.PolicyFastWeb) // StealthGate false
	// MASQUE method under a profile that denies MASQUE (balanced-web stealth-gated).
	masqueCand := safeCandidate(registry.RouteSplit2, registry.MethodMasqueConnectIP, 1)
	if masqueCand.PassesStealthGate(allProfilesByID(registry.PolicyBalancedWeb)) {
		t.Fatal("MASQUE method passed stealth gate on a stealth-gated profile")
	}
	// DirectQUICLab under a non-lab profile -> rejected.
	dqlabCand := safeCandidate(registry.RouteSplit2, registry.MethodDirectQUICLab, 1)
	if dqlabCand.PassesStealthGate(fastWeb) {
		t.Fatal("DirectQUICLab passed stealth gate on a non-lab profile")
	}
	// Non-stealth profile short-circuits to true for an ordinary method.
	if !safeCandidate(registry.RouteFast1, registry.MethodWebH2Stream, 1).PassesStealthGate(fastWeb) {
		t.Fatal("ordinary method rejected under non-stealth profile")
	}
	// QUIC-residual-block-suspect with an H3 method on a stealth profile -> rejected.
	strict := allProfilesByID(registry.PolicyAdversarialDPI)
	blockCand := safeCandidate(registry.RouteSplit2, registry.MethodWebH3Stream, 1)
	blockCand.QUICResidualBlockSuspect = true
	if blockCand.PassesStealthGate(strict) {
		t.Fatal("QUIC-residual-block-suspect H3 method passed stealth gate")
	}
	// DirectQUICLab under a stealth+LabOnly profile: passes the line-179 check
	// (LabOnly allows direct QUIC) but is rejected at line 188 (DirectQUICLab is
	// forbidden under a stealth gate regardless).
	stealthLab := Profile{StealthGate: true, LabOnly: true}
	if safeCandidate(registry.RouteSplit2, registry.MethodDirectQUICLab, 1).PassesStealthGate(stealthLab) {
		t.Fatal("DirectQUICLab passed stealth gate under a stealth+LabOnly profile")
	}
}

// TestSelectNoCandidateAndOverride covers the remaining Select branches
// (83.3% -> 100%): all candidates failing the gates yields an error, and the
// lowLatencyOverride lets an adversarial-DPI fast-1 candidate through.
func TestSelectNoCandidateAndOverride(t *testing.T) {
	adv := allProfilesByID(registry.PolicyAdversarialDPI)
	// No candidate passes: an unsafe candidate is filtered out.
	unsafe := safeCandidate(registry.RouteSplit2, registry.MethodWebH2Stream, 1)
	unsafe.ValidSignatures = false
	if _, err := Select(adv, []Candidate{unsafe}, time.Now(), false); err == nil {
		t.Fatal("Select accepted a candidate that fails the safety gate")
	}
	// Adversarial-DPI fast-1 candidate: filtered without override, kept with override.
	fast1 := safeCandidate(registry.RouteFast1, registry.MethodWebH2Stream, 1)
	if _, err := Select(adv, []Candidate{fast1}, time.Now(), false); err == nil {
		t.Fatal("Select kept adversarial-DPI fast-1 candidate without low-latency override")
	}
	got, err := Select(adv, []Candidate{fast1}, time.Now(), true)
	if err != nil {
		t.Fatalf("Select with override rejected fast-1: %v", err)
	}
	if got.RouteModeID != registry.RouteFast1 {
		t.Fatalf("Select returned route 0x%x, want fast-1", got.RouteModeID)
	}
	// Highest score wins among passing candidates. safeCandidate's score param
	// is a P50RTT divisor, so a larger param -> smaller RTT -> higher Score().
	loser := safeCandidate(registry.RouteSplit2, registry.MethodWebH2Stream, 0.5) // P50=160
	winner := safeCandidate(registry.RouteSplit2, registry.MethodWebH2Stream, 4)  // P50=20
	picked, err := Select(adv, []Candidate{loser, winner}, time.Now(), false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if picked != winner {
		t.Fatal("Select did not pick the higher-scoring candidate")
	}
}

// TestPassesStealthGateConjunctionFields covers each field of the stealth-gate
// conjunction (line 197-203): on a stealth-gated profile, a candidate that
// passes all earlier checks and has every conjunction field set passes; setting
// any single conjunction field to its failing value must fail the gate. Each
// field is an independent stealth property, so this is a security regression
// guard, not coverage padding.
func TestPassesStealthGateConjunctionFields(t *testing.T) {
	balanced := allProfilesByID(registry.PolicyBalancedWeb) // StealthGate true, QUIC opportunistic
	base := safeCandidate(registry.RouteSplit2, registry.MethodWebH2Stream, 1)
	if !base.PassesStealthGate(balanced) {
		t.Fatal("baseline stealth candidate rejected")
	}
	cases := []struct {
		name string
		mut  func(*Candidate)
	}{
		{"raw first payload", func(c *Candidate) { c.NoRawFirstPayload = false }},
		{"visible proxy semantics", func(c *Candidate) { c.NoVisibleProxySemantics = false }},
		{"fixed public auth path", func(c *Candidate) { c.NoFixedPublicAuthPath = false }},
		{"custom public headers", func(c *Candidate) { c.NoCustomPublicHeaders = false }},
		{"probe-neutral failure", func(c *Candidate) { c.ProbeNeutralFailure = false }},
		{"cover-profile plausible", func(c *Candidate) { c.CoverProfilePlausible = false }},
		{"suspicious fallback", func(c *Candidate) { c.SuspiciousFallback = true }},
	}
	for _, tc := range cases {
		c := base
		tc.mut(&c)
		if c.PassesStealthGate(balanced) {
			t.Fatalf("%s: stealth gate passed with failing conjunction field", tc.name)
		}
	}
}
