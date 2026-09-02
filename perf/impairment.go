// Package perf implements the Milestone P10 deterministic performance and
// bad-path validation harness. It drives the portable scoring, pacing,
// scheduling, carrier-selection, and flow primitives through the named network
// impairment scenarios and asserts the P10 acceptance criteria.
package perf

import (
	"bytes"
	"fmt"
	"time"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/transport"
)

type ScenarioResult struct {
	Name   string
	Passed bool
	Detail string
}

type ImpairmentReport struct {
	Passed    bool
	Scenarios []ScenarioResult

	// Acceptance criteria.
	InteractivePrioritized        bool
	UDPStalePolicy                bool
	DowngradeNoReconnectStorm     bool
	TupleCooldownActivates        bool
	PaddingReducesUnderCongestion bool

	Findings []string
}

func (r *ImpairmentReport) scenario(name string, passed bool, detail string) {
	r.Scenarios = append(r.Scenarios, ScenarioResult{Name: name, Passed: passed, Detail: detail})
	if !passed {
		r.Passed = false
		r.Findings = append(r.Findings, fmt.Sprintf("%s: %s", name, detail))
	}
}

func (r *ImpairmentReport) require(passed bool, finding string) {
	if !passed {
		r.Passed = false
		r.Findings = append(r.Findings, finding)
	}
}

// RunImpairmentHarness executes the P10 scenario matrix and acceptance checks.
func RunImpairmentHarness() (ImpairmentReport, error) {
	report := ImpairmentReport{Passed: true}
	now := time.Unix(1_700_000_000, 0)

	baseline := policy.PaceInput{SmoothedRTTMS: 60, GoodputMbps: 50, QueueDelayMS: 10, LossRate: 0}
	basePace := policy.ComputePACE(baseline)

	// --- Impairment scenario matrix ---

	// Loss ladder: 0.1%, 1%, 5%, 10%. Loss-rescue (FEC) MUST engage at high loss
	// and stay off at negligible loss.
	for _, tc := range []struct {
		name string
		loss float64
		fec  bool
	}{
		{"loss-0.1pct", 0.001, false},
		{"loss-1pct", 0.01, false},
		{"loss-5pct", 0.05, true},
		{"loss-10pct", 0.10, true},
	} {
		out := policy.ComputePACE(policy.PaceInput{SmoothedRTTMS: 60, GoodputMbps: 50, LossRate: tc.loss})
		got := out.FECRate > 0 && out.Mode == "pace.loss-rescue"
		report.scenario(tc.name, got == tc.fec,
			fmt.Sprintf("fec_engaged=%t want=%t fec_rate=%.3f mode=%s", got, tc.fec, out.FECRate, out.Mode))
	}

	// Burst loss: a high instantaneous loss spike must trigger loss-rescue with a
	// reduced burst limit versus the uncongested baseline.
	burst := policy.ComputePACE(policy.PaceInput{SmoothedRTTMS: 60, GoodputMbps: 50, LossRate: 0.08})
	report.scenario("burst-loss", burst.Mode == "pace.loss-rescue" && burst.BurstLimitPackets < basePace.BurstLimitPackets,
		fmt.Sprintf("mode=%s burst=%d base_burst=%d", burst.Mode, burst.BurstLimitPackets, basePace.BurstLimitPackets))

	// High jitter degrades the path score relative to a calm path.
	calm := policy.PathScoreRecord{P50RTTMS: 60, JitterMS: 5, GoodputMbps: 50, HandshakeSuccessRate: 1, SessionSurvivalRate: 1}
	jittery := calm
	jittery.JitterMS = 90
	report.scenario("high-jitter", jittery.Score(now) < calm.Score(now),
		fmt.Sprintf("jittery_score=%.3f calm_score=%.3f", jittery.Score(now), calm.Score(now)))

	// UDP blocked: with no H3 capability the carrier plan must fall back to a
	// stream carrier (no native datagram) and flag a performance downgrade.
	dpiProfile, err := policy.ProfileByID(registry.PolicyAdversarialDPI)
	if err != nil {
		return ImpairmentReport{}, err
	}
	udpBlockedCaps := transport.Capabilities{SupportsH2: true, SupportsH1WS: true, SupportsShadow: true, CoverTemplateOK: true}
	udpPlan, err := transport.SelectCarrierPlan(dpiProfile, udpBlockedCaps)
	if err != nil {
		return ImpairmentReport{}, err
	}
	report.scenario("udp-blocked", udpPlan.UDPMode != transport.UDPNativeDatagram && udpPlan.PerformanceDowngrade,
		fmt.Sprintf("udp_mode=%d native=%d downgrade=%t method=0x%x", udpPlan.UDPMode, transport.UDPNativeDatagram, udpPlan.PerformanceDowngrade, udpPlan.Carrier.MethodID))

	// QUIC Initial blocked: a sustained block must downgrade exactly once.
	quicController := policy.NewCarrierDowngradeController(registry.MethodWebH3ExtDgram, 30*time.Second)
	for i := 0; i < 8; i++ {
		quicController.ObserveQUICBlocked(registry.MethodWebH2Stream, now.Add(time.Duration(i)*time.Second))
	}
	report.scenario("quic-initial-blocked",
		quicController.CurrentMethodID() == registry.MethodWebH2Stream && quicController.Transitions() == 1,
		fmt.Sprintf("current=0x%x transitions=%d", quicController.CurrentMethodID(), quicController.Transitions()))

	// HTTP/2 stream loss / head-of-line blocking: loss reduces the send window
	// and burst budget so a lossy multiplexed stream slows rather than stalls.
	h2Loss := policy.ComputePACE(policy.PaceInput{SmoothedRTTMS: 80, GoodputMbps: 40, LossRate: 0.04, MethodID: registry.MethodWebH2Stream})
	report.scenario("h2-stream-loss-hol", h2Loss.BurstLimitPackets < basePace.BurstLimitPackets && h2Loss.FECRate > 0,
		fmt.Sprintf("burst=%d base=%d fec=%.3f", h2Loss.BurstLimitPackets, basePace.BurstLimitPackets, h2Loss.FECRate))

	// Mobile path change: a benign path change (no block suspicion) must NOT park
	// the tuple under cooldown, so the session continues without a reconnect.
	mobile := policy.PathScoreRecord{P50RTTMS: 90, JitterMS: 20, GoodputMbps: 30, HandshakeSuccessRate: 1, SessionSurvivalRate: 1, BlockSuspectScore: 0.1}
	mobileAfter := policy.ActivateBlockSuspectCooldown(mobile, now, policy.DefaultTupleCooldown)
	report.scenario("mobile-path-change", mobileAfter.CooldownUntil.IsZero() && mobileAfter.Score(now) > 0,
		fmt.Sprintf("cooldown_set=%t score=%.3f", !mobileAfter.CooldownUntil.IsZero(), mobileAfter.Score(now)))

	// Relay overload: high queue delay switches PACE to the delay-controlled mode
	// and reduces the pacing rate.
	overload := policy.ComputePACE(policy.PaceInput{SmoothedRTTMS: 120, GoodputMbps: 40, QueueDelayMS: 180})
	report.scenario("relay-overload", overload.Mode == "pace.delay-web" && overload.PacingRateMbps < basePace.PacingRateMbps,
		fmt.Sprintf("mode=%s rate=%.2f base_rate=%.2f", overload.Mode, overload.PacingRateMbps, basePace.PacingRateMbps))

	// Peak-hour congestion: queue delay above threshold reduces the padding
	// budget before loss forces FEC (acceptance criterion, asserted below too).
	peak := policy.ComputePACE(policy.PaceInput{SmoothedRTTMS: 100, GoodputMbps: 35, QueueDelayMS: 120})
	report.scenario("peak-hour-congestion", peak.PaddingBudgetPercent < basePace.PaddingBudgetPercent,
		fmt.Sprintf("padding=%.0f base_padding=%.0f", peak.PaddingBudgetPercent, basePace.PaddingBudgetPercent))

	// Carrier-specific path cache: a higher carrier affinity (cached good path)
	// must raise the score for an otherwise identical path.
	noAffinity := policy.PathScoreRecord{P50RTTMS: 70, JitterMS: 15, GoodputMbps: 45, HandshakeSuccessRate: 1, SessionSurvivalRate: 1}
	cached := noAffinity
	cached.CarrierAffinityScore = 1
	report.scenario("carrier-path-cache", cached.Score(now) > noAffinity.Score(now),
		fmt.Sprintf("cached_score=%.3f cold_score=%.3f", cached.Score(now), noAffinity.Score(now)))

	// Packet protect throughput: the only wall-clock scenario. It measures
	// seal+open round trips per second on the per-packet hot path against a
	// generous floor, so a gross regression (accidental O(n^2), large per-packet
	// allocation) fails the gate while slow shared CI runners still pass.
	protectOpsPerSec, err := measureProtectRoundTripsPerSecond(protectThroughputWarmup, protectThroughputIterations)
	if err != nil {
		return ImpairmentReport{}, err
	}
	report.scenario("packet-protect-throughput", protectThroughputWithinBudget(protectOpsPerSec, protectThroughputFloorOpsPerSec),
		fmt.Sprintf("ops_per_sec=%.0f floor=%d iterations=%d", protectOpsPerSec, protectThroughputFloorOpsPerSec, protectThroughputIterations))

	// --- Acceptance criteria ---

	report.InteractivePrioritized = checkInteractivePriority()
	report.require(report.InteractivePrioritized, "interactive TCP was not prioritized over bulk")

	report.UDPStalePolicy = checkUDPStalePolicy()
	report.require(report.UDPStalePolicy, "UDP stale-packet policy did not drop a stale realtime datagram")

	report.DowngradeNoReconnectStorm = quicController.Transitions() == 1
	report.require(report.DowngradeNoReconnectStorm, "QUIC downgrade caused more than one transition (reconnect storm)")

	report.TupleCooldownActivates = checkTupleCooldown(now)
	report.require(report.TupleCooldownActivates, "block-suspect trigger did not activate a tuple cooldown")

	report.PaddingReducesUnderCongestion = peak.PaddingBudgetPercent < basePace.PaddingBudgetPercent
	report.require(report.PaddingReducesUnderCongestion, "padding budget did not reduce under congestion")

	return report, nil
}

func checkInteractivePriority() bool {
	scheduler := flow.NewScheduler(flow.SchedulerOptions{})
	// Enqueue out of priority order: bulk, interactive, realtime.
	_ = scheduler.Enqueue(flow.StreamChunk{FlowID: 1, PriorityClass: flow.PriorityBulk, Data: []byte{0x01}})
	_ = scheduler.Enqueue(flow.StreamChunk{FlowID: 2, PriorityClass: flow.PriorityInteractive, Data: []byte{0x02}})
	_ = scheduler.Enqueue(flow.StreamChunk{FlowID: 3, PriorityClass: flow.PriorityRealtime, Data: []byte{0x03}})
	order := make([]uint8, 0, 3)
	for {
		chunk, ok := scheduler.Next()
		if !ok {
			break
		}
		order = append(order, chunk.PriorityClass)
	}
	return len(order) == 3 &&
		order[0] == flow.PriorityRealtime &&
		order[1] == flow.PriorityInteractive &&
		order[2] == flow.PriorityBulk
}

func checkUDPStalePolicy() bool {
	m := flow.NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           14,
		FlowKind:         flow.FlowKindUDPAssociation,
		TargetKind:       flow.TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 11},
		TargetPort:       443,
		UDPFQDNMode:      flow.UDPFQDNClientResolvedNameBinding,
		NameBindingID:    repeatedByte(0xaa, 16),
		DNSAnswerSetHash: repeatedByte(0xbb, 48),
		LocalBindingMode: flow.LocalBindingTransparentFakeIP,
		PriorityClass:    flow.PriorityRealtime,
	}
	if err := m.OpenWithOptions(open, flow.FlowOptions{NowUnix: 100, TTLSeconds: 100, IdleTimeoutSeconds: 100}); err != nil {
		return false
	}
	// Stale realtime datagram (age 10 > max 5) must be dropped.
	if _, ok := m.AcceptDatagramWithOptions(open.FlowID, flow.DatagramOptions{NowUnix: 110, SentAtUnix: 100, MaxRealtimeAgeSeconds: 5}); ok {
		return false
	}
	// Fresh realtime datagram must be accepted.
	_, ok := m.AcceptDatagramWithOptions(open.FlowID, flow.DatagramOptions{NowUnix: 111, SentAtUnix: 108, MaxRealtimeAgeSeconds: 5})
	return ok
}

func checkTupleCooldown(now time.Time) bool {
	blocked := policy.PathScoreRecord{P50RTTMS: 60, GoodputMbps: 50, HandshakeSuccessRate: 1, SessionSurvivalRate: 1, BlockSuspectScore: 0.9}
	parked := policy.ActivateBlockSuspectCooldown(blocked, now, policy.DefaultTupleCooldown)
	if parked.CooldownUntil.IsZero() || !parked.CooldownUntil.After(now) {
		return false
	}
	// A parked tuple scores zero during the cooldown window.
	return parked.Score(now) == 0
}

func repeatedByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

const (
	// protectThroughputWarmup runs unmeasured seal+open round trips so caches,
	// the AEAD scratch state, and the allocator are warm before timing.
	protectThroughputWarmup = 2048
	// protectThroughputIterations bounds the worst-case measured runtime to
	// iterations/floor (~1s) even on a runner running exactly at the floor.
	protectThroughputIterations = 10_000
	// protectThroughputFloorOpsPerSec is deliberately generous: modern hardware
	// sustains roughly 900k seal+open round trips/sec for 1200-byte packets, so
	// this floor is ~90x below that and only trips on a gross hot-path
	// regression (accidental O(n^2) work, large per-packet allocations). It must
	// stay rock-stable on slow shared ubuntu/macos/windows CI runners.
	protectThroughputFloorOpsPerSec = 10_000
)

// protectThroughputWithinBudget reports whether a measured seal+open round-trip
// rate (ops/sec) meets the regression floor.
func protectThroughputWithinBudget(opsPerSec, floor float64) bool {
	return opsPerSec >= floor
}

// measureProtectRoundTripsPerSecond seals and opens a 1200-byte stream-data
// packet (mirroring packet/benchmark_test.go) and returns wall-clock round
// trips per second after a warmup phase.
func measureProtectRoundTripsPerSecond(warmup, iterations int) (float64, error) {
	frame, err := protocol.NewStreamDataFrame(7, bytes.Repeat([]byte{0x5a}, 1200), 0)
	if err != nil {
		return 0, err
	}
	protector := &packet.Protector{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 0x42,
		HopLayer:        1,
		Direction:       0,
		Key:             bytes.Repeat([]byte{0x33}, 32),
		StaticIV:        bytes.Repeat([]byte{0x44}, 12),
	}
	block := protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}
	roundTrip := func() error {
		sealed, err := protector.Seal(block)
		if err != nil {
			return err
		}
		_, err = protector.Open(sealed)
		return err
	}
	for i := 0; i < warmup; i++ {
		if err := roundTrip(); err != nil {
			return 0, err
		}
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if err := roundTrip(); err != nil {
			return 0, err
		}
	}
	return float64(iterations) / time.Since(start).Seconds(), nil
}
