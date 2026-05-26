package policy

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

func safeCandidate(route, method uint64, score float64) Candidate {
	return Candidate{
		RouteModeID:             route,
		MethodID:                method,
		ValidSignatures:         true,
		ValidDescriptor:         true,
		ValidCoverTemplate:      true,
		ValidReplayState:        true,
		ValidCryptographicSuite: true,
		AbusePolicySatisfied:    true,
		LocalPolicySatisfied:    true,
		NoRawFirstPayload:       true,
		NoVisibleProxySemantics: true,
		NoFixedPublicAuthPath:   true,
		NoCustomPublicHeaders:   true,
		ProbeNeutralFailure:     true,
		CoverProfilePlausible:   true,
		Score: PathScoreRecord{
			P50RTTMS:             80 * (1 / score),
			JitterMS:             10,
			LossPercent:          0.2,
			GoodputMbps:          50,
			HandshakeSuccessRate: 0.99,
			SessionSurvivalRate:  0.98,
			CarrierAffinityScore: 0.5,
		},
	}
}

func TestStrictRejectsFast1AndQUIC(t *testing.T) {
	profile, _ := ProfileByID(registry.PolicyAdversarialStrict)
	if safeCandidate(registry.RouteFast1, registry.MethodWebH2Stream, 1).PassesStealthGate(profile) {
		t.Fatalf("strict profile should reject fast-1")
	}
	if safeCandidate(registry.RouteBridgeSplit, registry.MethodWebH3ExtDgram, 1).PassesStealthGate(profile) {
		t.Fatalf("strict profile should reject QUIC by default")
	}
}

func TestAdversarialSelectionRequiresLowLatencyOverrideForFast1(t *testing.T) {
	profile, _ := ProfileByID(registry.PolicyAdversarialDPI)
	candidates := []Candidate{
		safeCandidate(registry.RouteFast1, registry.MethodWebH2Stream, 2),
		safeCandidate(registry.RouteSplit2, registry.MethodWebH2Stream, 1),
	}
	got, err := Select(profile, candidates, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.RouteModeID != registry.RouteSplit2 {
		t.Fatalf("expected split-2 without override, got route 0x%x", got.RouteModeID)
	}
	got, err = Select(profile, candidates, time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.RouteModeID != registry.RouteFast1 {
		t.Fatalf("expected fast-1 with override, got route 0x%x", got.RouteModeID)
	}
}

func TestPACECongestionReducesPadding(t *testing.T) {
	out := ComputePACE(PaceInput{QueueDelayMS: 100, GoodputMbps: 20, PolicyID: registry.PolicyAdversarialDPI})
	if out.Mode != "pace.delay-web" || out.PaddingBudgetPercent >= 3 {
		t.Fatalf("unexpected PACE output: %+v", out)
	}
}
