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

func TestSmartResolvedAdversarialProfilesRejectFast1(t *testing.T) {
	// Config validation cannot see smart's dynamic resolution, so the
	// stealth gate must refuse fast-1 for any smart-resolved profile that
	// forbids it.
	for _, pathClass := range []string{"clean", "strict", "severe"} {
		profile := SmartProfile(pathClass)
		candidate := safeCandidate(registry.RouteFast1, registry.MethodWebH2Stream, 1)
		if profile.Fast1Forbidden && candidate.PassesStealthGate(profile) {
			t.Fatalf("smart(%q) resolved to %s, which forbids fast-1, but the gate accepted it", pathClass, profile.Name)
		}
		if !profile.Fast1Forbidden && !candidate.PassesStealthGate(profile) {
			t.Fatalf("smart(%q) resolved to %s, which allows fast-1, but the gate rejected a safe candidate", pathClass, profile.Name)
		}
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

func TestSmartProfileDoesNotSilentlyEscalateToEmergencyWeb(t *testing.T) {
	got := SmartProfile("severe")
	if got.ID == registry.PolicyEmergencyWeb {
		t.Fatalf("smart profile silently escalated to emergency-web")
	}
	if got.ID != registry.PolicyAdversarialStrict {
		t.Fatalf("severe smart profile = 0x%x, want adversarial strict", got.ID)
	}
}

func TestVisibleProxyMethodsStayProfileAllowlistedWithoutStealthGate(t *testing.T) {
	custom := Profile{Name: "custom-nonstealth"}
	if safeCandidate(registry.RouteFast1, registry.MethodMasqueConnectIP, 1).PassesStealthGate(custom) {
		t.Fatalf("custom non-stealth profile should not pass MASQUE candidate")
	}
	namedEnterprise := Profile{Name: "enterprise"}
	if safeCandidate(registry.RouteFast1, registry.MethodMasqueConnectIP, 1).PassesStealthGate(namedEnterprise) {
		t.Fatalf("enterprise-named profile without explicit visible-proxy opt-in should not pass MASQUE candidate")
	}
	explicitEnterprise := Profile{Name: "enterprise", VisibleProxySemanticsAllowed: true}
	if !safeCandidate(registry.RouteFast1, registry.MethodMasqueConnectIP, 1).PassesStealthGate(explicitEnterprise) {
		t.Fatalf("explicit enterprise profile should pass MASQUE candidate")
	}
	if safeCandidate(registry.RouteFast1, registry.MethodDirectQUICLab, 1).PassesStealthGate(custom) {
		t.Fatalf("custom non-stealth profile should not pass direct QUIC candidate")
	}

	fast, _ := ProfileByID(registry.PolicyFastWeb)
	if !safeCandidate(registry.RouteFast1, registry.MethodMasqueConnectIP, 1).PassesStealthGate(fast) {
		t.Fatalf("fast-web should pass explicitly enabled MASQUE candidates")
	}
	lab, _ := ProfileByID(registry.PolicyLab)
	if !safeCandidate(registry.RouteFast1, registry.MethodDirectQUICLab, 1).PassesStealthGate(lab) {
		t.Fatalf("lab should pass direct QUIC candidates")
	}
}

func TestPACECongestionReducesPadding(t *testing.T) {
	out := ComputePACE(PaceInput{QueueDelayMS: 100, GoodputMbps: 20, PolicyID: registry.PolicyAdversarialDPI})
	if out.Mode != "pace.delay-web" || out.PaddingBudgetPercent >= 3 {
		t.Fatalf("unexpected PACE output: %+v", out)
	}
}

func TestRequiresPQPreludeSignatureMatchesSpecAdversarialProfiles(t *testing.T) {
	for _, id := range []uint64{registry.PolicyAdversarialDPI, registry.PolicyAdversarialStrict, registry.PolicyEmergencyWeb} {
		if !RequiresPQPreludeSignature(id) {
			t.Fatalf("policy 0x%x should require the PQ prelude signature", id)
		}
	}
	for _, id := range []uint64{registry.PolicyFastWeb, registry.PolicyBalancedWeb, registry.PolicyLab, 0x00, 0x7e} {
		if RequiresPQPreludeSignature(id) {
			t.Fatalf("policy 0x%x should not require the PQ prelude signature", id)
		}
	}
}
