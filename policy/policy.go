package policy

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

type QUICMode string

const (
	QUICPreferred     QUICMode = "preferred"
	QUICOpportunistic QUICMode = "opportunistic"
	QUICValidated     QUICMode = "validated"
	QUICDisabled      QUICMode = "disabled"
	QUICDirectLab     QUICMode = "direct-lab"
)

type Profile struct {
	ID                 uint64
	Name               string
	DefaultRoute       uint64
	MethodOrder        []uint64
	QUIC               QUICMode
	DefaultPersonality uint64
	DefaultShape       uint64
	StealthGate        bool
	SafetyGate         bool
	Fast1Forbidden     bool
	LabOnly            bool
}

func ProfileByID(id uint64) (Profile, error) {
	for _, p := range allProfiles {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("policy: unknown profile 0x%x", id)
}

func ProfileByName(name string) (Profile, error) {
	for _, p := range allProfiles {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("policy: unknown profile %q", name)
}

func SmartProfile(pathClass string) Profile {
	switch pathClass {
	case "clean":
		p, _ := ProfileByID(registry.PolicyFastWeb)
		return p
	case "strict":
		p, _ := ProfileByID(registry.PolicyAdversarialStrict)
		return p
	case "severe":
		p, _ := ProfileByID(registry.PolicyEmergencyWeb)
		return p
	default:
		p, _ := ProfileByID(registry.PolicyAdversarialDPI)
		return p
	}
}

var allProfiles = []Profile{
	{
		ID:                 registry.PolicyFastWeb,
		Name:               "fast-web",
		DefaultRoute:       registry.RouteFast1,
		MethodOrder:        []uint64{registry.MethodWebH3ExtDgram, registry.MethodWebH3Stream, registry.MethodWebH2Stream, registry.MethodWebH1WS},
		QUIC:               QUICPreferred,
		DefaultPersonality: registry.PersonalityFullIP,
		DefaultShape:       registry.ShapeLight,
		SafetyGate:         true,
	},
	{
		ID:                 registry.PolicyBalancedWeb,
		Name:               "balanced-web",
		DefaultRoute:       registry.RouteAuto,
		MethodOrder:        []uint64{registry.MethodWebH2Stream, registry.MethodWebH3ExtDgram, registry.MethodWebH1WS, registry.MethodShadowOrigin},
		QUIC:               QUICOpportunistic,
		DefaultPersonality: registry.PersonalityProxyFlow,
		DefaultShape:       registry.ShapeLight,
		StealthGate:        true,
		SafetyGate:         true,
	},
	{
		ID:                 registry.PolicyAdversarialDPI,
		Name:               "adversarial-dpi",
		DefaultRoute:       registry.RouteSplit2,
		MethodOrder:        []uint64{registry.MethodWebH2Stream, registry.MethodWebH1WS, registry.MethodShadowOrigin, registry.MethodWebH3ExtDgram},
		QUIC:               QUICValidated,
		DefaultPersonality: registry.PersonalityProxyFlow,
		DefaultShape:       registry.ShapeNormal,
		StealthGate:        true,
		SafetyGate:         true,
	},
	{
		ID:                 registry.PolicyAdversarialStrict,
		Name:               "adversarial-dpi-strict",
		DefaultRoute:       registry.RouteBridgeSplit,
		MethodOrder:        []uint64{registry.MethodShadowOrigin, registry.MethodWebH2Stream, registry.MethodWebH1WS},
		QUIC:               QUICDisabled,
		DefaultPersonality: registry.PersonalityProxyFlow,
		DefaultShape:       registry.ShapeStrict,
		StealthGate:        true,
		SafetyGate:         true,
		Fast1Forbidden:     true,
	},
	{
		ID:                 registry.PolicyEmergencyWeb,
		Name:               "emergency-web",
		DefaultRoute:       registry.RouteBridgeSplit,
		MethodOrder:        []uint64{registry.MethodWebH1WS, registry.MethodShadowOrigin, registry.MethodWebH2Stream},
		QUIC:               QUICDisabled,
		DefaultPersonality: registry.PersonalityProxyFlow,
		DefaultShape:       registry.ShapeEmergency,
		StealthGate:        true,
		SafetyGate:         true,
		Fast1Forbidden:     true,
	},
	{
		ID:           registry.PolicyLab,
		Name:         "lab",
		DefaultRoute: registry.RouteFast1,
		MethodOrder:  []uint64{registry.MethodDirectQUICLab},
		QUIC:         QUICDirectLab,
		SafetyGate:   true,
		LabOnly:      true,
		DefaultShape: registry.ShapeLight,
	},
}

type Candidate struct {
	RelayID                  string
	RouteModeID              uint64
	MethodID                 uint64
	ValidSignatures          bool
	ValidDescriptor          bool
	ValidCoverTemplate       bool
	ValidReplayState         bool
	ValidCryptographicSuite  bool
	AbusePolicySatisfied     bool
	LocalPolicySatisfied     bool
	NoRawFirstPayload        bool
	NoVisibleProxySemantics  bool
	NoFixedPublicAuthPath    bool
	NoCustomPublicHeaders    bool
	ProbeNeutralFailure      bool
	CoverProfilePlausible    bool
	QUICResidualBlockSuspect bool
	SuspiciousFallback       bool
	Score                    PathScoreRecord
}

func (c Candidate) PassesSafetyGate() bool {
	return c.ValidSignatures &&
		c.ValidDescriptor &&
		c.ValidCoverTemplate &&
		c.ValidReplayState &&
		c.ValidCryptographicSuite &&
		c.AbusePolicySatisfied &&
		c.LocalPolicySatisfied
}

func (c Candidate) PassesStealthGate(profile Profile) bool {
	if isMASQUEMethod(c.MethodID) && !AllowsMASQUE(profile) {
		return false
	}
	if c.MethodID == registry.MethodDirectQUICLab && !allowsDirectQUICLab(profile) {
		return false
	}
	if !profile.StealthGate {
		return true
	}
	if c.RouteModeID == registry.RouteFast1 && profile.Fast1Forbidden {
		return false
	}
	if isMASQUEMethod(c.MethodID) || c.MethodID == registry.MethodDirectQUICLab {
		return false
	}
	if profile.QUIC == QUICDisabled && (c.MethodID == registry.MethodWebH3ExtDgram || c.MethodID == registry.MethodWebH3Stream) {
		return false
	}
	if c.QUICResidualBlockSuspect && (c.MethodID == registry.MethodWebH3ExtDgram || c.MethodID == registry.MethodWebH3Stream) {
		return false
	}
	return c.NoRawFirstPayload &&
		c.NoVisibleProxySemantics &&
		c.NoFixedPublicAuthPath &&
		c.NoCustomPublicHeaders &&
		c.ProbeNeutralFailure &&
		c.CoverProfilePlausible &&
		!c.SuspiciousFallback
}

func AllowsMASQUE(profile Profile) bool {
	if profile.StealthGate {
		return false
	}
	switch profile.ID {
	case registry.PolicyFastWeb, registry.PolicyLab:
		return true
	default:
		return profile.Name == "enterprise"
	}
}

func isMASQUEMethod(method uint64) bool {
	return method == registry.MethodMasqueConnectIP || method == registry.MethodMasqueConnectUDP
}

func allowsDirectQUICLab(profile Profile) bool {
	return profile.LabOnly || profile.ID == registry.PolicyLab
}

type PathScoreRecord struct {
	MinRTTMS             float64
	P50RTTMS             float64
	P95RTTMS             float64
	JitterMS             float64
	LossPercent          float64
	ReorderingPercent    float64
	GoodputMbps          float64
	HandshakeSuccessRate float64
	SessionSurvivalRate  float64
	QUICSuccessRate      float64
	H2SuccessRate        float64
	QueueDelayMS         float64
	CarrierAffinityScore float64
	BlockSuspectScore    float64
	FingerprintRiskScore float64
	CooldownUntil        time.Time
}

func (r PathScoreRecord) Score(now time.Time) float64 {
	if !r.CooldownUntil.IsZero() && now.Before(r.CooldownUntil) {
		return 0
	}
	if r.BlockSuspectScore > 0.65 || r.FingerprintRiskScore > 0.65 {
		return 0
	}
	latency := clamp01((350 - r.P50RTTMS) / (350 - 40))
	loss := clamp01((5 - r.LossPercent) / (5 - 0.1))
	jitter := clamp01((100 - r.JitterMS) / (100 - 5))
	goodput := clamp01(math.Log(1+r.GoodputMbps) / math.Log(1+100))
	stability := clamp01(0.7*r.HandshakeSuccessRate + 0.3*r.SessionSurvivalRate)
	congestion := clamp01(1 - r.QueueDelayMS/250)
	return 0.22*latency +
		0.20*loss +
		0.16*jitter +
		0.16*goodput +
		0.12*stability +
		0.08*clamp01(r.CarrierAffinityScore) +
		0.06*congestion
}

func Select(profile Profile, candidates []Candidate, now time.Time, lowLatencyOverride bool) (Candidate, error) {
	filtered := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if !c.PassesSafetyGate() || !c.PassesStealthGate(profile) {
			continue
		}
		if profile.ID == registry.PolicyAdversarialDPI && c.RouteModeID == registry.RouteFast1 && !lowLatencyOverride {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return Candidate{}, fmt.Errorf("policy: no candidate passes gates")
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].Score.Score(now) > filtered[j].Score.Score(now)
	})
	return filtered[0], nil
}

type PaceInput struct {
	SmoothedRTTMS      float64
	RTTVarianceMS      float64
	QueueDelayMS       float64
	LossRate           float64
	ReorderingRate     float64
	GoodputMbps        float64
	ApplicationLatency string
	MethodID           uint64
	PolicyID           uint64
	BlockSuspectScore  float64
}

type PaceOutput struct {
	Mode                 string
	PacingRateMbps       float64
	BurstLimitPackets    int
	SendWindowPackets    int
	FECRate              float64
	PaddingBudgetPercent float64
	ProbeInterval        time.Duration
	BackupPath           bool
	MethodSwitch         bool
}

func ComputePACE(in PaceInput) PaceOutput {
	out := PaceOutput{
		Mode:                 "pace.bbr-web",
		PacingRateMbps:       math.Max(0.1, in.GoodputMbps*0.95),
		BurstLimitPackets:    16,
		SendWindowPackets:    64,
		PaddingBudgetPercent: 3,
		ProbeInterval:        30 * time.Second,
	}
	if in.QueueDelayMS > 80 {
		out.Mode = "pace.delay-web"
		out.PacingRateMbps = math.Max(0.1, in.GoodputMbps*0.75)
		out.BurstLimitPackets = 6
		out.PaddingBudgetPercent = 1
	}
	if in.LossRate > 0.03 && in.BlockSuspectScore < 0.5 {
		out.Mode = "pace.loss-rescue"
		out.FECRate = 0.05
		out.BurstLimitPackets = 4
	}
	if in.PolicyID == registry.PolicyAdversarialStrict || in.PolicyID == registry.PolicyEmergencyWeb {
		out.Mode = "pace.strict"
		out.PaddingBudgetPercent = 8
		out.ProbeInterval = 2 * time.Minute
	}
	if in.BlockSuspectScore > 0.65 {
		out.BackupPath = true
		out.MethodSwitch = true
		out.PaddingBudgetPercent = 0
	}
	return out
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
