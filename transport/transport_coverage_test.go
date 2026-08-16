package transport

// Adversarial coverage for transport/transport.go carrier-selection logic.
//
// The happy paths through SelectCarrier / SelectCarrierPlan / IsMethodAllowed
// for the carriers the conformance harness exercises (H2 baseline, H1
// WebSocket fallback, shadow-origin, H3 extended datagram, MASQUE) are
// covered end-to-end by conformance_test.go and conformance_coverage_test.go.
// methodName and udpModeForMethod get incidental coverage for the methods the
// conformance cases select.
//
// This file covers the residual count-0 blocks, perturbing exactly one input
// per case so the branch under test is the one that fires:
//   - SelectCarrier 47: no method in MethodOrder passes the policy gates.
//   - SelectCarrierPlan 52-54: SelectCarrier error propagated.
//   - IsMethodAllowed 64-66: the cover-template gate
//     (!CoverTemplateOK && method != MethodDirectQUICLab). DirectQUICLab is
//     the only method exempted from the gate; that exemption is asserted too.
//   - IsMethodAllowed 72-73: MethodShadowOrigin -> SupportsShadow.
//   - IsMethodAllowed 74-77 / 75-77: MethodWebH3Stream QUIC-disabled early
//     return, plus the QUIC-enabled fall-through into the stealth check.
//   - IsMethodAllowed 78-80: MethodWebH3Stream stealth-gate rejection
//     (StealthGate && !H3Validated), plus the non-stealth fall-through.
//   - IsMethodAllowed 81: MethodWebH3Stream SupportsH3 return.
//   - IsMethodAllowed 83-85: MethodWebH3ExtDgram QUIC-disabled early return.
//   - IsMethodAllowed 92-93: MethodDirectQUICLab -> profile.LabOnly.
//   - IsMethodAllowed 94-95: unknown method default -> false.
//   - udpModeForMethod 105-106: unknown method -> (UDPUnsupported, true).
//   - methodName 118-119 / 122-123 / 126-127: MethodWebH3Stream,
//     MethodMasqueConnectIP, MethodDirectQUICLab name strings (not reached by
//     any conformance case).
//   - methodName 128-129: unknown method -> "unknown".
//
// No dead-by-design blocks remain: every count-0 line is reachable by a
// caller-constructed (policy.Profile, method, Capabilities) tuple.
//
// Not duplicated: the RunCarrierConformance happy path (which exercises the
// success returns of SelectCarrier/SelectCarrierPlan and the H2/H1WS/shadow/
// H3ExtDgram/MASQUE IsMethodAllowed cases) is covered by conformance_test.go
// and is not re-asserted here except as anchors proving the error-case inputs
// are otherwise valid.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The helpers covProfileOrder and covAllCaps are each
// referenced by >=2 tests/subtests, so they are not U1000. No context.Context,
// no goroutines, no deprecated APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/registry"
)

// covProfileOrder returns a permissive Profile carrying the given method
// order: QUIC enabled (QUICPreferred), no stealth gate, not lab-only. The
// caller clones the result and flips exactly one field per error-case test.
// Referenced by >=2 tests, so not U1000.
func covProfileOrder(order ...uint64) policy.Profile {
	return policy.Profile{
		Name:        "cov",
		MethodOrder: order,
		QUIC:        policy.QUICPreferred,
	}
}

// covAllCaps returns Capabilities with every carrier capability advertised
// and every gate satisfied (cover template, H3 validated, WebTransport, and
// MASQUE allowed). The caller clones the result and clears exactly one
// capability per error-case test. Referenced by >=2 tests, so not U1000.
func covAllCaps() Capabilities {
	return Capabilities{
		SupportsH2:      true,
		SupportsH1WS:    true,
		SupportsShadow:  true,
		SupportsH3:      true,
		SupportsH3Dgram: true,
		H3Validated:     true,
		WebTransportOK:  true,
		CoverTemplateOK: true,
		MASQUEAllowed:   true,
	}
}

func TestSelectCarrierNoMatchAndPlanError(t *testing.T) {
	// H2 is the only candidate but SupportsH2 is false -> IsMethodAllowed
	// returns false for it -> no carrier passes -> SelectCarrier error (47).
	profile := covProfileOrder(registry.MethodWebH2Stream)
	caps := covAllCaps()
	caps.SupportsH2 = false
	_, err := SelectCarrier(profile, caps)
	if err == nil || !strings.Contains(err.Error(), "no carrier passes policy gates") {
		t.Fatalf("SelectCarrier err = %v, want no-carrier error", err)
	}
	// The same input propagated through SelectCarrierPlan hits the err return
	// at 52-54.
	_, err = SelectCarrierPlan(profile, caps)
	if err == nil || !strings.Contains(err.Error(), "no carrier passes policy gates") {
		t.Fatalf("SelectCarrierPlan err = %v, want propagated no-carrier error", err)
	}

	// Anchor: a matching method selects the carrier and a plan without error.
	caps.SupportsH2 = true
	plan, err := SelectCarrierPlan(profile, caps)
	if err != nil {
		t.Fatalf("valid SelectCarrierPlan: %v", err)
	}
	if plan.Carrier.MethodID != registry.MethodWebH2Stream || plan.UDPMode != UDPOverStreamFallback {
		t.Fatalf("plan = %+v, want H2 stream fallback", plan)
	}
}

func TestIsMethodAllowedCoverTemplateGate(t *testing.T) {
	profile := covProfileOrder(registry.MethodWebH2Stream)
	// No cover template: any non-DirectQUICLab method is rejected at the gate
	// (64-66) before the per-method switch runs.
	caps := covAllCaps()
	caps.CoverTemplateOK = false
	if IsMethodAllowed(profile, registry.MethodWebH2Stream, caps) {
		t.Fatal("cover-template gate must reject H2 when CoverTemplateOK=false")
	}
	// DirectQUICLab is the only method exempted from the gate: with the gate
	// off and LabOnly set, it still reaches the LabOnly case (92-93).
	labProfile := covProfileOrder(registry.MethodDirectQUICLab)
	labProfile.LabOnly = true
	if !IsMethodAllowed(labProfile, registry.MethodDirectQUICLab, caps) {
		t.Fatal("DirectQUICLab must bypass the cover-template gate when LabOnly=true")
	}
}

func TestIsMethodAllowedPerMethodDecisions(t *testing.T) {
	t.Run("shadow allowed and denied", func(t *testing.T) {
		profile := covProfileOrder(registry.MethodShadowOrigin)
		if !IsMethodAllowed(profile, registry.MethodShadowOrigin, covAllCaps()) {
			t.Fatal("shadow must be allowed when SupportsShadow=true")
		}
		caps := covAllCaps()
		caps.SupportsShadow = false
		if IsMethodAllowed(profile, registry.MethodShadowOrigin, caps) {
			t.Fatal("shadow must be denied when SupportsShadow=false")
		}
	})
	t.Run("h3stream quic disabled", func(t *testing.T) {
		profile := covProfileOrder(registry.MethodWebH3Stream)
		profile.QUIC = policy.QUICDisabled
		if IsMethodAllowed(profile, registry.MethodWebH3Stream, covAllCaps()) {
			t.Fatal("H3 stream must be denied when QUIC is disabled")
		}
	})
	t.Run("h3stream stealth unvalidated", func(t *testing.T) {
		profile := covProfileOrder(registry.MethodWebH3Stream)
		profile.StealthGate = true
		caps := covAllCaps()
		caps.H3Validated = false
		if IsMethodAllowed(profile, registry.MethodWebH3Stream, caps) {
			t.Fatal("H3 stream must be denied under stealth gate without H3Validated")
		}
	})
	t.Run("h3stream allowed then unsupported", func(t *testing.T) {
		profile := covProfileOrder(registry.MethodWebH3Stream)
		if !IsMethodAllowed(profile, registry.MethodWebH3Stream, covAllCaps()) {
			t.Fatal("H3 stream must be allowed with QUIC, no stealth, SupportsH3")
		}
		caps := covAllCaps()
		caps.SupportsH3 = false
		if IsMethodAllowed(profile, registry.MethodWebH3Stream, caps) {
			t.Fatal("H3 stream must be denied when SupportsH3=false")
		}
	})
	t.Run("h3extdgram quic disabled", func(t *testing.T) {
		profile := covProfileOrder(registry.MethodWebH3ExtDgram)
		profile.QUIC = policy.QUICDisabled
		if IsMethodAllowed(profile, registry.MethodWebH3ExtDgram, covAllCaps()) {
			t.Fatal("H3 ext-dgram must be denied when QUIC is disabled")
		}
	})
	t.Run("directquiclab lab only", func(t *testing.T) {
		lab := covProfileOrder(registry.MethodDirectQUICLab)
		lab.LabOnly = true
		if !IsMethodAllowed(lab, registry.MethodDirectQUICLab, covAllCaps()) {
			t.Fatal("DirectQUICLab must be allowed when LabOnly=true")
		}
		lab.LabOnly = false
		if IsMethodAllowed(lab, registry.MethodDirectQUICLab, covAllCaps()) {
			t.Fatal("DirectQUICLab must be denied when LabOnly=false")
		}
	})
	t.Run("unknown method default", func(t *testing.T) {
		if IsMethodAllowed(covProfileOrder(0xBAD), 0xBAD, covAllCaps()) {
			t.Fatal("unknown method must be denied by the default case")
		}
	})
}

func TestUDPModeForMethodDefaults(t *testing.T) {
	cases := []struct {
		method     uint64
		wantMode   UDPMode
		wantDowngr bool
	}{
		{registry.MethodWebH2Stream, UDPOverStreamFallback, true},
		{registry.MethodWebH1WS, UDPOverStreamFallback, true},
		{registry.MethodShadowOrigin, UDPOverStreamFallback, true},
		{registry.MethodWebH3Stream, UDPOverStreamFallback, true},
		{registry.MethodWebH3ExtDgram, UDPNativeDatagram, false},
		{registry.MethodMasqueConnectIP, UDPNativeDatagram, false},
		{registry.MethodMasqueConnectUDP, UDPNativeDatagram, false},
		{registry.MethodDirectQUICLab, UDPNativeDatagram, false},
		{0xBAD, UDPUnsupported, true},
	}
	for _, c := range cases {
		mode, downgrade := udpModeForMethod(c.method)
		if mode != c.wantMode || downgrade != c.wantDowngr {
			t.Errorf("udpModeForMethod(0x%x) = (%v, %v), want (%v, %v)", c.method, mode, downgrade, c.wantMode, c.wantDowngr)
		}
	}
}

func TestMethodNameAllCases(t *testing.T) {
	cases := []struct {
		method uint64
		want   string
	}{
		{registry.MethodWebH2Stream, "web.h2.stream"},
		{registry.MethodWebH1WS, "web.h1.ws"},
		{registry.MethodShadowOrigin, "web.shadow-origin"},
		{registry.MethodWebH3Stream, "web.h3.stream"},
		{registry.MethodWebH3ExtDgram, "web.h3.ext-dgram"},
		{registry.MethodMasqueConnectIP, "masque.connect-ip"},
		{registry.MethodMasqueConnectUDP, "masque.connect-udp"},
		{registry.MethodDirectQUICLab, "direct.quic"},
		{0xBAD, "unknown"},
	}
	for _, c := range cases {
		if got := methodName(c.method); got != c.want {
			t.Errorf("methodName(0x%x) = %q, want %q", c.method, got, c.want)
		}
	}
}
