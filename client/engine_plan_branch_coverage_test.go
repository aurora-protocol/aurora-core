package client

// Adversarial white-box coverage for the count-0 default-profile branch of
// Engine.Plan in client/client.go (28-45):
//
//	func (e Engine) Plan(caps transport.Capabilities) (Plan, error) {
//	    profile := e.Profile
//	    if profile.ID == 0 {                       // 30 — count-0
//	        profile = policy.SmartProfile("normal") // 31
//	    }                                          // 32
//	    carrierPlan, err := transport.SelectCarrierPlan(profile, caps)
//	    ...
//	}
//
// Engine.Plan selects a carrier plan from the engine's policy.Profile. When
// the caller leaves Profile at its zero value (Profile.ID == 0), Plan
// substitutes policy.SmartProfile("normal") — the documented default — before
// handing the profile to SelectCarrierPlan. Every existing client_test.go
// Engine case constructs Engine with an EXPLICIT Profile (via
// policy.ProfileByID(registry.PolicyAdversarialDPI)), so profile.ID != 0 and
// the 30-32 substitution stayed count-0 even though it is plainly reachable:
// a caller that builds a zero-valued Engine{} and calls Plan gets the normal
// profile's plan.
//
// The proof is a golden-value comparison: the plan produced by a zero-valued
// Engine{} MUST equal the plan produced by an Engine whose Profile is
// explicitly policy.SmartProfile("normal"), for the same capabilities. If 30-32
// ran, the two are identical (the zero-Profile path substituted the very same
// profile the explicit path set). If 30-32 did NOT run, the zero-Profile path
// would feed a zero profile to SelectCarrierPlan, which rejects it
// ("transport: no carrier passes policy gates") — a different, error outcome.
// So an equal, non-error plan from both paths proves the substitution ran.
//
// The capabilities {SupportsH2: true, CoverTemplateOK: true} are the minimal
// set the normal profile accepts (verified empirically: SelectCarrierPlan
// returns a non-zero plan). No context, no network, no goroutine, no helpers.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/transport"
)

func TestEnginePlanSubstitutesNormalProfileWhenProfileIDIsZero(t *testing.T) {
	// 30-32: a zero-valued Engine{} has Profile.ID == 0, so Plan substitutes
	// policy.SmartProfile("normal") before SelectCarrierPlan. The resulting
	// plan MUST equal the plan from an Engine explicitly set to that same
	// profile — proving the substitution ran (a zero profile would instead
	// fail SelectCarrierPlan with "no carrier passes policy gates").
	caps := transport.Capabilities{SupportsH2: true, CoverTemplateOK: true}

	defaultPlan, err := Engine{}.Plan(caps)
	if err != nil {
		t.Fatalf("Engine{}.Plan(%+v) err = %v, want nil (:30-32 should substitute a usable profile)", caps, err)
	}
	if defaultPlan.RouteModeID == 0 && defaultPlan.MethodID == 0 && defaultPlan.PersonalityID == 0 && defaultPlan.ShapeID == 0 {
		t.Fatalf("Engine{}.Plan(%+v) = zero-valued Plan %+v, want a real plan from the normal profile", caps, defaultPlan)
	}

	explicitPlan, err := Engine{Profile: policy.SmartProfile("normal")}.Plan(caps)
	if err != nil {
		t.Fatalf("Engine{Profile: SmartProfile(\"normal\")}.Plan(%+v) err = %v, want nil", caps, err)
	}
	if defaultPlan != explicitPlan {
		t.Fatalf("zero-Profile plan %+v != explicit SmartProfile(\"normal\") plan %+v; :30-32 should substitute the same profile", defaultPlan, explicitPlan)
	}
}
