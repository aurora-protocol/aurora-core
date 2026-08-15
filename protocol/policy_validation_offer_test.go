package protocol

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// TestPolicyAcceptValidateForOfferAcceptsMatchingSelections covers the happy
// path: the sample accept's selections all fall within the sample offer.
func TestPolicyAcceptValidateForOfferAcceptsMatchingSelections(t *testing.T) {
	if err := samplePolicyAccept().ValidateForOffer(samplePolicyOffer()); err != nil {
		t.Fatalf("matching offer rejected: %v", err)
	}
}

// TestPolicyAcceptValidateForOfferRejectsMismatchedSelections covers each
// containsUint64/minimum mismatch branch. The accept stays structurally valid
// in every case; only the offer (and for the policy case, the accept's selected
// policy) is mutated so the selection falls outside what was offered.
func TestPolicyAcceptValidateForOfferRejectsMismatchedSelections(t *testing.T) {
	cases := []struct {
		name string
		mut  func(offer *PolicyOffer, accept *PolicyAccept)
		want string
	}{
		{
			name: "selected version not offered",
			mut:  func(o *PolicyOffer, a *PolicyAccept) { o.OfferedVersions = nil },
			want: "selected version",
		},
		{
			name: "selected suite not offered",
			mut:  func(o *PolicyOffer, a *PolicyAccept) { o.OfferedSuites = []uint64{registry.SuiteHybrid768ChaCha20} },
			want: "selected suite",
		},
		{
			name: "selected method not offered",
			mut:  func(o *PolicyOffer, a *PolicyAccept) { o.OfferedMethods = []uint64{registry.MethodWebH1WS} },
			want: "selected method",
		},
		{
			name: "selected policy weaker than minimum",
			mut:  func(o *PolicyOffer, a *PolicyAccept) {
				o.MinimumPolicyID = registry.PolicyBalancedWeb
				a.SelectedPolicy = registry.PolicyFastWeb
			},
			want: "weaker than minimum",
		},
		{
			name: "selected tunnel personality not offered",
			mut:  func(o *PolicyOffer, a *PolicyAccept) { o.TunnelPersonalityOffers = []uint64{registry.PersonalityIPLite} },
			want: "selected tunnel personality",
		},
	}
	for _, tc := range cases {
		offer := samplePolicyOffer()
		accept := samplePolicyAccept()
		tc.mut(&offer, &accept)
		err := accept.ValidateForOffer(offer)
		if err == nil {
			t.Fatalf("%s: mismatch accepted", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %q, want substring %q", tc.name, err, tc.want)
		}
	}
}

// TestPolicyAcceptValidateForOfferRejectsWhenOfferIsStructurallyInvalid confirms
// the offer's ValidateStructural runs first: an offer with a reserved suite is
// rejected before any selection comparison.
func TestPolicyAcceptValidateForOfferRejectsWhenOfferIsStructurallyInvalid(t *testing.T) {
	offer := samplePolicyOffer()
	offer.OfferedSuites = []uint64{0xdead}
	if err := samplePolicyAccept().ValidateForOffer(offer); err == nil {
		t.Fatal("structurally invalid offer accepted")
	}
}

// TestPolicyAcceptValidateForOfferRejectsWhenAcceptIsStructurallyInvalid covers
// the accept's ValidateStructural path: a reserved selected version is rejected
// after the offer passes its own structural validation.
func TestPolicyAcceptValidateForOfferRejectsWhenAcceptIsStructurallyInvalid(t *testing.T) {
	accept := samplePolicyAccept()
	accept.SelectedVersion = 0xdead
	if err := accept.ValidateForOffer(samplePolicyOffer()); err == nil {
		t.Fatal("structurally invalid accept accepted")
	}
}