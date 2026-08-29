package handshake

import (
	"context"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// fast1ForbiddenPolicies are the profiles whose stealth gate forbids the fast-1
// route unconditionally (spec sections 21.4/21.5).
var fast1ForbiddenPolicies = []uint64{registry.PolicyAdversarialStrict, registry.PolicyEmergencyWeb}

func fast1ProxyOffer(policyID uint64) protocol.PolicyOffer {
	return protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         policyID,
		RequestedPolicyID:       policyID,
		RequestedRouteModeID:    registry.RouteFast1,
		RequestedShapeID:        registry.ShapeStrict,
		TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
	}
}

func fast1ProxyAccept(policyID uint64) protocol.PolicyAccept {
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            policyID,
		SelectedRouteModeID:       registry.RouteFast1,
		SelectedShape:             registry.ShapeStrict,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	}
}

func TestValidateClientPolicyAcceptRejectsFast1UnderFast1ForbiddenPolicies(t *testing.T) {
	for _, policyID := range fast1ForbiddenPolicies {
		err := validateClientPolicyAccept(1_000_000, policyAcceptValidationDeployment{}, fast1ProxyOffer(policyID), fast1ProxyAccept(policyID))
		if err == nil || !strings.Contains(err.Error(), "fast-1") {
			t.Fatalf("policy 0x%x accepted the fast-1 route: err = %v", policyID, err)
		}
	}
	// A fast-1-tolerant policy keeps working with the same offer shape.
	err := validateClientPolicyAccept(1_000_000, policyAcceptValidationDeployment{}, fast1ProxyOffer(registry.PolicyBalancedWeb), fast1ProxyAccept(registry.PolicyBalancedWeb))
	if err != nil {
		t.Fatalf("balanced-web fast-1 accept rejected: %v", err)
	}
}

func TestValidateClientPolicyRejectsFast1WhenMinimumPolicyForbidsIt(t *testing.T) {
	for _, policyID := range fast1ForbiddenPolicies {
		err := validateClientPolicy(fast1ProxyOffer(policyID), protocol.ClientTransportHints{}, registry.SuiteHybrid768AESGCM)
		if err == nil || !strings.Contains(err.Error(), "fast-1") {
			t.Fatalf("policy 0x%x offer requesting fast-1 accepted: err = %v", policyID, err)
		}
	}
	if err := validateClientPolicy(fast1ProxyOffer(registry.PolicyBalancedWeb), protocol.ClientTransportHints{}, registry.SuiteHybrid768AESGCM); err != nil {
		t.Fatalf("balanced-web fast-1 offer rejected: %v", err)
	}
}

func TestNewFixedProxyPolicySelectorRejectsFast1UnderFast1ForbiddenPolicies(t *testing.T) {
	for _, policyID := range fast1ForbiddenPolicies {
		selector, err := NewFixedProxyPolicySelector(registry.SuiteHybrid768AESGCM, policyID, registry.RouteFast1, registry.ShapeStrict)
		if err == nil || !strings.Contains(err.Error(), "fast-1") {
			t.Fatalf("policy 0x%x fixed selector accepted fast-1: err = %v", policyID, err)
		}
		if selector != nil {
			t.Fatalf("policy 0x%x fixed selector returned non-nil on error", policyID)
		}
	}
	selector, err := NewFixedProxyPolicySelector(registry.SuiteHybrid768AESGCM, registry.PolicyAdversarialStrict, registry.RouteSplit2, registry.ShapeStrict)
	if err != nil {
		t.Fatalf("strict split-2 fixed selector rejected: %v", err)
	}
	offer := fast1ProxyOffer(registry.PolicyAdversarialStrict)
	offer.RequestedRouteModeID = registry.RouteSplit2
	if _, err := selector.SelectPolicy(context.Background(), offer, protocol.ClientTransportHints{}); err != nil {
		t.Fatalf("strict split-2 selection failed: %v", err)
	}
}
