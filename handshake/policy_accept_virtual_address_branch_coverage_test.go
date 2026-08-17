package handshake

// Adversarial white-box coverage for the count-0 VirtualAddressAssignment
// field-validation guards of validateClientPolicyAccept
// (handshake/client.go:616-627). After the protocol layer's
// PolicyAccept.ValidateForOffer (:595) / ValidateStructural (:537) accept the
// accept (which only checks the assignment's PRESENCE per tunnel personality —
// required for PersonalityIPLite/FullIP, forbidden for ProxyFlow — never its
// fields), validateClientPolicyApply runs the handshake-specific field checks
// in order:
//
//   - :616 if len(assignment.LeaseID) != 16
//             -> "handshake: virtual address lease ID length N, want 16"
//   - :619 if assignment.AddressFamily == 0 || len(ClientAddress) == 0 || len > 16
//             -> "handshake: invalid virtual client address"
//   - :622 if int(assignment.PrefixLength) > len(assignment.ClientAddress)*8
//             -> "handshake: virtual address prefix exceeds address width"
//   - :625 if assignment.DNSServerHint != nil && (len == 0 || len > 16)
//             -> "handshake: invalid virtual DNS server hint"
//   - :628 if assignment.LeaseExpiryUnix <= now
//             -> "handshake: virtual address lease expired"  (ALREADY covered)
//
// Coverage targets (baseline measured on main; the four error bodies are COUNT
// 0 while each condition was already evaluated once by the existing expired-
// lease test, client_test.go:418, which carries a fully-valid assignment except
// for an expired LeaseExpiryUnix — so it passes :616/:619/:622/:625 and fails at
// :628, leaving the four earlier error bodies unexercised):
//   - client.go:616.36,618.4 0  — LeaseID-length error
//   - client.go:619.112,621.4 0 — invalid-ClientAddress error
//   - client.go:622.69,624.4 0  — prefix-exceeds-width error
//   - client.go:625.116,627.4 0 — invalid-DNSServerHint error
//
// Reuses the existing validClientVirtualAddress(now) fixture (client_test.go:660),
// which carries a fully-valid assignment (LeaseID 16, AddressFamily 1, ClientAddress
// 4, PrefixLength 24 <= 32, DNSServerHint 4, LeaseExpiryUnix now+1h). Each subtest
// clones it and perturbs ONE field so the prior checks still pass and the target
// guard is the first to fail. validateClientPolicyAccept is unexported, so this
// is an in-package test that calls it directly with a crafted (now, deployment,
// offer, accept) — no full handshake, no provider/driver, no network.
//
// The offer/accept/deployment triple is built to pass ValidateForOffer (:595) and
// the handshake pre-assignment checks (:598-614): SelectedVersion/Suite/Method/
// Policy/RouteMode/Shape match the offer, SelectedTunnelPersonality=PersonalityIPLite
// (so ValidateStructural REQUIRES a non-nil assignment), empty FallbackMethods.
// No nil-context (no context.Context at all). No goroutines. This file adds one
// TestXxx with four t.Run subtests plus two small helpers, all referenced, so no
// U1000 surface (CI staticcheck@v0.7.0 will confirm).

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// policyAcceptValidationDeployment implements the validateClientPolicyAccept
// deployment interface { Suite() uint64; Method() uint64 } for the fixed suite/
// method the offer/accept below select. Referenced by the test below.
type policyAcceptValidationDeployment struct{}

func (policyAcceptValidationDeployment) Suite() uint64  { return registry.SuiteHybrid768AESGCM }
func (policyAcceptValidationDeployment) Method() uint64 { return registry.MethodWebH2Stream }

// policyAcceptValidationOffer returns a PolicyOffer whose offered/selected fields
// match policyAcceptValidationAccept, so ValidateForOffer passes for an IPLite
// accept carrying an assignment. Referenced by the test below.
func policyAcceptValidationOffer() protocol.PolicyOffer {
	return protocol.PolicyOffer{
		OfferedVersions:         []uint64{registry.Version20},
		OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
		OfferedMethods:          []uint64{registry.MethodWebH2Stream},
		MinimumPolicyID:         registry.PolicyAdversarialDPI,
		RequestedPolicyID:       registry.PolicyAdversarialDPI,
		RequestedRouteModeID:    registry.RouteSplit2,
		RequestedShapeID:        registry.ShapeNormal,
		TunnelPersonalityOffers: []uint64{registry.PersonalityIPLite},
	}
}

// policyAcceptValidationAccept returns a structurally-valid IPLite PolicyAccept
// carrying the given assignment, matching the offer above. Referenced by the
// test below.
func policyAcceptValidationAccept(assignment *protocol.VirtualAddressAssignment) protocol.PolicyAccept {
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyAdversarialDPI,
		SelectedRouteModeID:       registry.RouteSplit2,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityIPLite,
		VirtualAddressAssignment:  assignment,
	}
}

func TestValidateClientPolicyAcceptRejectsInvalidVirtualAddressAssignment(t *testing.T) {
	nowTime := time.Unix(1_000_000, 0)
	now := uint64(nowTime.Unix())
	offer := policyAcceptValidationOffer()

	// :616 — a LeaseID shorter than 16 fails the first field check before any
	// other assignment field is read.
	t.Run("lease ID length", func(t *testing.T) {
		assignment := validClientVirtualAddress(nowTime)
		assignment.LeaseID = bytes.Repeat([]byte{0x71}, 15) // 15, not 16
		err := validateClientPolicyAccept(now, policyAcceptValidationDeployment{}, offer, policyAcceptValidationAccept(assignment))
		if err == nil || !strings.Contains(err.Error(), "lease ID length") {
			t.Fatalf("err = %v, want non-nil containing \"lease ID length\" (:616)", err)
		}
	})

	// :619 — a zero AddressFamily fails the client-address check (LeaseID still
	// valid, so :616 passes first).
	t.Run("client address", func(t *testing.T) {
		assignment := validClientVirtualAddress(nowTime)
		assignment.AddressFamily = 0
		err := validateClientPolicyAccept(now, policyAcceptValidationDeployment{}, offer, policyAcceptValidationAccept(assignment))
		if err == nil || !strings.Contains(err.Error(), "invalid virtual client address") {
			t.Fatalf("err = %v, want non-nil containing \"invalid virtual client address\" (:619)", err)
		}
	})

	// :622 — a PrefixLength exceeding the address width (33 > 4*8=32) fails the
	// prefix check (LeaseID/address still valid).
	t.Run("prefix exceeds width", func(t *testing.T) {
		assignment := validClientVirtualAddress(nowTime)
		assignment.PrefixLength = 33 // 4-byte address => width 32
		err := validateClientPolicyAccept(now, policyAcceptValidationDeployment{}, offer, policyAcceptValidationAccept(assignment))
		if err == nil || !strings.Contains(err.Error(), "prefix exceeds address width") {
			t.Fatalf("err = %v, want non-nil containing \"prefix exceeds address width\" (:622)", err)
		}
	})

	// :625 — a DNSServerHint longer than 16 fails the DNS-hint check (all prior
	// fields valid, non-expired lease, so :616/:619/:622/:628 pass and :625 fires).
	t.Run("DNS server hint", func(t *testing.T) {
		assignment := validClientVirtualAddress(nowTime)
		assignment.DNSServerHint = bytes.Repeat([]byte{0x08}, 17) // 17, not <=16
		err := validateClientPolicyAccept(now, policyAcceptValidationDeployment{}, offer, policyAcceptValidationAccept(assignment))
		if err == nil || !strings.Contains(err.Error(), "invalid virtual DNS server hint") {
			t.Fatalf("err = %v, want non-nil containing \"invalid virtual DNS server hint\" (:625)", err)
		}
	})
}
