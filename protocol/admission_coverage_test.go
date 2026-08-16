package protocol

// Adversarial coverage for protocol/admission.go.
//
// The happy PolicyAccept encode/decode round trip (without a virtual address
// assignment), ValidateStructural for a valid proxy-flow accept, the
// VirtualAddressAssignment round trip WITH a DNS server hint, and the
// reserved-personality / fallback-method / extension validation branches are
// already covered by policy_validation_test.go, policy_validation_offer_test.go,
// bootstrap_test.go, and fuzz_test.go, and are not re-asserted here except as
// anchors.
//
// This file covers the residual count-0 blocks, perturbing exactly one input
// per case so the branch under test is the one that fires:
//
//   - VirtualAddressAssignment.EncodeTo 412: the nil-DNSServerHint branch
//     (WriteBool(false), no hint bytes). The existing grammar test uses a
//     non-nil hint, so the else branch (413-417) is covered and this nil
//     branch is not.
//   - PolicyAccept.EncodeTo 463: the non-nil assignment branch (WriteUint8(1)
//     + assignment.EncodeTo). The sample fixture carries no assignment, so
//     the nil branch (461-462, WriteUint8(0)) is covered and this branch is
//     not.
//   - DecodePolicyAccept 483: the has-assignment branch (ReadBool true ->
//     DecodeVirtualAddressAssignment). Encoding an accept with an assignment
//     and decoding it reaches this branch.
//   - ValidateStructural 512: PersonalityProxyFlow with a non-nil assignment
//     is rejected ("must not carry virtual address assignment").
//   - ValidateStructural 515-516: PersonalityIPLite (or FullIP) with a nil
//     assignment is rejected ("requires virtual address assignment").
//
// No dead-by-design blocks remain: every count-0 line is reachable. The
// encode/decode branches are exercised by a round trip (encode-with-assignment
// then decode), and the validation branches by perturbing only the
// personality / assignment pairing of an otherwise-valid accept.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). No new package-level helpers are introduced: the test
// reuses the in-package samplePolicyAccept / fill / bytesReader / Encode
// fixtures and inlines all other constructs, so there is nothing for
// staticcheck U1000 to flag. No context.Context, no goroutines, no deprecated
// APIs.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestPolicyAcceptVirtualAddressAssignmentRoundTrip(t *testing.T) {
	// Encoding an accept with a non-nil assignment drives the WriteUint8(1)
	// branch (463) and the assignment's nil-DNSServerHint encode branch (412).
	// Decoding the result drives the ReadBool-true branch (483) and confirms
	// the assignment survives the round trip with no hint.
	accept := samplePolicyAccept()
	accept.VirtualAddressAssignment = &VirtualAddressAssignment{
		LeaseID:         fill(0xa0, 16),
		AddressFamily:   1,
		ClientAddress:   []byte{10, 0, 0, 2},
		PrefixLength:    24,
		DNSServerHint:   nil, // exercises the nil-hint encode branch (412)
		LeaseExpiryUnix: 1700000600,
	}
	encoded, err := Encode(accept)
	if err != nil {
		t.Fatalf("encode policy accept: %v", err)
	}
	decoded := DecodePolicyAccept(bytesReader(encoded))
	if decoded.VirtualAddressAssignment == nil {
		t.Fatal("decoded VirtualAddressAssignment is nil, want the assignment (483)")
	}
	got := decoded.VirtualAddressAssignment
	if !bytes.Equal(got.LeaseID, accept.VirtualAddressAssignment.LeaseID) {
		t.Fatalf("LeaseID round trip mismatch: got %x want %x", got.LeaseID, accept.VirtualAddressAssignment.LeaseID)
	}
	if got.DNSServerHint != nil {
		t.Fatalf("DNSServerHint = %x, want nil (nil-hint branch should round-trip to nil)", got.DNSServerHint)
	}

	// Anchor: an accept WITHOUT an assignment still encodes and decodes with a
	// nil assignment, proving the assignment above is set because of the input,
	// not because the decoder always synthesizes one.
	plain := samplePolicyAccept()
	plainEncoded, err := Encode(plain)
	if err != nil {
		t.Fatalf("encode plain accept: %v", err)
	}
	if decodedPlain := DecodePolicyAccept(bytesReader(plainEncoded)); decodedPlain.VirtualAddressAssignment != nil {
		t.Fatalf("plain accept decoded assignment = %v, want nil", decodedPlain.VirtualAddressAssignment)
	}
}

func TestPolicyAcceptValidateStructuralAssignmentRules(t *testing.T) {
	t.Run("proxy-flow carries assignment", func(t *testing.T) {
		// samplePolicyAccept is proxy-flow with no assignment (valid); adding
		// an assignment trips the proxy-flow guard (512-513).
		accept := samplePolicyAccept()
		accept.VirtualAddressAssignment = &VirtualAddressAssignment{LeaseID: fill(0xa0, 16)}
		err := accept.ValidateStructural()
		if err == nil || !strings.Contains(err.Error(), "proxy-flow policy accept must not carry") {
			t.Fatalf("err = %v, want proxy-flow must not carry assignment", err)
		}
	})

	t.Run("ip-lite missing assignment", func(t *testing.T) {
		// Switching the personality to IP-lite (a known personality, so the
		// switch enters the 515 case) while keeping the assignment nil trips the
		// IP-requires-assignment guard (516-517). All earlier validate* checks
		// pass because the fixture is otherwise valid.
		accept := samplePolicyAccept()
		accept.SelectedTunnelPersonality = registry.PersonalityIPLite
		err := accept.ValidateStructural()
		if err == nil || !strings.Contains(err.Error(), "IP policy accept requires virtual address assignment") {
			t.Fatalf("err = %v, want IP requires assignment", err)
		}
	})
}
