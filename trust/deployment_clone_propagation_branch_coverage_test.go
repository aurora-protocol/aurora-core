package trust_test

// Adversarial white-box branch coverage for the two count-0 clone-error propagation
// guards at the very top of the exported VerifyRelayDeployment entry point
// (trust/deployment.go):
//
//	func VerifyRelayDeployment(in RelayDeploymentVerification) (VerifiedRelayDeployment, error) {
//	    descriptor, err := cloneRelayDescriptor(in.Descriptor)            // :57
//	    if err != nil {                                                  // :58 <-- COUNT 0
//	        return ..., fmt.Errorf("trust: invalid relay descriptor encoding: %w", err)
//	    }
//	    template, err := cloneCoverTemplate(in.Template)                  // :61
//	    if err != nil {                                                  // :62 <-- COUNT 0
//	        return ..., fmt.Errorf("trust: invalid cover template encoding: %w", err)
//	    }
//	    ...
//	}
//
// Both fire at the FIRST two steps of the public API, BEFORE any hash computation or
// signature verification, so the tests are fully deterministic: no goroutine, no
// network, no rand, no signatures.
//
// The clone helpers' OWN internal Encode-error branches (cloneRelayDescriptor and
// cloneCoverTemplate) are already covered by deployment_clone_branch_coverage_test.go,
// which calls the clone helpers directly. Those direct calls do NOT exercise the
// VerifyRelayDeployment CALLER's propagation guards (:58/:62), which stay count 0.
// This file is the companion pillar: it drives the propagation through the exported
// entry point so the public API's rejection of structurally-malformed inputs at its
// very first step is covered. Same shape as the ListenAndServe nil-handler companion
// pillar (#366).
//
//	- :58 -> a zero-value RelayDescriptor: RelayID is nil, so WriteOpaqueFixed(RelayID,
//	  32) in RelayDescriptor.EncodeTo (protocol/directory.go:153) SetErr's
//	  ("wire: fixed opaque length 0, want 32"), protocol.Encode fails, cloneRelayDescriptor
//	  returns that error, and VerifyRelayDeployment propagates it wrapped as
//	  "invalid relay descriptor encoding" at :58.
//	- :62 -> a structurally-VALID RelayDescriptor (one that round-trips through
//	  cloneRelayDescriptor: RelayID=32, ReplayWindowID=16, four 48-byte prehash
//	  commitments, one 48-byte CoverTemplateInstanceHash; the four PublicKeyRecords
//	  default to zero, which Encode fine via WriteVarint+WriteOpaque16) plus a
//	  zero-value CoverTemplate, whose OriginSPKIHash is nil so WritePreHash fails
//	  ("wire: fixed opaque length 0, want 48"), cloneCoverTemplate returns that error,
//	  and VerifyRelayDeployment propagates it wrapped as "invalid cover template
//	  encoding" at :62.
//
// The downstream count-0 in VerifyRelayDeployment (the hash/signature-input err
// propagations at :68/:78/:109/:123/:136/:151/:154) are deliberately NOT claimed:
// they sit AFTER both clones succeed, so the descriptor/template are structurally
// valid (the clones are faithful Encode->Decode round-trips), and the downstream
// re-encodes cannot fail (clone-round-trip domination). The signature branches
// additionally require regenerating ECDSA/ML-DSA signatures over a mutated descriptor
// (documented dead-by-design in deployment_coverage_test.go). RelayDeploymentVerification
// and RelayDescriptor have all-exported fields, so the test uses the external trust_test
// package. The per-line coverage flips (:58 0->1, :62 0->1) are the rigorous proof.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/trust"
)

func TestVerifyRelayDeploymentClonePropagation(t *testing.T) {
	// :58 — a zero-value Descriptor fails to encode (RelayID nil != 32 bytes), so
	// cloneRelayDescriptor errors and VerifyRelayDeployment propagates it at :58,
	// wrapped as "invalid relay descriptor encoding" — before any hash or signature.
	zeroDescriptor := protocol.RelayDescriptor{}
	if _, err := trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor: zeroDescriptor,
	}); err == nil {
		t.Fatal("VerifyRelayDeployment(zero descriptor) err = nil, want non-nil (:58 cloneRelayDescriptor err propagation)")
	} else if !strings.Contains(err.Error(), "invalid relay descriptor encoding") {
		t.Fatalf("VerifyRelayDeployment(zero descriptor) err = %v, want substring %q (:58)", err, "invalid relay descriptor encoding")
	}

	// :62 — a structurally-valid Descriptor (round-trips through cloneRelayDescriptor)
	// paired with a zero-value Template that fails to encode (OriginSPKIHash nil !=
	// 48 bytes), so cloneCoverTemplate errors and VerifyRelayDeployment propagates it
	// at :62, wrapped as "invalid cover template encoding".
	h48 := make([]byte, 48)
	validDescriptor := protocol.RelayDescriptor{
		RelayID:                      make([]byte, 32),
		ReplayWindowID:               make([]byte, 16),
		SupportedPolicyIDsCommitment: h48,
		SupportedShapeIDsCommitment:  h48,
		ExitPolicyCommitment:         h48,
		AbusePolicyCommitment:        h48,
		CoverTemplateInstanceHashes:  [][]byte{h48},
	}
	if _, err := trust.VerifyRelayDeployment(trust.RelayDeploymentVerification{
		Descriptor: validDescriptor,
		Template:   protocol.CoverTemplate{},
	}); err == nil {
		t.Fatal("VerifyRelayDeployment(valid descriptor, zero template) err = nil, want non-nil (:62 cloneCoverTemplate err propagation)")
	} else if !strings.Contains(err.Error(), "invalid cover template encoding") {
		t.Fatalf("VerifyRelayDeployment(valid descriptor, zero template) err = %v, want substring %q (:62)", err, "invalid cover template encoding")
	}
}
