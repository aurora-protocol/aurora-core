package trust

// Adversarial coverage for the pure deployment-descriptor and cover-template
// validators in trust/deployment.go that the existing deployment_test.go suite
// reaches only indirectly (and mostly not at all).
//
// The existing TestVerifyRelayDeploymentRejectsInvalidTrustOrCompatibility mutates a
// fully-signed fixture, but nearly every mutation changes the relay-descriptor hash,
// so those mutations fail at the trusted-hash check (deployment.go:71) long before
// reaching the validator branch they appear to target. The count-0 map confirms the
// validator internals stay uncovered. This file covers them by calling
// validateDeploymentDescriptor and validateDeploymentTemplate directly with crafted
// inputs, perturbing exactly one field per case so the target branch is the one that
// fires. It also covers VerifiedRelayDeployment.FirstHopMetadata (0% before — the
// existing suite never calls it) by constructing a VerifiedRelayDeployment directly
// (white-box: unexported fields are accessible from this package), and the four small
// predicates whose false/duplicate returns were never exercised.
//
// Uncovered blocks (measured count 0 before this file):
//   - validateDeploymentDescriptor (line 224, 57.1% before): version, identifier
//     length, validity interval, epoch interval, replay-epoch expiry, per-key
//     compatibility propagation, classical-uses-PQ, PQ-not-PQ, commitment length,
//     empty compatibility lists, duplicate IDs, cover-template commitment length.
//   - validateDeploymentTemplate (line 280, 75% before): version, identifier/hash
//     length, CoverOriginCommitment computation error, commitment mismatch, capsule
//     envelope inversion, duplicate request class, path-template-id length, unknown
//     method family, sidecar-requires-shadow-origin, private-capsule local-consume.
//     The existing TestValidateDeploymentTemplateAppliesSelectedSuiteEnvelopeFloors
//     covers the prelude envelope floors (301/304) — NOT duplicated.
//   - FirstHopMetadata (line 179, 0% before): the selectedSuite==0 fallback and the
//     whole metadata assembly.
//   - containsDeploymentID (line 416): the not-found return.
//   - isProductionSuite (line 425): the default return.
//   - isKnownDeploymentMethod (line 439): the default return.
//   - hasDuplicateDeploymentIDs (line 455): the duplicate-found return.
//   - VerifyRelayDeployment (line 74): the validateDeploymentDescriptor propagation —
//     reached with a descriptor whose hash matches TrustedDescriptorHash but fails
//     validation; no signatures are needed because the check precedes signature
//     verification (line 81).
//
// Covered elsewhere in this package (documented, covered):
//   - cloneRelayDescriptor:363 and cloneCoverTemplate:379 — the Encode error
//     branches. Encode does not only fail on a varint-length overflow; it also
//     fails on a fixed-width length mismatch (WriteOpaqueFixed / WritePreHash
//     reject a field whose length is not the fixed width), and a zero-valued
//     struct has nil/empty fixed fields. cloneRelayDescriptor(zero) fails at
//     WriteOpaqueFixed(RelayID, 32); cloneCoverTemplate(zero) fails at
//     WritePreHash(OriginSPKIHash, 48). These two branches are covered by
//     deployment_clone_branch_coverage_test.go, along with deploymentRequestClass
//     352/355 and happy-path byte-identity locks.
//
// Dead-by-design / not-contrived (documented, not covered):
//   - cloneRelayDescriptor (368/371) and cloneCoverTemplate (384/387) — the
//     decode-error and trailing-bytes branches. Each clone is a faithful
//     protocol.Encode -> wire.NewReader -> Decode round-trip of the same wire
//     format, so for any struct whose Encode succeeds the Decode consumes exactly
//     the encoded bytes (no decode error, EOF reached with no trailing bytes).
//     The decode and trailing-bytes branches guard against an Encode/Decode
//     wire-format mismatch that no constructible struct can produce.
//   - VerifyRelayDeployment signature branches (78, 88, 92, 101, 109, 117, 120, 124,
//     133, 136, 146, 148, 151, 154). Reaching them requires a descriptor whose hash
//     matches TrustedDescriptorHash AND whose classical + ML-DSA signatures all
//     verify, which means regenerating ECDSA and ML-DSA signatures over a mutated
//     descriptor. The signature-verification logic itself is exercised by the crypto
//     package tests and the signed fixture in newDeploymentFixture; the post-signature
//     suite/method compatibility checks (148/151/154) are unreachable from the
//     existing mutation table because every such mutation changes the descriptor hash
//     and fails at line 71 first. Contriving them would require a custom signed
//     fixture and is out of scope for a pure-validator coverage pass.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection case asserts exactly one error so the failure is
// attributable to the perturbed field alone. New helpers are each referenced by >=2
// tests so there is no U1000. No context.Context, no deprecated APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	deploymentCovNow  uint64 = 15
	deploymentCovSkew uint64 = 120
)

// classicalECDSAP256Key returns a public-key record that passes
// PublicKeyRecord.ValidateCompatibility: ECDSA P-256 with a SEC1-uncompressed key
// whose length is exactly 65 bytes. ValidateCompatibility only checks the
// scheme/encoding pair and the key length (not that the bytes are a valid curve
// point), so a fixed 65-byte value suffices and avoids generating a real key. Used by
// validDeploymentDescriptor's two classical slots and the key-compat test, so it is
// not U1000.
func classicalECDSAP256Key() protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       rb(0x04, 65),
	}
}

// pqMLDSA65Key returns a public-key record that passes ValidateCompatibility for
// ML-DSA-65: a fixed byte slice of exactly mldsa65.PublicKeySize bytes. Used by
// validDeploymentDescriptor's two PQ slots and the PQ-scheme tests, so it is not U1000.
func pqMLDSA65Key() protocol.PublicKeyRecord {
	return protocol.PublicKeyRecord{
		SignatureScheme: registry.SigMLDSA65,
		KeyEncoding:     registry.KeyMLDSA65RawPublic,
		PublicKey:       make([]byte, mldsa65.PublicKeySize),
	}
}

// validDeploymentDescriptor returns a RelayDescriptor that passes
// validateDeploymentDescriptor(deploymentCovNow) and round-trips through
// cloneRelayDescriptor (so it is usable both for the direct validator table and for
// the VerifyRelayDeployment propagation case). The two classical slots use
// classicalECDSAP256Key and the two PQ slots use pqMLDSA65Key; the signatures are dummy
// bytes (never verified before the branch under test). Referenced by the descriptor
// table and by FirstHopMetadata, so it is not U1000.
func validDeploymentDescriptor() protocol.RelayDescriptor {
	return protocol.RelayDescriptor{
		DescriptorVersion:            registry.Version20,
		RelayID:                      rb(0x11, 32),
		RoleFlags:                    1,
		ValidFromUnix:                10,
		ValidUntilUnix:               20,
		RelayLongtermClassicalKey:    classicalECDSAP256Key(),
		RelayLongtermPQKey:           pqMLDSA65Key(),
		EpochID:                      9,
		EpochAuthClassicalKey:        classicalECDSAP256Key(),
		EpochAuthPQKey:               pqMLDSA65Key(),
		EpochValidFromUnix:           10,
		EpochValidUntilUnix:          20,
		ReplayEpochID:                10,
		ReplayEpochValidUntilUnix:    20,
		ReplayWindowID:               rb(0x12, 16),
		SupportedSuiteIDs:            []uint64{registry.SuiteHybrid768P256AESGCM},
		SupportedMethodIDs:           []uint64{registry.MethodWebH2Stream},
		SupportedPolicyIDsCommitment: rb(0x13, 48),
		SupportedShapeIDsCommitment:  rb(0x14, 48),
		CoverTemplateInstanceHashes:  [][]byte{rb(0x17, 48)},
		ExitPolicyCommitment:         rb(0x15, 48),
		AbusePolicyCommitment:        rb(0x16, 48),
		SignatureByLongtermClassical: []byte("cls-sig"),
		SignatureByLongtermPQ:        []byte("pq-sig"),
	}
}

// validDeploymentTemplate returns a CoverTemplate that passes
// validateDeploymentTemplate(registry.SuiteHybrid768P256AESGCM, deploymentCovNow,
// deploymentCovSkew). It reuses the in-package validCoverTemplate fixture and
// overwrites CoverOriginCommitment with the computed value so the 294 commitment-match
// check passes. Referenced by the template table and by FirstHopMetadata, so it is
// not U1000.
func validDeploymentTemplate(t *testing.T) protocol.CoverTemplate {
	t.Helper()
	tmpl := validCoverTemplate()
	commitment, err := CoverOriginCommitment(tmpl)
	if err != nil {
		t.Fatalf("compute cover origin commitment for base template: %v", err)
	}
	tmpl.CoverOriginCommitment = commitment
	return tmpl
}

func TestValidateDeploymentDescriptorDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*protocol.RelayDescriptor)
		wantSub string
	}{
		{"unsupported descriptor version", func(d *protocol.RelayDescriptor) { d.DescriptorVersion = 0 }, "unsupported relay descriptor version"},
		{"identifier wrong length", func(d *protocol.RelayDescriptor) { d.RelayID = rb(0xee, 31) }, "invalid relay descriptor identifier length"},
		{"empty validity interval", func(d *protocol.RelayDescriptor) { d.ValidUntilUnix = 10 }, "relay descriptor outside validity interval"},
		{"empty epoch interval", func(d *protocol.RelayDescriptor) { d.EpochValidUntilUnix = 10 }, "relay epoch outside validity interval"},
		{"replay epoch expired", func(d *protocol.RelayDescriptor) { d.ReplayEpochValidUntilUnix = 10 }, "relay replay epoch expired"},
		{"long-term classical key incompatible", func(d *protocol.RelayDescriptor) { d.RelayLongtermClassicalKey.PublicKey = rb(0x04, 64) }, "invalid relay long-term classical key"},
		{"classical key uses PQ scheme", func(d *protocol.RelayDescriptor) { d.RelayLongtermClassicalKey = pqMLDSA65Key() }, "relay classical key uses a PQ signature scheme"},
		{"PQ key uses classical scheme", func(d *protocol.RelayDescriptor) { d.RelayLongtermPQKey = classicalECDSAP256Key() }, "relay PQ key does not use a PQ signature scheme"},
		{"commitment wrong length", func(d *protocol.RelayDescriptor) { d.SupportedPolicyIDsCommitment = rb(0x13, 47) }, "invalid relay policy commitment length"},
		{"empty compatibility lists", func(d *protocol.RelayDescriptor) { d.SupportedSuiteIDs = nil }, "relay descriptor compatibility lists are empty"},
		{"duplicate suite IDs", func(d *protocol.RelayDescriptor) {
			d.SupportedSuiteIDs = []uint64{registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid768P256AESGCM}
		}, "relay descriptor compatibility list contains duplicates"},
		{"cover template commitment wrong length", func(d *protocol.RelayDescriptor) { d.CoverTemplateInstanceHashes = [][]byte{rb(0x17, 47)} }, "invalid cover template commitment length"},
		{"valid descriptor accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validDeploymentDescriptor()
			if tc.mutate != nil {
				tc.mutate(&d)
			}
			err := validateDeploymentDescriptor(d, deploymentCovNow)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestValidateDeploymentTemplateDecidesPerCondition(t *testing.T) {
	gatewayClass := func(method uint64, prelude, capsule bool) protocol.RequestClass {
		return protocol.RequestClass{
			ClassID:             7,
			ClassType:           registry.RequestGatewayOwnedSlot,
			AllowedMethodFamily: method,
			PathTemplateID:      rb(0x06, 16),
			MayCarryPrelude:     prelude,
			MayCarryCapsule:     capsule,
		}
	}

	cases := []struct {
		name    string
		mutate  func(*protocol.CoverTemplate)
		wantSub string
	}{
		{"unsupported template version", func(t *protocol.CoverTemplate) { t.TemplateVersion = 0 }, "unsupported cover template version"},
		{"empty template id", func(t *protocol.CoverTemplate) { t.TemplateID = nil }, "invalid cover template identifier or hash length"},
		{"cover origin commitment computation error", func(t *protocol.CoverTemplate) { t.GatewayOwnedSlotCommitments = [][]byte{rb(0x07, 47)} }, "fixed opaque length"},
		{"cover origin commitment mismatch", func(t *protocol.CoverTemplate) { t.CoverOriginCommitment = rb(0xFF, 48) }, "cover origin commitment mismatch"},
		{"capsule envelope inverted", func(t *protocol.CoverTemplate) {
			t.CapsuleEnvelope.MinCapsuleBodySize = 100
			t.CapsuleEnvelope.MaxCapsuleBodySize = 50
		}, "invalid cover capsule envelope"},
		{"duplicate request class", func(t *protocol.CoverTemplate) {
			t.RequestClasses = []protocol.RequestClass{gatewayClass(registry.MethodWebH2Stream, true, true), gatewayClass(registry.MethodWebH2Stream, true, true)}
		}, "duplicate cover request class"},
		{"path template id wrong length", func(t *protocol.CoverTemplate) {
			t.RequestClasses = []protocol.RequestClass{gatewayClass(registry.MethodWebH2Stream, true, false)}
			t.RequestClasses[0].PathTemplateID = rb(0x06, 15)
		}, "invalid request-class path template ID"},
		{"unknown method family", func(t *protocol.CoverTemplate) {
			t.RequestClasses = []protocol.RequestClass{gatewayClass(0xBAD, true, false)}
		}, "request class has unknown method family"},
		{"sidecar requires shadow origin", func(t *protocol.CoverTemplate) {
			t.RequestClasses = []protocol.RequestClass{{
				ClassID:             7,
				ClassType:           registry.RequestSidecarOriginSlot,
				AllowedMethodFamily: registry.MethodWebH2Stream,
				PathTemplateID:      rb(0x06, 16),
				MayCarryPrelude:     false,
				MayCarryCapsule:     false,
			}}
		}, "sidecar carrier requires shadow-origin method"},
		{"private capsule not consumed locally", func(t *protocol.CoverTemplate) { t.CapsuleEnvelope.ConsumeFailedBodyLocally = false }, "failed private capsule bodies must be consumed locally"},
		{"valid template accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := validDeploymentTemplate(t)
			if tc.mutate != nil {
				tc.mutate(&tmpl)
			}
			err := validateDeploymentTemplate(tmpl, registry.SuiteHybrid768P256AESGCM, deploymentCovNow, deploymentCovSkew)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestVerifiedRelayDeploymentFirstHopMetadataSelectsSuite(t *testing.T) {
	deployment := VerifiedRelayDeployment{
		verified:     true,
		suite:        registry.SuiteHybrid768P256AESGCM,
		method:       registry.MethodWebH2Stream,
		descriptor:   validDeploymentDescriptor(),
		template:     validDeploymentTemplate(t),
		requestClass: protocol.RequestClass{ClassType: registry.RequestGatewayOwnedSlot, AllowedMethodFamily: registry.MethodWebH2Stream, MayCarryPrelude: true, MayCarryCapsule: true},
	}

	// selectedSuite == 0 falls back to d.suite (line 180-182); the supported flag is
	// true because d.suite is in the descriptor's SupportedSuiteIDs.
	meta := deployment.FirstHopMetadata(0)
	if meta.SelectedSuiteIsSupported != true {
		t.Fatalf("FirstHopMetadata(0).SelectedSuiteIsSupported = %v, want true (fallback to d.suite)", meta.SelectedSuiteIsSupported)
	}
	if meta.DescriptorValidFromUnix != 10 || meta.DescriptorValidUntilUnix != 20 {
		t.Fatalf("FirstHopMetadata(0) descriptor validity = %d..%d, want 10..20", meta.DescriptorValidFromUnix, meta.DescriptorValidUntilUnix)
	}
	if !meta.RequestClassMayCarryPrelude || !meta.RequestClassMayCarryCapsule {
		t.Fatalf("FirstHopMetadata(0) request-class flags = prelude=%v capsule=%v, want both true", meta.RequestClassMayCarryPrelude, meta.RequestClassMayCarryCapsule)
	}

	// An explicitly-selected suite that is NOT in the descriptor's list reports
	// unsupported (covers the non-fallback path through line 198).
	other := deployment.FirstHopMetadata(registry.SuiteHybrid1024AESGCM)
	if other.SelectedSuiteIsSupported != false {
		t.Fatalf("FirstHopMetadata(1024AESGCM).SelectedSuiteIsSupported = %v, want false", other.SelectedSuiteIsSupported)
	}
}

func TestDeploymentPredicatesCoverRemainingBranches(t *testing.T) {
	// containsDeploymentID not-found return (line 422).
	if containsDeploymentID([]uint64{1, 2, 3}, 4) {
		t.Fatal("containsDeploymentID([1,2,3], 4) = true, want false")
	}
	if !containsDeploymentID([]uint64{1, 2, 3}, 2) {
		t.Fatal("containsDeploymentID([1,2,3], 2) = false, want true")
	}

	// isProductionSuite default return (line 434-435).
	if isProductionSuite(0xBAD) {
		t.Fatal("isProductionSuite(0xBAD) = true, want false")
	}
	if !isProductionSuite(registry.SuiteHybrid768AESGCM) {
		t.Fatal("isProductionSuite(SuiteHybrid768AESGCM) = false, want true")
	}

	// isKnownDeploymentMethod default return (line 450-451).
	if isKnownDeploymentMethod(0xBAD) {
		t.Fatal("isKnownDeploymentMethod(0xBAD) = true, want false")
	}
	if !isKnownDeploymentMethod(registry.MethodWebH2Stream) {
		t.Fatal("isKnownDeploymentMethod(MethodWebH2Stream) = false, want true")
	}

	// hasDuplicateDeploymentIDs duplicate-found return (line 458-460).
	if !hasDuplicateDeploymentIDs([]uint64{1, 1}) {
		t.Fatal("hasDuplicateDeploymentIDs([1,1]) = false, want true")
	}
	if hasDuplicateDeploymentIDs([]uint64{1, 2, 3}) {
		t.Fatal("hasDuplicateDeploymentIDs([1,2,3]) = true, want false")
	}
}

func TestVerifyRelayDeploymentPropagatesDescriptorValidationError(t *testing.T) {
	// To reach the validateDeploymentDescriptor propagation at line 74-75, the
	// descriptor must pass cloneRelayDescriptor (57) and the trusted-hash check (71)
	// but fail validation. A descriptor whose hash matches TrustedDescriptorHash and
	// whose version is 0 does exactly that: clone and hash ignore the version, the
	// trusted-hash check passes because we pin TrustedDescriptorHash to the actual
	// hash, and validateDeploymentDescriptor rejects version 0 at line 225. No
	// signatures are needed because signature verification (line 81) runs after line
	// 74.
	descriptor := validDeploymentDescriptor()
	descriptor.DescriptorVersion = 0
	hash, err := RelayDescriptorHash(descriptor)
	if err != nil {
		t.Fatalf("hash mutated descriptor: %v", err)
	}
	_, err = VerifyRelayDeployment(RelayDeploymentVerification{
		Descriptor:            descriptor,
		TrustedDescriptorHash: hash,
		Template:              validDeploymentTemplate(t),
		RequestClassID:        7,
		Suite:                 registry.SuiteHybrid768P256AESGCM,
		Method:                registry.MethodWebH2Stream,
		NowUnix:               deploymentCovNow,
		MaxTemplateFutureSkew: deploymentCovSkew,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported relay descriptor version") {
		t.Fatalf("VerifyRelayDeployment err = %v, want unsupported relay descriptor version", err)
	}
}
