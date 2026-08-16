package handshake

// Adversarial coverage for the handshake key-derivation helpers in handshake/keys.go.
// The happy derive / cover-stream-binding / first-hop / finished / application-secrets
// paths are already exercised end-to-end by keys_test.go (TestDeriveHandshakeSecrets*,
// TestCoverStreamBindingMatchesCanonicalPreimage, TestFirstHopBindingContext*,
// TestFinishedAndApplicationSecrets, TestRouteCapsuleFinishedUsesHopTranscript) and the
// happy VerifyCoverPrelude1Signatures path by session_test.go
// (signedCoverPreludeVerificationInput + TestClientVerifiesCoverPrelude1Signatures*).
// The signature-verification failure branches (142-144 classical, 149-151 PQ), the
// descriptor-hash / cover-template mismatches (129-131, 132-134), the selected-suite
// mismatch (110-112) and ValidatePreludeHybridShares (119-121) are covered by
// session_test.go/relay_test.go and are not re-asserted here.
//
// This file covers the residual count-0 blocks with crafted inputs, perturbing exactly
// one condition per case so the branch under test is the one that fires. Each rejection
// asserts exactly one error substring so the failure is attributable to the perturbed
// field alone. The prelude-verification cases clone signedCoverPreludeVerificationInput
// (a fully-valid, freshly-signed input) and perturb one field.
//
// Uncovered blocks (measured count 0 before this file):
//   - CoverStreamBinding: encoder error 53.
//   - FirstHopBindingContext: encoder error 65.
//   - PreludeTranscriptHash: Encode(p0) error 73, Encode(p1.Unsigned()) error 77.
//   - VerifyCoverPrelude1Signatures: Prelude0 ValidateStructural 98, Prelude1
//     ValidateStructural 101, selected-suite-not-offered 113, selected-suite-not-
//     supported-by-descriptor 116, relay-epoch mismatch 122, RelayDescriptorHash error
//     126, PreludeTranscriptHash error 136, missing classical signature 139, missing PQ
//     signature 146.
//   - suiteOffered: fall-through false 166.
//   - DeriveHandshakeSecrets: SuiteHashLength error 171.
//   - ComputeClientFinished: Encode error 241.
//   - computeClientFinished: SuiteHash error 257.
//   - ComputeRouteClientFinished: Encode error 249.
//   - ComputeServerFinished: Encode error 273.
//   - computeServerFinished: SuiteHash capsule1Hash error 292.
//   - ComputeRouteServerFinished: Encode error 281.
//   - DeriveApplicationSecrets: SuiteHashLength error 332.
//
// Dead-by-design (documented, not covered):
//   - VerifyCoverPrelude1Signatures header re-checks 104/107. CoverPrelude0/1
//     ValidateStructural (98/101) already enforces MsgType and validateVersionKnown,
//     and validateVersionKnown accepts only Version20 (protocol/admission.go). After
//     ValidateStructural passes, MsgType and Version are exactly the canonical values,
//     so the redundant header re-check (`MsgType != … || Version != Version20`) at
//     104/107 can never fail for any constructible input.
//   - DeriveHandshakeSecrets HKDF/HKDF-Extract/AEAD branches 176/180/185/189/193/197/
//     201/205/209/213/217/221. After SuiteHashLength(171) accepts a supported suite,
//     HKDFExtractForSuite wraps hkdf.Extract (no error), HKDFExpandLabelForSuite uses
//     the short fixed labels ("derived"/"client hs"/"server hs"/"finished"/"key"/"iv")
//     and contexts that are nil or a transcript hash (<=64 bytes, well under the 255
//     hkdf limit), and AEADKeyLength returns 32 for a supported suite — none can error.
//   - computeClientFinished second SuiteHash 265. After the first SuiteHash(257)
//     accepts a supported suite, the second SuiteHash (260) uses the same suite, so it
//     cannot error.
//   - computeServerFinished Encode(accept) 296, SuiteHash policyAcceptHash 300, SuiteHash
//     input 309, HMAC 313. Encode(accept) runs only after ValidateForOffer(288) passes,
//     which constrains every Selected* field to an offer-listed registry constant and
//     the optional VirtualAddressAssignment to a structurally valid IP assignment, all
//     of which encode (296). The remaining SuiteHash/HMAC calls (300/309/313) use the
//     already-validated supported suite, so they cannot error.
//   - DeriveApplicationSecrets SuiteHash/HKDF/AEAD/trafficKeyIV branches 342/346/350/
//     354/358/362/366/370. Same reasoning as DeriveHandshakeSecrets: after
//     SuiteHashLength(332) accepts a supported suite, every subsequent HKDF/SuiteHash/
//     AEAD/trafficKeyIV call uses short labels and a supported suite and cannot error.
//   - trafficKeyIV HKDF key/iv 387/391 and length check 394. HKDFExpandLabelForSuite
//     returns exactly the requested length, so len(key)==keyLen and len(iv)==12 always
//     hold after the supported-suite HKDFs succeed (394). 387/391 cannot fire for a
//     supported suite.
//
// Not duplicated: the happy derive/finished/application/binding paths and the
// signature/descriptor-hash/cover-template mismatch paths are covered by keys_test.go
// and session_test.go and are not re-asserted here except for a single
// ComputeServerFinished success anchor that proves the suite=0xBAD error-case inputs
// are otherwise valid.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The new helpers keysCovCoverCapsule1, keysCovRouteCapsule1 and
// keysCovValidAccept are each referenced by >=2 tests/subtests, so they are not U1000.
// No context.Context, no goroutines, no deprecated APIs.

import (
	"math"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// keysCovCoverCapsule1 returns a CoverCapsule1Plain that encodes and whose PolicyOffer
// matches keysCovValidAccept (so ValidateForOffer passes). Cloned from the proven-valid
// fixture in keys_test.go. Each error-case test clones it and perturbs one field.
// Referenced by >=2 tests, so not U1000.
func keysCovCoverCapsule1() protocol.CoverCapsule1Plain {
	return protocol.CoverCapsule1Plain{
		MsgType:         registry.MsgCoverCapsule1,
		RouteInstanceID: 5,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(1, 16),
			TokenKeyID:            hx(2, 32),
			RelayBucketID:         hx(3, 16),
			TokenScopeID:          hx(4, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(5, 32),
			RedemptionContextHash: hx(6, 48),
			TokenAuthenticator:    []byte("token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       1,
			TokenRedemptionHash: hx(7, 48),
			ClientReplayNonce:   hx(8, 32),
			ReplayContextHash:   hx(9, 48),
			ReplayWindowID:      hx(10, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyAdversarialDPI,
			RequestedPolicyID:       registry.PolicyAdversarialDPI,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
	}
}

// keysCovRouteCapsule1 returns a RouteCapsule1Plain that encodes. Cloned from the
// proven-valid fixture in keys_test.go (TestRouteCapsuleFinishedUsesHopTranscript).
// Referenced by >=2 tests, so not U1000.
func keysCovRouteCapsule1() protocol.RouteCapsule1Plain {
	return protocol.RouteCapsule1Plain{
		MsgType:         registry.MsgRouteCapsule1,
		RouteInstanceID: 77,
		HopIndex:        1,
		AdmissionProof: protocol.AdmissionProof{
			ProofVersion:          registry.Version20,
			ProofType:             registry.ProofLabStaticToken,
			IssuerID:              hx(1, 16),
			TokenKeyID:            hx(2, 32),
			RelayBucketID:         hx(3, 16),
			TokenScopeID:          hx(4, 16),
			ExpiryUnix:            2000000000,
			TokenNonce:            hx(5, 32),
			RedemptionContextHash: hx(6, 48),
			TokenAuthenticator:    []byte("token"),
		},
		ReplayProof: protocol.ReplayProof{
			ProofVersion:        registry.Version20,
			ReplayEpochID:       1,
			TokenRedemptionHash: hx(7, 48),
			ClientReplayNonce:   hx(8, 32),
			ReplayContextHash:   hx(9, 48),
			ReplayWindowID:      hx(10, 16),
		},
		PolicyOffer: protocol.PolicyOffer{
			OfferedVersions:         []uint64{registry.Version20},
			OfferedSuites:           []uint64{registry.SuiteHybrid768AESGCM},
			OfferedMethods:          []uint64{registry.MethodWebH2Stream},
			MinimumPolicyID:         registry.PolicyAdversarialDPI,
			RequestedPolicyID:       registry.PolicyAdversarialDPI,
			RequestedRouteModeID:    registry.RouteSplit2,
			RequestedShapeID:        registry.ShapeNormal,
			TunnelPersonalityOffers: []uint64{registry.PersonalityProxyFlow},
		},
	}
}

// keysCovValidAccept returns a PolicyAccept that validates against the PolicyOffer in
// keysCovCoverCapsule1/keysCovRouteCapsule1. Referenced by >=2 tests, so not U1000.
func keysCovValidAccept() protocol.PolicyAccept {
	return protocol.PolicyAccept{
		SelectedVersion:           registry.Version20,
		SelectedSuite:             registry.SuiteHybrid768AESGCM,
		SelectedMethod:            registry.MethodWebH2Stream,
		SelectedPolicy:            registry.PolicyAdversarialDPI,
		SelectedRouteModeID:       registry.RouteSplit2,
		SelectedShape:             registry.ShapeNormal,
		SelectedTunnelPersonality: registry.PersonalityProxyFlow,
	}
}

func TestSuiteOfferedDecidesPerCondition(t *testing.T) {
	t.Run("offered", func(t *testing.T) {
		if !suiteOffered([]uint64{registry.SuiteHybrid768AESGCM}, registry.SuiteHybrid768AESGCM) {
			t.Fatalf("suiteOffered returned false for an offered suite")
		}
	})
	t.Run("not offered", func(t *testing.T) {
		// A known-but-different offer list falls through the loop to the `return false`
		// at line 166.
		if suiteOffered([]uint64{registry.SuiteHybrid1024AESGCM}, registry.SuiteHybrid768AESGCM) {
			t.Fatalf("suiteOffered returned true for a non-offered suite")
		}
	})
}

func TestCoverStreamBindingDecidesPerCondition(t *testing.T) {
	t.Run("encode failure", func(t *testing.T) {
		// An out-of-range StreamIDOrRequestID fails WriteVarint inside the encoder,
		// surfacing at e.Bytes() (53).
		in := CoverStreamBindingInput{
			OuterExporterValue:       hx(0x11, 48),
			HTTPVersion:              []byte("h2"),
			ConnectionIDHash:         hx(0x12, 48),
			StreamIDOrRequestID:      math.MaxUint64,
			MethodFamilyID:           registry.MethodWebH2Stream,
			NormalizedAuthorityHash:  hx(0x13, 48),
			NormalizedPathTemplateID: hx(0x14, 16),
			RequestClassID:           3,
			ClientCoverRandom:        hx(0x15, 32),
		}
		_, err := CoverStreamBinding(in)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
}

func TestFirstHopBindingContextDecidesPerCondition(t *testing.T) {
	t.Run("encode failure", func(t *testing.T) {
		// WritePreHash requires a 48-byte input; a 47-byte coverStreamBinding fails
		// WriteOpaqueFixed, surfacing at e.Bytes() (65).
		_, err := FirstHopBindingContext(hx(0x21, 48), hx(0x99, 47))
		if err == nil || !strings.Contains(err.Error(), "fixed opaque length") {
			t.Fatalf("err = %v, want %q", err, "fixed opaque length")
		}
	})
}

func TestPreludeTranscriptHashDecidesPerCondition(t *testing.T) {
	in := signedCoverPreludeVerificationInput(t)
	t.Run("encode prelude0 failure", func(t *testing.T) {
		// RequestClassID is written via WriteVarint (line 39 of CoverPrelude0.EncodeTo);
		// an out-of-range value fails Encode(p0) at 73.
		p0 := in.Prelude0
		p0.RequestClassID = math.MaxUint64
		_, err := PreludeTranscriptHash(registry.SuiteHybrid768AESGCM, in.CoverStreamBinding, p0, in.Prelude1)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("encode prelude1 failure", func(t *testing.T) {
		// ServerNonce is written via WriteOpaqueFixed(32); a 31-byte value fails
		// Encode(p1.Unsigned()) at 77 after Encode(p0) succeeds.
		p1 := in.Prelude1
		p1.ServerNonce = hx(0x10, 31)
		_, err := PreludeTranscriptHash(registry.SuiteHybrid768AESGCM, in.CoverStreamBinding, in.Prelude0, p1)
		if err == nil || !strings.Contains(err.Error(), "fixed opaque length") {
			t.Fatalf("err = %v, want %q", err, "fixed opaque length")
		}
	})
}

func TestVerifyCoverPrelude1SignaturesDecidesPerCondition(t *testing.T) {
	t.Run("prelude0 validate structural", func(t *testing.T) {
		in := signedCoverPreludeVerificationInput(t)
		in.Prelude0.Version = 0xBAD
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "reserved version") {
			t.Fatalf("err = %v, want %q", err, "reserved version")
		}
	})
	t.Run("prelude1 validate structural", func(t *testing.T) {
		in := signedCoverPreludeVerificationInput(t)
		in.Prelude1.Version = 0xBAD
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "reserved version") {
			t.Fatalf("err = %v, want %q", err, "reserved version")
		}
	})
	t.Run("selected suite not offered", func(t *testing.T) {
		// A known-but-different SuiteOffers list passes ValidateStructural (all known)
		// but fails the suiteOffered check at 113.
		in := signedCoverPreludeVerificationInput(t)
		in.Prelude0.SuiteOffers = []uint64{registry.SuiteHybrid1024AESGCM}
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "selected suite was not offered") {
			t.Fatalf("err = %v, want %q", err, "selected suite was not offered")
		}
	})
	t.Run("selected suite not supported by descriptor", func(t *testing.T) {
		// Prelude0 offers the suite (113 passes), but the descriptor does not (116).
		in := signedCoverPreludeVerificationInput(t)
		in.Descriptor.SupportedSuiteIDs = []uint64{registry.SuiteHybrid1024AESGCM}
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "not supported by descriptor") {
			t.Fatalf("err = %v, want %q", err, "not supported by descriptor")
		}
	})
	t.Run("relay epoch mismatch", func(t *testing.T) {
		in := signedCoverPreludeVerificationInput(t)
		in.Prelude1.RelayEpochID = in.Descriptor.EpochID + 1
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "relay epoch mismatch") {
			t.Fatalf("err = %v, want %q", err, "relay epoch mismatch")
		}
	})
	t.Run("descriptor hash encode failure", func(t *testing.T) {
		// DescriptorVersion is written via WriteVarint; an out-of-range value fails
		// protocol.Encode(descriptor.Unsigned()) inside RelayDescriptorHash at 126.
		in := signedCoverPreludeVerificationInput(t)
		in.Descriptor.DescriptorVersion = math.MaxUint64
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("transcript hash encode failure", func(t *testing.T) {
		// A 31-byte ServerNonce passes the descriptor-hash/cover-template checks but
		// fails Encode(p1.Unsigned()) inside PreludeTranscriptHash at 136.
		in := signedCoverPreludeVerificationInput(t)
		in.Prelude1.ServerNonce = hx(0x10, 31)
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "fixed opaque length") {
			t.Fatalf("err = %v, want %q", err, "fixed opaque length")
		}
	})
	t.Run("missing classical signature", func(t *testing.T) {
		in := signedCoverPreludeVerificationInput(t)
		in.Prelude1.ServerPreludeSignatureClassical = nil
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "missing classical prelude signature") {
			t.Fatalf("err = %v, want %q", err, "missing classical prelude signature")
		}
	})
	t.Run("missing pq signature", func(t *testing.T) {
		// RequirePQ forces the PQ path; an empty PQ signature fails the presence
		// check at 146 after the classical signature still verifies at 142.
		in := signedCoverPreludeVerificationInput(t)
		in.RequirePQ = true
		_, err := VerifyCoverPrelude1Signatures(in)
		if err == nil || !strings.Contains(err.Error(), "missing PQ prelude signature") {
			t.Fatalf("err = %v, want %q", err, "missing PQ prelude signature")
		}
	})
}

func TestDeriveHandshakeSecretsDecidesPerCondition(t *testing.T) {
	t.Run("unsupported suite", func(t *testing.T) {
		_, err := DeriveHandshakeSecrets(0xBAD, hx(1, 32), hx(2, 32), hx(3, 48), hx(4, 48))
		if err == nil || !strings.Contains(err.Error(), "unsupported suite 0xbad") {
			t.Fatalf("err = %v, want %q", err, "unsupported suite 0xbad")
		}
	})
}

func TestComputeClientFinishedDecidesPerCondition(t *testing.T) {
	t.Run("encode failure", func(t *testing.T) {
		capsule := keysCovCoverCapsule1()
		capsule.RouteInstanceID = math.MaxUint64
		_, err := ComputeClientFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("unsupported suite hash", func(t *testing.T) {
		// A valid capsule encodes, then computeClientFinished's first SuiteHash
		// rejects the unknown suite at 257.
		_, err := ComputeClientFinished(0xBAD, hx(0x33, 48), hx(0x44, 48), keysCovCoverCapsule1())
		if err == nil || !strings.Contains(err.Error(), "unsupported suite 0xbad") {
			t.Fatalf("err = %v, want %q", err, "unsupported suite 0xbad")
		}
	})
}

func TestComputeRouteClientFinishedDecidesPerCondition(t *testing.T) {
	t.Run("encode failure", func(t *testing.T) {
		capsule := keysCovRouteCapsule1()
		capsule.RouteInstanceID = math.MaxUint64
		_, err := ComputeRouteClientFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
}

func TestComputeServerFinishedDecidesPerCondition(t *testing.T) {
	t.Run("encode failure", func(t *testing.T) {
		// Encode(capsule1) fails before the accept is consulted, so a zero accept
		// suffices (273).
		capsule := keysCovCoverCapsule1()
		capsule.RouteInstanceID = math.MaxUint64
		_, _, _, err := ComputeServerFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule, protocol.PolicyAccept{})
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("unsupported suite hash", func(t *testing.T) {
		// A valid capsule+accept passes ValidateForOffer (288), then computeServerFinished's
		// first SuiteHash rejects the unknown suite at 292.
		_, _, _, err := ComputeServerFinished(0xBAD, hx(0x33, 48), hx(0x44, 48), keysCovCoverCapsule1(), keysCovValidAccept())
		if err == nil || !strings.Contains(err.Error(), "unsupported suite 0xbad") {
			t.Fatalf("err = %v, want %q", err, "unsupported suite 0xbad")
		}
	})
	t.Run("valid", func(t *testing.T) {
		// Anchor: a supported suite + valid capsule+accept computes a server-finished,
		// proving the suite=0xBAD error-case inputs are otherwise valid.
		finished, capsuleHash, policyHash, err := ComputeServerFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), keysCovCoverCapsule1(), keysCovValidAccept())
		if err != nil {
			t.Fatalf("valid server finished: %v", err)
		}
		if len(finished) != 48 || len(capsuleHash) == 0 || len(policyHash) == 0 {
			t.Fatalf("unexpected server finished outputs: finished=%d capsuleHash=%d policyHash=%d", len(finished), len(capsuleHash), len(policyHash))
		}
	})
}

func TestComputeRouteServerFinishedDecidesPerCondition(t *testing.T) {
	t.Run("encode failure", func(t *testing.T) {
		capsule := keysCovRouteCapsule1()
		capsule.RouteInstanceID = math.MaxUint64
		_, _, _, err := ComputeRouteServerFinished(registry.SuiteHybrid768AESGCM, hx(0x33, 48), hx(0x44, 48), capsule, protocol.PolicyAccept{})
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
}

func TestDeriveApplicationSecretsDecidesPerCondition(t *testing.T) {
	t.Run("unsupported suite", func(t *testing.T) {
		_, err := DeriveApplicationSecrets(0xBAD, hx(0x01, 48), hx(0x02, 48), hx(0x03, 48), hx(0x04, 48), hx(0x05, 48))
		if err == nil || !strings.Contains(err.Error(), "unsupported suite 0xbad") {
			t.Fatalf("err = %v, want %q", err, "unsupported suite 0xbad")
		}
	})
}
