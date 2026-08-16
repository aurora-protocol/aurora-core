package cover

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// opts used by the ValidateTemplate-driven tests; NowUnix 150 sits inside the
// validTemplate window [100,300] with room for the future-skew guard.
var coverOpts = ValidationOptions{NowUnix: 150, MaxFutureSkew: 120}

// TestValidateTemplateRejectsUnsupportedVersion covers the template-version
// guard (previously uncovered), checked before the commitment is recomputed.
func TestValidateTemplateRejectsUnsupportedVersion(t *testing.T) {
	tpl := validTemplate(t)
	tpl.TemplateVersion = 0xff
	if err := ValidateTemplate(tpl, coverOpts); err == nil {
		t.Fatal("unsupported template version accepted")
	}
}

// TestValidateTemplateRejectsExpiredTemplate covers the time-validation guard
// (previously uncovered): NowUnix past ValidUntilUnix + MaxFutureSkew.
func TestValidateTemplateRejectsExpiredTemplate(t *testing.T) {
	tpl := validTemplate(t)
	if err := ValidateTemplate(tpl, ValidationOptions{NowUnix: 500, MaxFutureSkew: 120}); err == nil {
		t.Fatal("expired template accepted")
	}
}

// TestValidateTemplateRejectsMalformedOriginCommitment covers the
// CoverOriginCommitment error propagation (previously unreachable): a
// wrong-length slot commitment makes encodePreHashVector fail inside the
// fresh commitment recomputation at line 24, before the comparison at line 28.
func TestValidateTemplateRejectsMalformedOriginCommitment(t *testing.T) {
	tpl := validTemplate(t)
	tpl.GatewayOwnedSlotCommitments[0] = cb(0x07, 47) // PreHash wants 48 bytes
	if err := ValidateTemplate(tpl, coverOpts); err == nil {
		t.Fatal("template with malformed slot commitment accepted")
	}
}

// TestValidateTemplateRejectsInvalidPreludeEnvelope covers the
// validatePreludeEnvelope propagation through ValidateTemplate (previously
// uncovered).
func TestValidateTemplateRejectsInvalidPreludeEnvelope(t *testing.T) {
	tpl := validTemplate(t)
	tpl.PreludeEnvelope.MaxRequestBodySize = tpl.PreludeEnvelope.MinRequestBodySize - 1
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, coverOpts); err == nil {
		t.Fatal("template with invalid prelude request interval accepted")
	}
}

// TestValidateTemplateRejectsDuplicateRequestClass covers the duplicate
// class-id guard (previously uncovered).
func TestValidateTemplateRejectsDuplicateRequestClass(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses = append(tpl.RequestClasses, protocol.RequestClass{
		ClassID:             1, // duplicates class 0
		ClassType:           registry.RequestOriginPassThrough,
		AllowedMethodFamily: registry.MethodWebH2Stream,
		PathTemplateID:      cb(0x20, 16),
	})
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, coverOpts); err == nil {
		t.Fatal("duplicate request class id accepted")
	}
}

// TestValidateTemplateRejectsSidecarWithoutShadowOrigin covers the sidecar
// method-family guard (previously uncovered): a sidecar-origin carrier that
// carries protocol material must use the shadow-origin method family.
func TestValidateTemplateRejectsSidecarWithoutShadowOrigin(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses[0].ClassType = registry.RequestSidecarOriginSlot
	tpl.RequestClasses[0].AllowedMethodFamily = registry.MethodWebH2Stream
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, coverOpts); err == nil {
		t.Fatal("sidecar carrier without shadow-origin method family accepted")
	}
}

// TestValidateTemplateRejectsTemplateWithoutPrivateCarrier covers the
// no-private-carrier guard (previously uncovered): if no request class can
// carry protocol material, validation fails.
func TestValidateTemplateRejectsTemplateWithoutPrivateCarrier(t *testing.T) {
	tpl := validTemplate(t)
	tpl.RequestClasses[0].MayCarryPrelude = false
	tpl.RequestClasses[0].MayCarryCapsule = false
	refreshOriginCommitment(t, &tpl)
	if err := ValidateTemplate(tpl, coverOpts); err == nil {
		t.Fatal("template with no private carrier class accepted")
	}
}

// TestSelectCarrierClassPropagatesGatewayError covers the gateway-selection
// error propagation in SelectCarrierClass (previously uncovered): selecting a
// non-shadow method against a non-gateway-owned class surfaces the error.
func TestSelectCarrierClassPropagatesGatewayError(t *testing.T) {
	tpl := validTemplate(t)
	if _, err := SelectCarrierClass(tpl, 2, registry.MethodWebH2Stream, true); err == nil {
		t.Fatal("SelectCarrierClass accepted a non-gateway-owned class for a web method")
	}
}

// TestSelectPrivateCarrierClassErrorPaths covers the five SelectPrivateCarrierClass
// rejection branches (previously uncovered): not-private, method mismatch,
// cannot-carry-capsule, cannot-carry-prelude, and class-not-found.
func TestSelectPrivateCarrierClassErrorPaths(t *testing.T) {
	tpl := validTemplate(t)

	// Not a private carrier slot (class 2 is origin pass-through).
	if _, err := SelectPrivateCarrierClass(tpl, 2, registry.MethodShadowOrigin, true); err == nil {
		t.Fatal("non-private class accepted as private carrier")
	}
	// Method family mismatch on a private slot.
	if _, err := SelectPrivateCarrierClass(tpl, 1, registry.MethodWebH1WS, true); err == nil {
		t.Fatal("method-family mismatch accepted for private carrier")
	}
	// Needs capsule but the class cannot carry one.
	noCapsule := validTemplate(t)
	noCapsule.RequestClasses[0].MayCarryCapsule = false
	if _, err := SelectPrivateCarrierClass(noCapsule, 1, registry.MethodWebH2Stream, true); err == nil {
		t.Fatal("capsule request accepted on a prelude-only private carrier")
	}
	// Needs prelude but the class cannot carry one.
	noPrelude := validTemplate(t)
	noPrelude.RequestClasses[0].MayCarryPrelude = false
	if _, err := SelectPrivateCarrierClass(noPrelude, 1, registry.MethodWebH2Stream, false); err == nil {
		t.Fatal("prelude request accepted on a capsule-only private carrier")
	}
	// Class id not present.
	if _, err := SelectPrivateCarrierClass(tpl, 999, registry.MethodWebH2Stream, true); err == nil {
		t.Fatal("missing class id accepted as private carrier")
	}
}

// TestSelectGatewayOwnedClassErrorPaths covers the four SelectGatewayOwnedClass
// rejection branches (previously uncovered): not-gateway-owned, cannot-carry-
// capsule, cannot-carry-prelude, and class-not-found. The non-matching-class
// continue branch is exercised by searching past class 0.
func TestSelectGatewayOwnedClassErrorPaths(t *testing.T) {
	tpl := validTemplate(t)

	// Class 2 is origin pass-through (also exercises the continue past class 0).
	if _, err := SelectGatewayOwnedClass(tpl, 2, true); err == nil {
		t.Fatal("non-gateway-owned class accepted as gateway owned")
	}
	// Needs capsule but the gateway class cannot carry one.
	noCapsule := validTemplate(t)
	noCapsule.RequestClasses[0].MayCarryCapsule = false
	if _, err := SelectGatewayOwnedClass(noCapsule, 1, true); err == nil {
		t.Fatal("capsule request accepted on a prelude-only gateway class")
	}
	// Needs prelude but the gateway class cannot carry one.
	noPrelude := validTemplate(t)
	noPrelude.RequestClasses[0].MayCarryPrelude = false
	if _, err := SelectGatewayOwnedClass(noPrelude, 1, false); err == nil {
		t.Fatal("prelude request accepted on a capsule-only gateway class")
	}
	// Class id not present.
	if _, err := SelectGatewayOwnedClass(tpl, 999, true); err == nil {
		t.Fatal("missing class id accepted as gateway owned")
	}
}

// TestValidatePreludeEnvelopeErrorPaths covers all four validatePreludeEnvelope
// rejection branches (previously uncovered) directly.
func TestValidatePreludeEnvelopeErrorPaths(t *testing.T) {
	base := func() protocol.PreludeEnvelope {
		return protocol.PreludeEnvelope{
			MinRequestBodySize:  1200,
			MaxRequestBodySize:  1536,
			MinResponseBodySize: 5000,
			MaxResponseBodySize: 6144,
		}
	}
	if err := validatePreludeEnvelope(base()); err != nil {
		t.Fatalf("baseline prelude envelope rejected: %v", err)
	}
	// Request interval inverted.
	p := base()
	p.MaxRequestBodySize = p.MinRequestBodySize - 1
	if err := validatePreludeEnvelope(p); err == nil {
		t.Fatal("inverted request size interval accepted")
	}
	// Response interval inverted.
	p = base()
	p.MaxResponseBodySize = p.MinResponseBodySize - 1
	if err := validatePreludeEnvelope(p); err == nil {
		t.Fatal("inverted response size interval accepted")
	}
	// Request envelope too small.
	p = base()
	p.MaxRequestBodySize = 1535
	if err := validatePreludeEnvelope(p); err == nil {
		t.Fatal("undersized request envelope accepted")
	}
	// Response envelope too small.
	p = base()
	p.MaxResponseBodySize = 6143
	if err := validatePreludeEnvelope(p); err == nil {
		t.Fatal("undersized response envelope accepted")
	}
}

// TestValidateCapsuleEnvelopeRejectsInvalidInterval covers the capsule body
// size interval guard (previously uncovered) directly.
func TestValidateCapsuleEnvelopeRejectsInvalidInterval(t *testing.T) {
	tpl := validTemplate(t)
	tpl.CapsuleEnvelope.MinCapsuleBodySize = 100
	tpl.CapsuleEnvelope.MaxCapsuleBodySize = 50
	if err := validateCapsuleEnvelope(tpl); err == nil {
		t.Fatal("inverted capsule body size interval accepted")
	}
}

// TestEvaluateClassifierBaselineErrorPaths covers the two EvaluateClassifierBaseline
// guards (previously uncovered): an empty sample set and a sample with an empty
// name. (DefaultClassifierBaseline's PublicProbeSurface error branch at
// classifier.go:65-67 is dead-by-design -- failure.PublicProbeSurface never
// errors because Classify always yields a CoverOrigin action -- and is not
// contrived here.)
func TestEvaluateClassifierBaselineErrorPaths(t *testing.T) {
	if _, err := EvaluateClassifierBaseline(nil); err == nil {
		t.Fatal("empty classifier sample set accepted")
	}
	samples, err := DefaultClassifierBaseline()
	if err != nil {
		t.Fatal(err)
	}
	samples[0].Name = ""
	if _, err := EvaluateClassifierBaseline(samples); err == nil {
		t.Fatal("classifier sample with empty name accepted")
	}
}

// TestEvaluateClassifierBaselineFlagsForbiddenMarkerOnOrdinary covers the
// ordinary-surface forbidden-marker path (previously uncovered): the existing
// test only attaches a forbidden public label to the candidate surface, so
// the ordinary-surface scan branch at classifier.go:110-114 was never exercised.
func TestEvaluateClassifierBaselineFlagsForbiddenMarkerOnOrdinary(t *testing.T) {
	samples, err := DefaultClassifierBaseline()
	if err != nil {
		t.Fatal(err)
	}
	samples[0].Ordinary.PublicLabels = append(samples[0].Ordinary.PublicLabels, "x-aurora-token")
	report, err := EvaluateClassifierBaseline(samples)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("classifier baseline accepted a forbidden ordinary marker: %+v", report)
	}
	if len(report.ForbiddenMarkers) != 1 {
		t.Fatalf("expected one forbidden marker, got %d: %+v", len(report.ForbiddenMarkers), report.ForbiddenMarkers)
	}
}