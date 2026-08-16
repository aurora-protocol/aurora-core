package protocol

// Adversarial coverage for the bootstrap-message validators and signature-zeroing
// helpers in protocol/bootstrap.go. The existing bootstrap_validation_test.go covers
// only the happy path (each fuzzSample passes ValidateStructural) and the
// unknown-critical-extension branch (which is why every ValidateExtensions error
// return is already covered). Every other error branch in the seven ValidateStructural
// cascades stays at count 0, as do the four Unsigned*/UnsignedClientFinished helpers
// (0% before — only the signing code calls them, never the tests).
//
// This file covers the residual branches by mutating exactly one field of a fuzzSample
// baseline per case so the branch under test is the one that fires. Each ValidateStructural
// is a short cascade: a MsgType check, then (preludes) version/suite[/shape] checks, then
// an extensions check, or (capsules) one sub-struct validation per nested proof/offer/
// accept/hints. The sub-struct validators are themselves covered by their own coverage
// files (admission_validation_coverage_test.go, policy_validation_*.go,
// transport_hints_test.go); here we only need each sub-validator to FAIL so the capsule
// branch that propagates its error is reached, so a single minimal mutation per sub-struct
// suffices.
//
// Uncovered blocks (measured count 0 before this file):
//   - CoverPrelude0.ValidateStructural (72, 70.0%): MsgType 73, Version 76, Suite 80.
//   - CoverPrelude1.ValidateStructural (146, 66.7%): MsgType 147, Version 150, Suite 153.
//   - CoverCapsule1Plain.ValidateStructural (206, 61.5%): MsgType 207, AdmissionProof 210,
//     ReplayProof 213, PolicyOffer 216, ClientTransportHints 219.
//   - CoverCapsule2Plain.ValidateStructural (262, 71.4%): MsgType 263, PolicyAccept 266.
//   - RouteCapsule1Plain.ValidateStructural (313, 63.6%): MsgType 314, AdmissionProof 317,
//     ReplayProof 320, PolicyOffer 323.
//   - RouteCapsule2Plain.ValidateStructural (369, 71.4%): MsgType 370, PolicyAccept 373.
//   - RoutePrelude1.ValidateStructural (441, 63.6%): MsgType 442, Version 445, Suite 448,
//     Shape 451.
//   - CoverPrelude1.Unsigned (162), CoverCapsule1Plain.UnsignedClientFinished (228),
//     RouteCapsule1Plain.UnsignedClientFinished (332), RoutePrelude1.Unsigned (460): 0%.
//
// Not duplicated: the happy paths and the ValidateExtensions error returns are already
// covered by bootstrap_validation_test.go and are not repeated here. The sub-struct
// validators' own internals are covered by their dedicated coverage files; this file
// only drives each to a failure so the capsule propagation branch fires.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection asserts exactly one error substring so the failure
// is attributable to the perturbed field alone. No new package-level helpers are added
// (the fuzzSample* baselines are reused), so there is no U1000 concern. No context.Context,
// no deprecated APIs.

import (
	"strings"
	"testing"
)

// bootstrapCovBadVersion/Suite/Shape are distinct reserved values the validators reject.
// They are package-level so each table case can reference them by name; each is used by
// >=2 tests, so neither is U1000.
const (
	bootstrapCovBadVersion uint64 = 0
	bootstrapCovBadSuite   uint64 = 0xBAD
	bootstrapCovBadShape   uint64 = 0xBAD
)

func TestCoverPrelude0ValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CoverPrelude0)
		wantSub string
	}{
		{"wrong message type", func(p *CoverPrelude0) { p.MsgType = 0xBAD }, "malformed CoverPrelude0 message type"},
		{"reserved version", func(p *CoverPrelude0) { p.Version = bootstrapCovBadVersion }, "reserved version"},
		{"reserved suite offer", func(p *CoverPrelude0) { p.SuiteOffers = []uint64{bootstrapCovBadSuite} }, "reserved suite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleCoverPrelude0()
			tc.mutate(&v)
			err := v.ValidateStructural()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestCoverPrelude1ValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CoverPrelude1)
		wantSub string
	}{
		{"wrong message type", func(p *CoverPrelude1) { p.MsgType = 0xBAD }, "malformed CoverPrelude1 message type"},
		{"reserved version", func(p *CoverPrelude1) { p.Version = bootstrapCovBadVersion }, "reserved version"},
		{"reserved selected suite", func(p *CoverPrelude1) { p.SelectedSuite = bootstrapCovBadSuite }, "reserved suite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleCoverPrelude1()
			tc.mutate(&v)
			err := v.ValidateStructural()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestCoverCapsule1PlainValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CoverCapsule1Plain)
		wantSub string
	}{
		{"wrong message type", func(c *CoverCapsule1Plain) { c.MsgType = 0xBAD }, "malformed CoverCapsule1 message type"},
		{"admission proof rejected", func(c *CoverCapsule1Plain) { c.AdmissionProof.ProofVersion = bootstrapCovBadVersion }, "unsupported admission proof version"},
		{"replay proof rejected", func(c *CoverCapsule1Plain) { c.ReplayProof.ProofVersion = bootstrapCovBadVersion }, "unsupported replay proof version"},
		{"policy offer rejected", func(c *CoverCapsule1Plain) { c.PolicyOffer.OfferedVersions = []uint64{bootstrapCovBadVersion} }, "reserved version"},
		{"client transport hints rejected", func(c *CoverCapsule1Plain) { c.ClientTransportHints.HintFlags = 1 }, "client transport hint_flags must be zero"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleCoverCapsule1Plain()
			tc.mutate(&v)
			err := v.ValidateStructural(15, false)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestCoverCapsule2PlainValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CoverCapsule2Plain)
		wantSub string
	}{
		{"wrong message type", func(c *CoverCapsule2Plain) { c.MsgType = 0xBAD }, "malformed CoverCapsule2 message type"},
		{"policy accept rejected", func(c *CoverCapsule2Plain) { c.PolicyAccept.SelectedVersion = bootstrapCovBadVersion }, "reserved version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleCoverCapsule2Plain()
			tc.mutate(&v)
			err := v.ValidateStructural()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestRouteCapsule1PlainValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RouteCapsule1Plain)
		wantSub string
	}{
		{"wrong message type", func(c *RouteCapsule1Plain) { c.MsgType = 0xBAD }, "malformed RouteCapsule1 message type"},
		{"admission proof rejected", func(c *RouteCapsule1Plain) { c.AdmissionProof.ProofVersion = bootstrapCovBadVersion }, "unsupported admission proof version"},
		{"replay proof rejected", func(c *RouteCapsule1Plain) { c.ReplayProof.ProofVersion = bootstrapCovBadVersion }, "unsupported replay proof version"},
		{"policy offer rejected", func(c *RouteCapsule1Plain) { c.PolicyOffer.OfferedVersions = []uint64{bootstrapCovBadVersion} }, "reserved version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleRouteCapsule1Plain()
			tc.mutate(&v)
			err := v.ValidateStructural(15, false)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestRouteCapsule2PlainValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RouteCapsule2Plain)
		wantSub string
	}{
		{"wrong message type", func(c *RouteCapsule2Plain) { c.MsgType = 0xBAD }, "malformed RouteCapsule2 message type"},
		{"policy accept rejected", func(c *RouteCapsule2Plain) { c.PolicyAccept.SelectedVersion = bootstrapCovBadVersion }, "reserved version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleRouteCapsule2Plain()
			tc.mutate(&v)
			err := v.ValidateStructural()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestRoutePrelude1ValidateStructuralDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RoutePrelude1)
		wantSub string
	}{
		{"wrong message type", func(p *RoutePrelude1) { p.MsgType = 0xBAD }, "malformed RoutePrelude1 message type"},
		{"reserved version", func(p *RoutePrelude1) { p.Version = bootstrapCovBadVersion }, "reserved version"},
		{"reserved selected suite", func(p *RoutePrelude1) { p.SelectedSuite = bootstrapCovBadSuite }, "reserved suite"},
		{"reserved selected shape", func(p *RoutePrelude1) { p.SelectedShapeID = bootstrapCovBadShape }, "reserved shape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := fuzzSampleRoutePrelude1()
			tc.mutate(&v)
			err := v.ValidateStructural()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestBootstrapUnsignedMethodsZeroSignatures(t *testing.T) {
	// CoverPrelude1.Unsigned zeroes both prelude signature fields; a non-signature
	// field must survive.
	cp1 := fuzzSampleCoverPrelude1()
	cp1u := cp1.Unsigned()
	if cp1u.ServerPreludeSignatureClassical != nil || cp1u.ServerPreludeSignaturePQ != nil {
		t.Fatalf("CoverPrelude1.Unsigned left signatures set: cls=%v pq=%v", cp1u.ServerPreludeSignatureClassical, cp1u.ServerPreludeSignaturePQ)
	}
	if cp1u.SelectedSuite != cp1.SelectedSuite {
		t.Fatalf("CoverPrelude1.Unsigned dropped SelectedSuite: got %d want %d", cp1u.SelectedSuite, cp1.SelectedSuite)
	}

	// RoutePrelude1.Unsigned zeroes both prelude signature fields.
	rp1 := fuzzSampleRoutePrelude1()
	rp1u := rp1.Unsigned()
	if rp1u.ServerPreludeSignatureClassical != nil || rp1u.ServerPreludeSignaturePQ != nil {
		t.Fatalf("RoutePrelude1.Unsigned left signatures set: cls=%v pq=%v", rp1u.ServerPreludeSignatureClassical, rp1u.ServerPreludeSignaturePQ)
	}
	if rp1u.RouteInstanceID != rp1.RouteInstanceID {
		t.Fatalf("RoutePrelude1.Unsigned dropped RouteInstanceID: got %d want %d", rp1u.RouteInstanceID, rp1.RouteInstanceID)
	}

	// CoverCapsule1Plain.UnsignedClientFinished zeroes ClientFinished only.
	cc1 := fuzzSampleCoverCapsule1Plain()
	cc1u := cc1.UnsignedClientFinished()
	if cc1u.ClientFinished != nil {
		t.Fatalf("CoverCapsule1Plain.UnsignedClientFinished left ClientFinished set: %v", cc1u.ClientFinished)
	}
	if cc1u.RouteInstanceID != cc1.RouteInstanceID {
		t.Fatalf("CoverCapsule1Plain.UnsignedClientFinished dropped RouteInstanceID: got %d want %d", cc1u.RouteInstanceID, cc1.RouteInstanceID)
	}

	// RouteCapsule1Plain.UnsignedClientFinished zeroes ClientFinished only.
	rc1 := fuzzSampleRouteCapsule1Plain()
	rc1u := rc1.UnsignedClientFinished()
	if rc1u.ClientFinished != nil {
		t.Fatalf("RouteCapsule1Plain.UnsignedClientFinished left ClientFinished set: %v", rc1u.ClientFinished)
	}
	if rc1u.HopIndex != rc1.HopIndex {
		t.Fatalf("RouteCapsule1Plain.UnsignedClientFinished dropped HopIndex: got %d want %d", rc1u.HopIndex, rc1.HopIndex)
	}
}
