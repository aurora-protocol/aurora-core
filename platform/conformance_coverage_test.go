package platform

// Adversarial coverage for the pure conformance helpers in the platform
// package that the existing VerifyPackagingBlueprints/VerifyHostBuildMatrix
// suite reaches only indirectly or partially:
//   - VerifyHostBuildMatrix (host_build.go:44): the nil-packages default
//     (line 45-46), the nil-runner early return (50-53), and the empty-targets
//     early return (55-58). The existing tests pass explicit packages and a
//     populated target list to a non-nil runner, so these three branches stay
//     uncovered.
//   - verifyReleasePackagingTarget (packaging.go:165): the packet_mode,
//     release_no_entitlement, and required_entitlement rejection branches.
//   - verifyCIPackagingTarget (packaging.go:179): the ci_entitlements,
//     ci_no_entitlement, and mock_packet_flow rejection branches.
//   - addPackagingMissingFailure (packaging.go:221): the missing-target failure
//     recorder, only reachable from VerifyPackagingBlueprints when a declared
//     target is absent from the matrix.
//   - cloneExtensions (platform.go:240): the non-empty deep-copy loop body
//     (the empty/nil early return is already covered).
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestVerifyHostBuildMatrixRejectsMissingRunnerAndEmptyMatrix(t *testing.T) {
	t.Run("nil runner", func(t *testing.T) {
		report := VerifyHostBuildMatrix([]HostBuildTarget{{Name: "linux-amd64"}}, []string{"./..."}, nil)
		if report.Passed {
			t.Fatal("VerifyHostBuildMatrix accepted a nil runner")
		}
		if len(report.Findings) != 1 || report.Findings[0] != "host build runner is missing" {
			t.Fatalf("findings = %v, want [host build runner is missing]", report.Findings)
		}
	})
	t.Run("empty target matrix", func(t *testing.T) {
		report := VerifyHostBuildMatrix(nil, []string{"./..."}, &recordingHostBuildRunner{})
		if report.Passed {
			t.Fatal("VerifyHostBuildMatrix accepted an empty target matrix")
		}
		if len(report.Findings) != 1 || report.Findings[0] != "host build target matrix is empty" {
			t.Fatalf("findings = %v, want [host build target matrix is empty]", report.Findings)
		}
	})
	t.Run("nil packages default to all packages", func(t *testing.T) {
		// Passing nil packages exercises the default branch (line 45-46); the
		// runner records the args it received so the default can be observed.
		runner := &recordingHostBuildRunner{}
		report := VerifyHostBuildMatrix([]HostBuildTarget{{Name: "linux-amd64"}}, nil, runner)
		if !report.Passed || len(report.Results) != 1 {
			t.Fatalf("unexpected report: %+v", report)
		}
		if len(runner.calls) != 1 {
			t.Fatalf("runner calls = %d, want 1", len(runner.calls))
		}
		args := runner.calls[0].Args
		if args[len(args)-1] != "./..." {
			t.Fatalf("default packages = %v, want trailing ./...", args)
		}
	})
}

func TestVerifyReleasePackagingTargetRejectsEachCondition(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PackagingTarget)
		field  string
	}{
		{"packet mode mismatch", func(t *PackagingTarget) { t.PacketMode = "wrong-mode" }, "packet_mode"},
		{"release marked no-entitlement", func(t *PackagingTarget) { t.NoEntitlementOnly = true }, "release_no_entitlement"},
		{"missing required entitlement", func(t *PackagingTarget) { t.RequiredEntitlements = nil }, "required_entitlement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := validReleasePackagingTargetForCoverage()
			tc.mutate(&target)
			report := &PackagingConformanceReport{Passed: true}
			targetReport := &PackagingTargetReport{Name: target.Name, Passed: true}
			verifyReleasePackagingTarget(target, report, targetReport)
			if report.Passed || targetReport.Passed {
				t.Fatalf("verifyReleasePackagingTarget accepted %s", tc.name)
			}
			if !packagingFailureField(report, tc.field) {
				t.Fatalf("%s failures = %v, want field %q", tc.name, report.Failures, tc.field)
			}
		})
	}
}

func TestVerifyReleasePackagingTargetAcceptsValid(t *testing.T) {
	target := validReleasePackagingTargetForCoverage()
	report := &PackagingConformanceReport{Passed: true}
	targetReport := &PackagingTargetReport{Name: target.Name, Passed: true}
	verifyReleasePackagingTarget(target, report, targetReport)
	if !report.Passed || !targetReport.Passed {
		t.Fatalf("valid release target rejected: failures=%v", report.Failures)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("valid release target produced failures: %v", report.Failures)
	}
}

func TestVerifyCIPackagingTargetRejectsEachCondition(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PackagingTarget)
		field  string
	}{
		{"ci declares entitlements", func(t *PackagingTarget) { t.RequiredEntitlements = []string{"forbidden"} }, "ci_entitlements"},
		{"ci not marked no-entitlement", func(t *PackagingTarget) { t.NoEntitlementOnly = false }, "ci_no_entitlement"},
		{"ci lacks mock packet flow", func(t *PackagingTarget) { t.UsesMockPacketFlow = false }, "mock_packet_flow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := validCIPackagingTargetForCoverage()
			tc.mutate(&target)
			report := &PackagingConformanceReport{Passed: true}
			targetReport := &PackagingTargetReport{Name: target.Name, Passed: true}
			verifyCIPackagingTarget(target, report, targetReport)
			if report.Passed || targetReport.Passed {
				t.Fatalf("verifyCIPackagingTarget accepted %s", tc.name)
			}
			if !packagingFailureField(report, tc.field) {
				t.Fatalf("%s failures = %v, want field %q", tc.name, report.Failures, tc.field)
			}
		})
	}
}

func TestVerifyCIPackagingTargetAcceptsValid(t *testing.T) {
	target := validCIPackagingTargetForCoverage()
	report := &PackagingConformanceReport{Passed: true}
	targetReport := &PackagingTargetReport{Name: target.Name, Passed: true}
	verifyCIPackagingTarget(target, report, targetReport)
	if !report.Passed || !targetReport.Passed {
		t.Fatalf("valid CI target rejected: failures=%v", report.Failures)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("valid CI target produced failures: %v", report.Failures)
	}
}

func TestAddPackagingMissingFailureRecordsFailure(t *testing.T) {
	report := &PackagingConformanceReport{Passed: true}
	addPackagingMissingFailure(report, "absent-target", "declared_target")
	if report.Passed {
		t.Fatal("addPackagingMissingFailure did not mark the report failed")
	}
	if len(report.Failures) != 1 {
		t.Fatalf("failures = %d, want 1", len(report.Failures))
	}
	f := report.Failures[0]
	if f.TargetName != "absent-target" || f.Field != "declared_target" {
		t.Fatalf("failure = %+v, want TargetName=absent-target Field=declared_target", f)
	}
}

func TestCloneExtensionsDeepCopiesBodyAndHandlesEmpty(t *testing.T) {
	t.Run("empty input returns nil", func(t *testing.T) {
		if got := cloneExtensions(nil); got != nil {
			t.Fatalf("cloneExtensions(nil) = %v, want nil", got)
		}
		if got := cloneExtensions([]protocol.Extension{}); got != nil {
			t.Fatalf("cloneExtensions(empty) = %v, want nil", got)
		}
	})
	t.Run("non-empty input is deep copied", func(t *testing.T) {
		in := []protocol.Extension{{ExtensionType: 0x7005, Body: []byte("payload")}}
		orig := append([]byte(nil), in[0].Body...)
		out := cloneExtensions(in)
		if len(out) != 1 || out[0].ExtensionType != 0x7005 || !bytes.Equal(out[0].Body, orig) {
			t.Fatalf("cloneExtensions = %+v, want a copy of the input", out)
		}
		// Mutating the original Body must not affect the clone (distinct backing).
		in[0].Body[0] = 0xAA
		if !bytes.Equal(out[0].Body, orig) {
			t.Fatal("cloneExtensions shared the Body backing array with the input")
		}
		// Mutating the clone must not affect the original.
		out[0].Body[0] = 0xBB
		if in[0].Body[0] != 0xAA {
			t.Fatal("cloneExtensions output aliases the input Body")
		}
	})
}

// validReleasePackagingTargetForCoverage returns a PackagingTarget that passes
// every verifyReleasePackagingTarget check (KindLinux release with the
// required tun-device entitlement). Each rejection subtest perturbs exactly
// one field so the rejection is attributable to that field alone.
func validReleasePackagingTargetForCoverage() PackagingTarget {
	return PackagingTarget{
		Name:                 "linux-release",
		Kind:                 KindLinux,
		Release:              true,
		PacketMode:           PacketTUN,
		RequiredEntitlements: []string{"tun-device"},
	}
}

// validCIPackagingTargetForCoverage returns a PackagingTarget that passes
// every verifyCIPackagingTarget check (entitlement-free CI with mock packet
// flow). Each rejection subtest perturbs exactly one field.
func validCIPackagingTargetForCoverage() PackagingTarget {
	return PackagingTarget{
		Name:               "linux-ci",
		Kind:               KindCI,
		CI:                 true,
		NoEntitlementOnly:  true,
		UsesMockPacketFlow: true,
	}
}

// packagingFailureField reports whether a conformance report carries a
// failure for the given field.
func packagingFailureField(report *PackagingConformanceReport, field string) bool {
	for _, f := range report.Failures {
		if f.Field == field {
			return true
		}
	}
	return false
}
