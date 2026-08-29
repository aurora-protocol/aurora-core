package release

// Adversarial coverage for the pure readiness-validation helpers in
// release.go that the existing TestVerifyReleaseReadiness* suite reaches only
// indirectly through the top-level VerifyReleaseReadiness/RunReleaseReadinessHarness
// path. Driving each helper directly with a crafted input isolates the
// individual finding branches (the harness exercises some but not all of them).
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// All five helpers are pure: they take crafted structs/strings and a
// *ReadinessReport, append a finding on rejection, and return a bool. No
// crypto, network, or filesystem fixture is needed.

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
)

const hexCommitForCoverage = "abcdef0123456789abcdef0123456789abcdef01" // 40 hex chars

func TestVerifyArtifactProvenanceRejectsEachInvalidField(t *testing.T) {
	digest := bytes.Repeat([]byte{0x01}, 48)
	cases := []struct {
		name        string
		mutate      func(*Provenance)
		wantFinding string
	}{
		{"unsupported predicate", func(p *Provenance) { p.PredicateType = "https://wrong" }, "predicate is unsupported"},
		{"missing build type", func(p *Provenance) { p.BuildType = "" }, "lacks build type or builder"},
		{"missing source repository", func(p *Provenance) { p.SourceRepository = "" }, "lacks source repository or commit"},
		{"subject name mismatch", func(p *Provenance) { p.SubjectName = "wrong-subject" }, "subject mismatch"},
		{"slsa level below three", func(p *Provenance) { p.SLSALevel = 2 }, "below required build level"},
		{"no resolved dependencies", func(p *Provenance) { p.ResolvedDependencies = nil }, "lacks resolved dependencies"},
		{"dependency incomplete", func(p *Provenance) {
			p.ResolvedDependencies = []Dependency{{URI: "", Digest: bytes.Repeat([]byte{0x02}, 48)}}
		}, "dependency is incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			artifact := validArtifactForCoverage(digest)
			tc.mutate(&artifact.Provenance)
			var report ReadinessReport
			if passed := verifyArtifactProvenance([]Artifact{artifact}, &report); passed {
				t.Fatalf("verifyArtifactProvenance accepted %s", tc.name)
			}
			if !findingsContain(report.Findings, tc.wantFinding) {
				t.Fatalf("verifyArtifactProvenance(%s) findings=%v, want substring %q", tc.name, report.Findings, tc.wantFinding)
			}
		})
	}
}

func TestVerifyArtifactProvenanceAcceptsValid(t *testing.T) {
	artifact := validArtifactForCoverage(bytes.Repeat([]byte{0x01}, 48))
	var report ReadinessReport
	if passed := verifyArtifactProvenance([]Artifact{artifact}, &report); !passed {
		t.Fatalf("valid artifact provenance rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid artifact produced findings: %v", report.Findings)
	}
}

func TestVerifyIncidentResponsePlanRejectsEachInvalidCondition(t *testing.T) {
	const nowUnix = uint64(200)
	cases := []struct {
		name        string
		mutate      func(*IncidentResponsePlan)
		wantFinding string
	}{
		{"metadata incomplete", func(p *IncidentResponsePlan) { p.PlanID = "" }, "metadata is incomplete"},
		{"invalid exercise timestamp", func(p *IncidentResponsePlan) { p.LastExerciseUnix = 0 }, "exercise timestamp is invalid"},
		{"stale exercise", func(p *IncidentResponsePlan) {
			p.MaxExerciseAgeSeconds = 10 // nowUnix(200)-LastExercise(100)=100 > 10 -> stale; covers maxAge!=0 path
		}, "exercise is stale"},
		{"drills incomplete", func(p *IncidentResponsePlan) { p.CompromisedKeyTested = false }, "drills are incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := validIncidentResponsePlanForCoverage()
			tc.mutate(&plan)
			var report ReadinessReport
			if passed := verifyIncidentResponsePlan(plan, nowUnix, &report); passed {
				t.Fatalf("verifyIncidentResponsePlan accepted %s", tc.name)
			}
			if !findingsContain(report.Findings, tc.wantFinding) {
				t.Fatalf("verifyIncidentResponsePlan(%s) findings=%v, want substring %q", tc.name, report.Findings, tc.wantFinding)
			}
		})
	}
}

func TestVerifyIncidentResponsePlanAcceptsValid(t *testing.T) {
	// A valid plan with MaxExerciseAgeSeconds==0 exercises the default-age
	// (180 days) branch and the not-stale path; nowUnix-LastExerciseUnix is
	// well within the default window.
	plan := validIncidentResponsePlanForCoverage()
	var report ReadinessReport
	if passed := verifyIncidentResponsePlan(plan, 200, &report); !passed {
		t.Fatalf("valid incident response plan rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid plan produced findings: %v", report.Findings)
	}
}

func TestVerifyReproducibleBuildsRejectsInvalidDigests(t *testing.T) {
	t.Run("invalid digest length", func(t *testing.T) {
		artifact := Artifact{Digest: bytes.Repeat([]byte{0x01}, 47), RebuildDigest: bytes.Repeat([]byte{0x01}, 48)}
		var report ReadinessReport
		if passed := verifyReproducibleBuilds([]Artifact{artifact}, &report); passed {
			t.Fatal("verifyReproducibleBuilds accepted a too-short digest")
		}
		if !findingsContain(report.Findings, "digest length is invalid") {
			t.Fatalf("findings=%v, want digest length finding", report.Findings)
		}
	})
	t.Run("rebuild digest mismatch", func(t *testing.T) {
		artifact := Artifact{Digest: bytes.Repeat([]byte{0x01}, 48), RebuildDigest: bytes.Repeat([]byte{0x02}, 48)}
		var report ReadinessReport
		if passed := verifyReproducibleBuilds([]Artifact{artifact}, &report); passed {
			t.Fatal("verifyReproducibleBuilds accepted a mismatched rebuild digest")
		}
		if !findingsContain(report.Findings, "rebuild digest mismatch") {
			t.Fatalf("findings=%v, want rebuild mismatch finding", report.Findings)
		}
	})
}

func TestVerifyReproducibleBuildsAcceptsValid(t *testing.T) {
	artifact := Artifact{Digest: bytes.Repeat([]byte{0x01}, 48), RebuildDigest: bytes.Repeat([]byte{0x01}, 48)}
	var report ReadinessReport
	if passed := verifyReproducibleBuilds([]Artifact{artifact}, &report); !passed {
		t.Fatalf("valid reproducible build rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid build produced findings: %v", report.Findings)
	}
}

func TestVerifyRequiredReleaseArtifactsRejectsInvalidArtifacts(t *testing.T) {
	target := platform.PackagingTarget{Name: "aurora-core-linux-amd64", Kind: platform.KindLinux}
	t.Run("missing artifact", func(t *testing.T) {
		var report ReadinessReport
		if passed := verifyRequiredReleaseArtifacts([]platform.PackagingTarget{target}, map[string]Artifact{}, &report); passed {
			t.Fatal("verifyRequiredReleaseArtifacts accepted a missing artifact")
		}
		if !findingsContain(report.Findings, "release artifact missing for ") {
			t.Fatalf("findings=%v, want missing-artifact finding", report.Findings)
		}
	})
	t.Run("platform mismatch", func(t *testing.T) {
		artifact := Artifact{Name: target.Name, Platform: platform.KindOpenWrt, Version: "1.0.0", SizeBytes: 1024}
		var report ReadinessReport
		if passed := verifyRequiredReleaseArtifacts([]platform.PackagingTarget{target}, map[string]Artifact{target.Name: artifact}, &report); passed {
			t.Fatal("verifyRequiredReleaseArtifacts accepted a platform mismatch")
		}
		if !findingsContain(report.Findings, "release artifact platform mismatch for ") {
			t.Fatalf("findings=%v, want platform mismatch finding", report.Findings)
		}
	})
	t.Run("missing version or size", func(t *testing.T) {
		artifact := Artifact{Name: target.Name, Platform: platform.KindLinux, Version: "", SizeBytes: 0}
		var report ReadinessReport
		if passed := verifyRequiredReleaseArtifacts([]platform.PackagingTarget{target}, map[string]Artifact{target.Name: artifact}, &report); passed {
			t.Fatal("verifyRequiredReleaseArtifacts accepted an artifact without version or size")
		}
		if !findingsContain(report.Findings, "release artifact lacks version or size for ") {
			t.Fatalf("findings=%v, want version/size finding", report.Findings)
		}
	})
}

func TestVerifyRequiredReleaseArtifactsAcceptsValid(t *testing.T) {
	target := platform.PackagingTarget{Name: "aurora-core-linux-amd64", Kind: platform.KindLinux}
	artifact := Artifact{Name: target.Name, Platform: platform.KindLinux, Version: "1.0.0", SizeBytes: 1024}
	var report ReadinessReport
	if passed := verifyRequiredReleaseArtifacts([]platform.PackagingTarget{target}, map[string]Artifact{target.Name: artifact}, &report); !passed {
		t.Fatalf("valid required release artifact rejected: findings=%v", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("valid artifact produced findings: %v", report.Findings)
	}
}

func TestIsHexCommitClassification(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"forty hex chars", hexCommitForCoverage, true},
		{"forty non-hex chars", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false}, // hex.DecodeString fails
		{"wrong length", "abc", false},                                             // len != 40
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHexCommit(tc.value); got != tc.want {
				t.Fatalf("isHexCommit(%q) = %t, want %t", tc.value, got, tc.want)
			}
		})
	}
}

// validArtifactForCoverage returns an Artifact whose Provenance passes every
// verifyArtifactProvenance check; the caller supplies the digest so
// SubjectDigest and artifact.Digest stay consistent. Each rejection subtest
// perturbs exactly one Provenance field so the rejection is attributable to
// that field alone.
func validArtifactForCoverage(digest []byte) Artifact {
	return Artifact{
		Name:      "aurora-core-linux-amd64",
		Platform:  platform.KindLinux,
		Version:   "1.0.0",
		SizeBytes: 1024,
		Digest:    digest,
		Provenance: Provenance{
			PredicateType:        PredicateSLSAProvenance,
			BuildType:            "https://aurora.example/build",
			BuilderID:            "https://aurora.example/builder",
			SourceRepository:     "https://github.com/aurora-protocol/aurora-core",
			SourceCommit:         hexCommitForCoverage,
			SubjectName:          "aurora-core-linux-amd64",
			SubjectDigest:        digest,
			SLSALevel:            3,
			ResolvedDependencies: []Dependency{{URI: "https://example/dep", Digest: bytes.Repeat([]byte{0x02}, 48)}},
		},
	}
}

// validIncidentResponsePlanForCoverage returns a plan that passes every
// verifyIncidentResponsePlan check at nowUnix=200 (LastExerciseUnix=100,
// MaxExerciseAgeSeconds=0 -> default 180 days, well within window, all drills
// tested). Each rejection subtest perturbs exactly one field.
func validIncidentResponsePlanForCoverage() IncidentResponsePlan {
	return IncidentResponsePlan{
		PlanID:                   "plan-1",
		SecurityContact:          "security@aurora.example",
		KeyRevocationRunbookID:   "runbook-key-rev",
		UpdateRollbackRunbookID:  "runbook-rollback",
		AbuseEscalationRunbookID: "runbook-abuse",
		LastExerciseUnix:         100,
		MaxExerciseAgeSeconds:    0,
		CompromisedKeyTested:     true,
		UpdateRollbackTested:     true,
		DisclosureWorkflowTested: true,
	}
}

// findingsContain reports whether any finding contains substr as a substring.
func findingsContain(findings []string, substr string) bool {
	for _, f := range findings {
		if bytes.Contains([]byte(f), []byte(substr)) {
			return true
		}
	}
	return false
}

// TestVerifyIncidentResponsePlanCapsLooserExerciseAge proves a bundle cannot
// raise its own staleness bar: a self-reported MaxExerciseAgeSeconds above the
// 180-day default must be capped, while a stricter bar is still honored.
func TestVerifyIncidentResponsePlanCapsLooserExerciseAge(t *testing.T) {
	const day = uint64(24 * 60 * 60)
	const nowUnix = 400 * day
	plan := validIncidentResponsePlanForCoverage()
	plan.LastExerciseUnix = nowUnix - 365*day
	plan.MaxExerciseAgeSeconds = ^uint64(0)
	var report ReadinessReport
	if passed := verifyIncidentResponsePlan(plan, nowUnix, &report); passed {
		t.Fatalf("self-reported max exercise age let a 365-day-old exercise through: %v", report.Findings)
	}
	if !findingsContain(report.Findings, "exercise is stale") {
		t.Fatalf("findings=%v, want stale-exercise finding", report.Findings)
	}

	plan = validIncidentResponsePlanForCoverage()
	plan.LastExerciseUnix = nowUnix - 100*day
	plan.MaxExerciseAgeSeconds = 90 * day
	report = ReadinessReport{}
	if passed := verifyIncidentResponsePlan(plan, nowUnix, &report); passed {
		t.Fatalf("stricter 90-day bar let a 100-day-old exercise through: %v", report.Findings)
	}
}
