package release

// Adversarial white-box coverage for verifySignedUpdatePipeline
// (release/release.go 351-449), the signed-update-pipeline gate of the
// release-readiness harness. verifySignedUpdatePipeline validates that a
// SignedUpdatePipeline carries the four known roles (root/targets/snapshot/
// timestamp) exactly once each, that each role's signature input encodes and
// its signature threshold is met, and that the four roles' PayloadDigest
// fields chain correctly: root links to the targets-payload digest, targets
// IS the targets-payload digest, snapshot links to targets' payload, and
// timestamp links to snapshot's payload. It then checks that every target
// references a known artifact with matching digest/size and that every
// artifact is referenced by some target.
//
// The existing readiness harness exercises the fully-consistent happy path
// and several guards (unknown/duplicate roles, expired roles, threshold
// failures, root mismatch), so the eight count-0 branches below are the
// rejection paths the harness does not construct.
//
// consistentUpdatePipeline builds a fully-consistent pipeline using the
// package's own digest helpers (updateTargetsPayloadDigest,
// roleLinkPayloadDigest) and a real ECDSA signature per role via
// newSigner()/sign(), so a verifySignedUpdatePipeline call on it returns
// true with no findings. Each rejection test then perturbs exactly one field
// (or the role/artifact set) to trip exactly one guard, asserting the
// specific finding substring is present. Where a perturbation invalidates a
// role's signature (changing its PayloadDigest), reSignRole re-signs that
// role so the threshold check still passes and the link-mismatch finding is
// isolated from the threshold-failure finding.
//
// Targets covered (previously count-0):
//
//   - :375-378 — a known role is missing. Drop the timestamp role; the loop
//     at 373 finds it absent and reports "role timestamp missing" while the
//     other three roles and the target/artifact checks still pass.
//   - :381-384 — a role's updateRoleSignatureInput fails (its PayloadDigest is
//     not 48 bytes). The root role's PayloadDigest is shortened; the gate
//     reports "role root input failed" before its expiry/threshold checks
//     run. (The already-covered root link-mismatch at :400 co-fires; only the
//     "input failed" finding is asserted.)
//   - :396-398 — updateTargetsPayloadDigest fails (a target's Digest is not 48
//     bytes). The gate reports "targets payload failed"; the already-covered
//     target digest-mismatch at :437 co-fires and only the payload-failed
//     finding is asserted.
//   - :404-407 — the targets role's PayloadDigest does not equal the
//     targets-payload digest. The targets role is given a valid 48-byte but
//     wrong PayloadDigest and re-signed so its threshold still passes;
//     "targets payload digest mismatch" fires in isolation.
//   - :411-414 — the snapshot role's PayloadDigest does not link to the
//     targets role's payload. Re-signed for isolation; "snapshot payload
//     digest mismatch" fires.
//   - :418-421 — the timestamp role's PayloadDigest does not link to the
//     snapshot role's payload. Re-signed for isolation; "timestamp payload
//     digest mismatch" fires.
//   - :437-439 — a target's digest or size does not match its artifact. The
//     single target's SizeBytes is changed (the targets-payload digest is
//     computed only from target.Digest, so the role link chain stays valid
//     and this finding fires in isolation).
//   - :443-446 — an artifact in the map is not referenced by any target. A
//     second artifact is added with no matching target; "target missing for"
//     that artifact fires in isolation.
//
// verifySignedUpdatePipelineSucceedsForConsistentPipeline grounds the happy
// path so the eight rejection tests are meaningful contrasts (each perturbs
// exactly one thing from the consistent baseline).
//
// consistentUpdatePipeline, signedUpdateFindings, and reSignRole are each
// referenced by multiple tests, so there is no staticcheck U1000 surface. No
// context.Context (no SA1012 surface). The cryptography is real ECDSA P-256
// via newSigner (crypto/rand), bounded and self-contained: no network, no
// filesystem, no goroutines, and no flaky surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
)

// consistentUpdatePipeline returns a SignedUpdatePipeline and matching
// artifactsByName map on which verifySignedUpdatePipeline returns true: the
// four known roles are present exactly once, each role's PayloadDigest chains
// correctly (root links to the targets-payload digest, targets IS that
// digest, snapshot links to targets' payload, timestamp links to snapshot's
// payload), each role is signed over its own signature input by a fresh
// ECDSA key, and the single target references the single artifact with a
// matching digest and size.
func consistentUpdatePipeline(t *testing.T, now uint64) (SignedUpdatePipeline, map[string]Artifact) {
	t.Helper()
	artifact := Artifact{
		Name:      "aurora-core-linux-amd64",
		Platform:  platform.KindLinux,
		Version:   "1.0.0",
		SizeBytes: 1024,
		Digest:    make([]byte, 48),
	}
	artifacts := map[string]Artifact{artifact.Name: artifact}
	targets := []UpdateTarget{{ArtifactName: artifact.Name, Digest: artifact.Digest, SizeBytes: artifact.SizeBytes}}

	targetDigest, err := updateTargetsPayloadDigest(targets)
	if err != nil {
		t.Fatalf("updateTargetsPayloadDigest: %v", err)
	}

	// signRole builds a role whose signature is valid over its own signature
	// input, so the threshold check at :390 passes for the baseline.
	signRole := func(name string, payloadDigest []byte) UpdateRole {
		role := UpdateRole{
			Name:          name,
			Version:       1,
			ExpiresUnix:   now + 1_000_000,
			Threshold:     1,
			PayloadDigest: payloadDigest,
		}
		input, err := updateRoleSignatureInput(role)
		if err != nil {
			t.Fatalf("updateRoleSignatureInput(%s): %v", name, err)
		}
		s, err := newSigner()
		if err != nil {
			t.Fatalf("newSigner(%s): %v", name, err)
		}
		sig, err := s.sign(input)
		if err != nil {
			t.Fatalf("sign(%s): %v", name, err)
		}
		role.Signatures = []SignatureRecord{sig}
		return role
	}

	rootDigest := roleLinkPayloadDigest(RoleRoot, targetDigest)
	snapshotDigest := roleLinkPayloadDigest(RoleSnapshot, targetDigest)
	timestampDigest := roleLinkPayloadDigest(RoleTimestamp, snapshotDigest)

	pipeline := SignedUpdatePipeline{
		Roles: []UpdateRole{
			signRole(RoleRoot, rootDigest),
			signRole(RoleTargets, targetDigest),
			signRole(RoleSnapshot, snapshotDigest),
			signRole(RoleTimestamp, timestampDigest),
		},
		Targets: targets,
	}
	return pipeline, artifacts
}

// signedUpdateFindings runs the gate and returns the result plus the joined
// findings string for substring checks.
func signedUpdateFindings(pipeline SignedUpdatePipeline, artifacts map[string]Artifact, now uint64) (bool, string) {
	report := &ReadinessReport{}
	ok := verifySignedUpdatePipeline(pipeline, artifacts, now, report)
	return ok, strings.Join(report.Findings, "\n")
}

// reSignRole re-signs the named role over its current signature input so that
// after a PayloadDigest perturbation the threshold check still passes and a
// link-mismatch finding is not masked by a threshold-failure finding.
func reSignRole(t *testing.T, pipeline *SignedUpdatePipeline, name string) {
	t.Helper()
	for i := range pipeline.Roles {
		if pipeline.Roles[i].Name != name {
			continue
		}
		input, err := updateRoleSignatureInput(pipeline.Roles[i])
		if err != nil {
			t.Fatalf("updateRoleSignatureInput(%s): %v", name, err)
		}
		s, err := newSigner()
		if err != nil {
			t.Fatalf("newSigner(%s): %v", name, err)
		}
		sig, err := s.sign(input)
		if err != nil {
			t.Fatalf("sign(%s): %v", name, err)
		}
		pipeline.Roles[i].Signatures = []SignatureRecord{sig}
		return
	}
	t.Fatalf("reSignRole: role %s not found", name)
}

func TestVerifySignedUpdatePipelineRejectsMissingRole(t *testing.T) {
	// 375-378: the timestamp role is absent, so the loop at 373 reports it
	// missing while the other three roles and the target/artifact checks pass.
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	var roles []UpdateRole
	for _, r := range pipeline.Roles {
		if r.Name != RoleTimestamp {
			roles = append(roles, r)
		}
	}
	pipeline.Roles = roles
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(missing timestamp) = true, want false")
	}
	if !strings.Contains(findings, "signed update role "+RoleTimestamp+" missing") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update role "+RoleTimestamp+" missing")
	}
}

func TestVerifySignedUpdatePipelineRejectsRoleInputFailure(t *testing.T) {
	// 381-384: the root role's PayloadDigest is not 48 bytes, so
	// updateRoleSignatureInput fails and the gate reports the root input failed
	// before its expiry/threshold checks run. (The already-covered root
	// link-mismatch at :400 co-fires; only the input-failed finding is asserted.)
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	for i := range pipeline.Roles {
		if pipeline.Roles[i].Name == RoleRoot {
			pipeline.Roles[i].PayloadDigest = []byte{0x01, 0x02, 0x03}
		}
	}
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(root bad payload) = true, want false")
	}
	if !strings.Contains(findings, "signed update role "+RoleRoot+" input failed") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update role "+RoleRoot+" input failed")
	}
}

func TestVerifySignedUpdatePipelineRejectsTargetsPayloadFailure(t *testing.T) {
	// 396-398: a target's Digest is not 48 bytes, so updateTargetsPayloadDigest
	// fails and the gate reports the targets payload failed. (The already-
	// covered target digest-mismatch at :437 co-fires; only the payload-failed
	// finding is asserted.)
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	pipeline.Targets[0].Digest = []byte{0x01, 0x02, 0x03}
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(bad target digest) = true, want false")
	}
	if !strings.Contains(findings, "signed update targets payload failed") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update targets payload failed")
	}
}

func TestVerifySignedUpdatePipelineRejectsTargetsPayloadDigestMismatch(t *testing.T) {
	// 404-407: the targets role's PayloadDigest is a valid 48 bytes but not the
	// targets-payload digest. Re-signed so the threshold still passes, which
	// isolates the link-mismatch finding from the threshold-failure finding.
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	for i := range pipeline.Roles {
		if pipeline.Roles[i].Name == RoleTargets {
			pipeline.Roles[i].PayloadDigest = make([]byte, 48) // valid length, wrong value
		}
	}
	reSignRole(t, &pipeline, RoleTargets)
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(targets link mismatch) = true, want false")
	}
	if !strings.Contains(findings, "signed update targets payload digest mismatch") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update targets payload digest mismatch")
	}
	if strings.Contains(findings, "lacks threshold signatures") {
		t.Fatalf("targets link mismatch masked by threshold failure; re-sign did not isolate: %q", findings)
	}
}

func TestVerifySignedUpdatePipelineRejectsSnapshotPayloadDigestMismatch(t *testing.T) {
	// 411-414: the snapshot role's PayloadDigest does not link to the targets
	// role's payload. Re-signed for isolation.
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	for i := range pipeline.Roles {
		if pipeline.Roles[i].Name == RoleSnapshot {
			pipeline.Roles[i].PayloadDigest = make([]byte, 48)
		}
	}
	reSignRole(t, &pipeline, RoleSnapshot)
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(snapshot link mismatch) = true, want false")
	}
	if !strings.Contains(findings, "signed update snapshot payload digest mismatch") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update snapshot payload digest mismatch")
	}
	if strings.Contains(findings, "lacks threshold signatures") {
		t.Fatalf("snapshot link mismatch masked by threshold failure; re-sign did not isolate: %q", findings)
	}
}

func TestVerifySignedUpdatePipelineRejectsTimestampPayloadDigestMismatch(t *testing.T) {
	// 418-421: the timestamp role's PayloadDigest does not link to the snapshot
	// role's payload. Re-signed for isolation.
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	for i := range pipeline.Roles {
		if pipeline.Roles[i].Name == RoleTimestamp {
			pipeline.Roles[i].PayloadDigest = make([]byte, 48)
		}
	}
	reSignRole(t, &pipeline, RoleTimestamp)
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(timestamp link mismatch) = true, want false")
	}
	if !strings.Contains(findings, "signed update timestamp payload digest mismatch") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update timestamp payload digest mismatch")
	}
	if strings.Contains(findings, "lacks threshold signatures") {
		t.Fatalf("timestamp link mismatch masked by threshold failure; re-sign did not isolate: %q", findings)
	}
}

func TestVerifySignedUpdatePipelineRejectsTargetDigestOrSizeMismatch(t *testing.T) {
	// 437-439: the single target's size does not match its artifact.
	// updateTargetsPayloadDigest is computed only from target.Digest, so the
	// role link chain stays valid and this finding fires in isolation.
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	pipeline.Targets[0].SizeBytes = 2048 // artifact.SizeBytes is 1024
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(target size mismatch) = true, want false")
	}
	if !strings.Contains(findings, "signed update target digest or size mismatch") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update target digest or size mismatch")
	}
}

func TestVerifySignedUpdatePipelineRejectsUnreferencedArtifact(t *testing.T) {
	// 443-446: a second artifact in the map is not referenced by any target,
	// so updateTargetsContain returns false for it. The single target still
	// references the first artifact, so only this finding fires.
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	artifacts["aurora-core-linux-arm64"] = Artifact{
		Name:      "aurora-core-linux-arm64",
		Platform:  platform.KindLinux,
		Version:   "1.0.0",
		SizeBytes: 2048,
		Digest:    make([]byte, 48),
	}
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if ok {
		t.Fatal("verifySignedUpdatePipeline(unreferenced artifact) = true, want false")
	}
	if !strings.Contains(findings, "signed update target missing for aurora-core-linux-arm64") {
		t.Fatalf("findings = %q, want substring %q", findings, "signed update target missing for aurora-core-linux-arm64")
	}
}

func TestVerifySignedUpdatePipelineSucceedsForConsistentPipeline(t *testing.T) {
	// Happy-path lock: the consistent baseline returns true with no findings,
	// so the eight rejection tests above are meaningful contrasts (each
	// perturbs exactly one thing from this baseline).
	const now uint64 = 1_000_000
	pipeline, artifacts := consistentUpdatePipeline(t, now)
	ok, findings := signedUpdateFindings(pipeline, artifacts, now)
	if !ok {
		t.Fatalf("verifySignedUpdatePipeline(consistent) = false, want true (findings: %q)", findings)
	}
	if findings != "" {
		t.Fatalf("verifySignedUpdatePipeline(consistent) findings = %q, want none", findings)
	}
}
