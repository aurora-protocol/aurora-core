package release

// Adversarial white-box coverage for the two reachable count-0 error
// branches in the artifact digest/signature validation surface of
// release/release.go: verifyArtifactSignatures (259-274) and
// signedUpdatePipeline (527-582). Both gates iterate the artifacts of a
// release bundle and encode each artifact's Digest through WritePreHash
// (a fixed 48-byte SHA-384 pre-image write), so a Digest whose length is not
// 48 bytes makes the encoding fail and trips the gate's input-error branch.
//
// verifyArtifactSignatures builds each artifact's signature input via
// artifactSignatureInput (which itself first hashes the artifact's Provenance
// via provenancePayloadDigest, then WritePreHash's artifact.Digest), verifies
// the artifact's signatures at threshold 1 via verifyThreshold, and reports a
// finding on either failure. The harness (release_coverage_test.go) already
// drives it with a fully-valid artifact that carries a valid signature (so the
// :268 verifyThreshold-false branch and the happy path are covered) and with
// an artifact whose Provenance is invalid (so the artifactSignatureInput
// failure via provenancePayloadDigest is covered). The one remaining count-0
// branch is :263, the artifactSignatureInput failure originating from
// artifact.Digest itself (a valid Provenance but a bad Digest), which the
// harness never constructs.
//
// signedUpdatePipeline is the inverse of verifySignedUpdatePipeline: it builds
// a SignedUpdatePipeline from a set of artifacts, signing each of the four roles
// with a fresh ECDSA key. The harness drives it with valid artifacts, so the
// happy path is covered. The remaining count-0 lines are the four `return
// SignedUpdatePipeline{}, err` branches at :537/:551/:555/:559. Only :537 is
// reachable: updateTargetsPayloadDigest (called at :537) WritePreHash's each
// target's Digest, so an artifact with a non-48-byte Digest makes it fail. The
// other three (:551 newSigner, :555 updateRoleSignatureInput, :559 sign) are
// dead-by-design: newSigner draws an ECDSA P-256 key from crypto/rand (key
// generation does not error in practice); updateRoleSignatureInput only
// WritePreHash's the role's PayloadDigest, which signedUpdatePipeline itself
// computes via roleLinkPayloadDigest / updateTargetsPayloadDigest — both
// return a 48-byte PreHash, so the write cannot fail; and signer.sign is
// ecdsa.SignASN1, which does not error. So a call with valid-shaped artifacts
// cannot reach :551/:555/:559.
//
// Targets covered (previously count-0):
//
//   - verifyArtifactSignatures:263-266 — an artifact whose Provenance is valid
//     (48-byte SubjectDigest, so provenancePayloadDigest succeeds) but whose
//     Digest is not 48 bytes, so the WritePreHash(artifact.Digest) inside
//     artifactSignatureInput fails and the "release artifact signature input
//     failed" finding fires.
//   - signedUpdatePipeline:537-539 — an artifact whose Digest is not 48 bytes,
//     so updateTargetsPayloadDigest fails and signedUpdatePipeline returns a
//     zero pipeline and a non-nil error.
//
// TestVerifyArtifactSignaturesSucceedsWithValidSignature and
// TestSignedUpdatePipelineSucceedsForValidArtifacts ground the happy paths so
// the two rejection tests are meaningful contrasts (each perturbs exactly the
// Digest from a valid baseline).
//
// This file adds no new helpers: it reuses validArtifactForCoverage and
// findingsContain from release_coverage_test.go and validSignedRecord from
// verify_threshold_branch_coverage_test.go (each already referenced by
// multiple tests), so there is no staticcheck U1000 surface. No context.Context
// (no SA1012 surface). The cryptography is real ECDSA P-256 via newSigner
// (crypto/rand), bounded and self-contained: no network, no filesystem, no
// goroutines, and no flaky surface.

import (
	"testing"
)

func TestVerifyArtifactSignaturesRejectsBadDigest(t *testing.T) {
	// 263-266: a valid Provenance (48-byte SubjectDigest, so
	// provenancePayloadDigest succeeds inside artifactSignatureInput) but a
	// 3-byte Digest, so the WritePreHash(artifact.Digest) step fails and the
	// "release artifact signature input failed" finding fires.
	artifact := validArtifactForCoverage(make([]byte, 48))
	artifact.Digest = []byte{0x01, 0x02, 0x03}

	report := &ReadinessReport{}
	if verifyArtifactSignatures([]Artifact{artifact}, report) {
		t.Fatal("verifyArtifactSignatures(bad digest) = true, want false")
	}
	if !findingsContain(report.Findings, "release artifact signature input failed") {
		t.Fatalf("findings = %v, want a finding containing \"release artifact signature input failed\"", report.Findings)
	}
}

func TestVerifyArtifactSignaturesSucceedsWithValidSignature(t *testing.T) {
	// Happy-path lock so the :263 rejection is a meaningful contrast: a
	// valid artifact (48-byte Digest, valid Provenance) carrying a signature
	// over its own artifactSignatureInput passes verifyThreshold at threshold 1
	// and produces no finding. validSignedRecord signs an arbitrary input with a
	// fresh ECDSA key whose KeyID binds to its PublicKey, exactly what
	// verifyThreshold requires.
	artifact := validArtifactForCoverage(make([]byte, 48))
	input, err := artifactSignatureInput(artifact)
	if err != nil {
		t.Fatalf("artifactSignatureInput(valid) err = %v, want nil", err)
	}
	artifact.Signatures = []SignatureRecord{validSignedRecord(t, input)}

	report := &ReadinessReport{}
	if !verifyArtifactSignatures([]Artifact{artifact}, report) {
		t.Fatalf("verifyArtifactSignatures(valid signed) = false, want true (findings: %v)", report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("verifyArtifactSignatures(valid signed) findings = %v, want none", report.Findings)
	}
}

func TestSignedUpdatePipelineRejectsBadDigest(t *testing.T) {
	// 537-539: an artifact whose Digest is not 48 bytes, so
	// updateTargetsPayloadDigest WritePreHash's it and fails, and
	// signedUpdatePipeline returns a zero pipeline and a non-nil error. (signedUpdatePipeline
	// uses only the artifact's Name, Digest, and SizeBytes — not its Provenance — so a
	// minimal artifact suffices.)
	artifacts := []Artifact{{
		Name:      "aurora-core-linux-amd64",
		Digest:    []byte{0x01, 0x02, 0x03},
		SizeBytes: 1024,
	}}
	pipeline, err := signedUpdatePipeline(artifacts, 1_000_000)
	if err == nil {
		t.Fatal("signedUpdatePipeline(bad digest) err = nil, want non-nil (updateTargetsPayloadDigest should fail)")
	}
	if len(pipeline.Roles) != 0 || len(pipeline.Targets) != 0 {
		t.Fatalf("signedUpdatePipeline(bad digest) = %+v, want zero pipeline", pipeline)
	}
}

func TestSignedUpdatePipelineSucceedsForValidArtifacts(t *testing.T) {
	// Happy-path lock so the :537 rejection is a meaningful contrast: a single
	// artifact with a valid 48-byte Digest yields a pipeline with the four
	// known roles (root/targets/snapshot/timestamp) each carrying one signature
	// and no error.
	artifacts := []Artifact{{
		Name:      "aurora-core-linux-amd64",
		Digest:    make([]byte, 48),
		SizeBytes: 1024,
	}}
	pipeline, err := signedUpdatePipeline(artifacts, 1_000_000)
	if err != nil {
		t.Fatalf("signedUpdatePipeline(valid) err = %v, want nil", err)
	}
	if len(pipeline.Roles) != 4 {
		t.Fatalf("signedUpdatePipeline(valid) roles = %d, want 4", len(pipeline.Roles))
	}
	wantRoles := map[string]bool{RoleRoot: false, RoleTargets: false, RoleSnapshot: false, RoleTimestamp: false}
	for _, role := range pipeline.Roles {
		if _, ok := wantRoles[role.Name]; !ok {
			t.Fatalf("signedUpdatePipeline(valid) unexpected role %q", role.Name)
		}
		if len(role.Signatures) != 1 {
			t.Fatalf("signedUpdatePipeline(valid) role %q signatures = %d, want 1", role.Name, len(role.Signatures))
		}
		wantRoles[role.Name] = true
	}
	for name, seen := range wantRoles {
		if !seen {
			t.Fatalf("signedUpdatePipeline(valid) missing role %q", name)
		}
	}
	if len(pipeline.Targets) != 1 || pipeline.Targets[0].ArtifactName != "aurora-core-linux-amd64" {
		t.Fatalf("signedUpdatePipeline(valid) targets = %+v, want one target for aurora-core-linux-amd64", pipeline.Targets)
	}
}
