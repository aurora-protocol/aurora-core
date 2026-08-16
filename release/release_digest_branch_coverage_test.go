package release

// Adversarial white-box coverage for the pure digest helpers of
// release/release.go: artifactSignatureInput, provenancePayloadDigest,
// updateRoleSignatureInput, and updateTargetsPayloadDigest. Each helper is a
// deterministic wire encoder (string fields as Opaque16, scalars as
// Uint64/Uint8, counts as varints, and the cryptographically committed digests
// as WritePreHash) folded into a SHA-384 PreHash digest, so a successful call
// always returns 48 bytes and is byte-identical across repeated calls. There is
// no signature verification, no key material, no network, and no filesystem on
// these paths.
//
// The only reachable error branch in each helper is the e.Bytes() propagation
// of a WritePreHash length mismatch: WritePreHash is WriteOpaqueFixed(b, 48),
// so any committed digest field that is not exactly 48 bytes fails the
// fixed-width write and the encoder surfaces it. The existing release harness
// (release_coverage_test.go / RunReleaseReadinessHarness) always feeds these
// helpers canonical 48-byte digests, so the error branches are unreached. The
// success paths (the non-error encoder body + PreHash return) ARE already
// covered by the harness; the success assertions below are byte-identity locks
// that ground the error tests, not new coverage claims.
//
// The varint count writes (provenancePayloadDigest:615,
// updateTargetsPayloadDigest:647) cannot fail: a slice length is bounded by
// available memory far below wire.MaxVarint (1<<62-1), so the oversized-varint
// path is memory-bound and not feasible in a unit test. The Opaque16 string
// fields cannot fail either: they are bounded to 64 KiB (well below the 16 MiB
// oversized threshold) and the test strings are short. So the WritePreHash
// length mismatch is the sole reachable error surface.
//
// Targets covered:
//
//   - provenancePayloadDigest:621-623 — the e.Bytes() error. Reachable two ways:
//     a SubjectDigest that is not 48 bytes (WritePreHash at :613) or a
//     resolved-dependency Digest that is not 48 bytes (WritePreHash at :618).
//     Both are exercised.
//   - artifactSignatureInput:586-588 — the provenancePayloadDigest error
//     propagation. Reachable with a valid 48-byte artifact.Digest but a
//     Provenance whose SubjectDigest is not 48 bytes: provenancePayloadDigest
//     fails first at :585 and artifactSignatureInput surfaces it at :587
//     before its own encoder runs.
//   - artifactSignatureInput:598-600 — the e.Bytes() error from
//     artifactSignatureInput's own encoder. Reachable with a valid Provenance
//     (so :585 succeeds) but an artifact.Digest that is not 48 bytes: the
//     WritePreHash at :595 fails and e.Bytes() surfaces it at :598.
//   - updateRoleSignatureInput:636-638 — the e.Bytes() error. role.PayloadDigest
//     is written as WritePreHash at :634, so a non-48-byte PayloadDigest fails
//     it.
//   - updateTargetsPayloadDigest:654-656 — the e.Bytes() error. Each target's
//     Digest is written as WritePreHash at :650, so a non-48-byte target.Digest
//     fails it.
//
// validProvenance is referenced by three tests (provenance success,
// artifactSignatureInput success, and artifactSignatureInput :598's valid
// Provenance), so there is no staticcheck U1000 surface. No context.Context
// (no SA1012 surface), no goroutines, no cryptography, no real network or
// filesystem.

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/platform"
)

// validProvenance returns a Provenance whose every field encodes cleanly: short
// Opaque16 strings, a 48-byte SubjectDigest, a single dependency with a 48-byte
// Digest, and a small dependency count. provenancePayloadDigest and
// artifactSignatureInput both succeed on it.
func validProvenance() Provenance {
	return Provenance{
		PredicateType:        PredicateSLSAProvenance,
		BuildType:            "reproducible",
		BuilderID:            "builder",
		SourceRepository:     "https://aurora.example/repo",
		SourceCommit:         "0123456789abcdef",
		SubjectName:          "aurora-core-linux-amd64",
		SubjectDigest:        make([]byte, 48),
		SLSALevel:            3,
		ResolvedDependencies: []Dependency{{URI: "https://aurora.example/dep", Digest: make([]byte, 48)}},
	}
}

func TestProvenancePayloadDigestRejectsMalformedDigests(t *testing.T) {
	// Success path (already covered by the harness; asserted as a byte-identity
	// lock to ground the error cases). PreHash is SHA-384, so 48 bytes and
	// deterministic.
	digest, err := provenancePayloadDigest(validProvenance())
	if err != nil {
		t.Fatalf("provenancePayloadDigest(valid) err = %v, want nil", err)
	}
	if len(digest) != 48 {
		t.Fatalf("provenancePayloadDigest(valid) len = %d, want 48 (SHA-384)", len(digest))
	}
	again, err := provenancePayloadDigest(validProvenance())
	if err != nil {
		t.Fatalf("provenancePayloadDigest(valid, second) err = %v, want nil", err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatal("provenancePayloadDigest(valid) is non-deterministic across two calls")
	}

	// 621-623 via a SubjectDigest that is not 48 bytes (WritePreHash at :613).
	_, err = provenancePayloadDigest(Provenance{SubjectDigest: []byte{0x01, 0x02, 0x03}})
	if err == nil {
		t.Fatal("provenancePayloadDigest(short SubjectDigest) err = nil, want encoder error")
	}

	// 621-623 via a resolved-dependency Digest that is not 48 bytes
	// (WritePreHash at :618).
	badDeps := validProvenance()
	badDeps.ResolvedDependencies = []Dependency{{URI: "https://aurora.example/dep", Digest: []byte{0x01, 0x02, 0x03}}}
	if _, err := provenancePayloadDigest(badDeps); err == nil {
		t.Fatal("provenancePayloadDigest(short dependency Digest) err = nil, want encoder error")
	}
}

func TestArtifactSignatureInputRejectsMalformedDigests(t *testing.T) {
	// Success path (byte-identity lock).
	artifact := Artifact{
		Name:       "aurora-core-linux-amd64",
		Platform:   platform.KindLinux,
		Version:    "1.0.0",
		SizeBytes:  1024,
		Digest:     make([]byte, 48),
		Provenance: validProvenance(),
	}
	digest, err := artifactSignatureInput(artifact)
	if err != nil {
		t.Fatalf("artifactSignatureInput(valid) err = %v, want nil", err)
	}
	if len(digest) != 48 {
		t.Fatalf("artifactSignatureInput(valid) len = %d, want 48 (SHA-384)", len(digest))
	}
	again, err := artifactSignatureInput(artifact)
	if err != nil {
		t.Fatalf("artifactSignatureInput(valid, second) err = %v, want nil", err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatal("artifactSignatureInput(valid) is non-deterministic across two calls")
	}

	// 586-588: a valid 48-byte artifact.Digest but a Provenance whose
	// SubjectDigest is not 48 bytes makes provenancePayloadDigest fail at :585,
	// so artifactSignatureInput surfaces the error at :587 before its own
	// encoder runs.
	_, err = artifactSignatureInput(Artifact{
		Digest:     make([]byte, 48),
		Provenance: Provenance{SubjectDigest: []byte{0x01, 0x02, 0x03}},
	})
	if err == nil {
		t.Fatal("artifactSignatureInput(bad Provenance) err = nil, want provenance propagation error")
	}

	// 598-600: a valid Provenance (so :585 succeeds) but an artifact.Digest that
	// is not 48 bytes makes the WritePreHash at :595 fail and e.Bytes() surfaces
	// it at :598.
	badDigest := artifact
	badDigest.Digest = []byte{0x01, 0x02, 0x03}
	if _, err := artifactSignatureInput(badDigest); err == nil {
		t.Fatal("artifactSignatureInput(short artifact Digest) err = nil, want encoder error")
	}
}

func TestUpdateRoleSignatureInputRejectsMalformedDigest(t *testing.T) {
	// Success path (byte-identity lock).
	role := UpdateRole{
		Name:          RoleRoot,
		Version:       1,
		ExpiresUnix:   9_999_999,
		Threshold:     1,
		PayloadDigest: make([]byte, 48),
	}
	digest, err := updateRoleSignatureInput(role)
	if err != nil {
		t.Fatalf("updateRoleSignatureInput(valid) err = %v, want nil", err)
	}
	if len(digest) != 48 {
		t.Fatalf("updateRoleSignatureInput(valid) len = %d, want 48 (SHA-384)", len(digest))
	}
	again, err := updateRoleSignatureInput(role)
	if err != nil {
		t.Fatalf("updateRoleSignatureInput(valid, second) err = %v, want nil", err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatal("updateRoleSignatureInput(valid) is non-deterministic across two calls")
	}

	// 636-638: a PayloadDigest that is not 48 bytes makes the WritePreHash at
	// :634 fail and e.Bytes() surfaces it.
	_, err = updateRoleSignatureInput(UpdateRole{PayloadDigest: []byte{0x01, 0x02, 0x03}})
	if err == nil {
		t.Fatal("updateRoleSignatureInput(short PayloadDigest) err = nil, want encoder error")
	}
}

func TestUpdateTargetsPayloadDigestRejectsMalformedDigest(t *testing.T) {
	// Success path (byte-identity lock).
	targets := []UpdateTarget{{ArtifactName: "aurora-core-linux-amd64", Digest: make([]byte, 48), SizeBytes: 1024}}
	digest, err := updateTargetsPayloadDigest(targets)
	if err != nil {
		t.Fatalf("updateTargetsPayloadDigest(valid) err = %v, want nil", err)
	}
	if len(digest) != 48 {
		t.Fatalf("updateTargetsPayloadDigest(valid) len = %d, want 48 (SHA-384)", len(digest))
	}
	again, err := updateTargetsPayloadDigest(targets)
	if err != nil {
		t.Fatalf("updateTargetsPayloadDigest(valid, second) err = %v, want nil", err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatal("updateTargetsPayloadDigest(valid) is non-deterministic across two calls")
	}

	// 654-656: a target.Digest that is not 48 bytes makes the WritePreHash at
	// :650 fail and e.Bytes() surfaces it.
	_, err = updateTargetsPayloadDigest([]UpdateTarget{{ArtifactName: "aurora-core-linux-amd64", Digest: []byte{0x01, 0x02, 0x03}}})
	if err == nil {
		t.Fatal("updateTargetsPayloadDigest(short target Digest) err = nil, want encoder error")
	}
}
