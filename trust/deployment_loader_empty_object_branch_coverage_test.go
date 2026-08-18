package trust

// Adversarial white-box coverage for the two reachable count-0 branches in
// trust/deployment_loader.go: the validateCanonicalDeploymentObject error-wrap
// returns inside decodeCanonicalCoverTemplate (70-72) and
// decodeCanonicalPublicKeyRecord (82-84).
//
// VerifyCanonicalRelayDeployment is the PUBLIC entry point that accepts a
// canonical deployment as raw []byte encodings (CanonicalRelayDeploymentInput:
// Descriptor, Template, TemplateAuthorityKey, ...). It decodes them in order
// via three unexported helpers — decodeCanonicalRelayDescriptor,
// decodeCanonicalCoverTemplate, decodeCanonicalPublicKeyRecord — and each
// helper first validates the bytes with validateCanonicalDeploymentObject,
// which rejects only empty or over-length input:
//
//	func validateCanonicalDeploymentObject(encoded []byte) error {
//	    if len(encoded) == 0 || len(encoded) > maximumCanonicalDeploymentObjectBytes {
//	        return fmt.Errorf("object length is invalid")
//	    }
//	    return nil
//	}
//
//   - 70-72 — decodeCanonicalCoverTemplate wraps that error as
//     "trust: canonical cover template: object length is invalid". It fires
//     when input.Template is empty (or over-length), reached only AFTER
//     decodeCanonicalRelayDescriptor(input.Descriptor) succeeds at the first
//     step, so the descriptor must be valid and only the template empty.
//   - 82-84 — decodeCanonicalPublicKeyRecord wraps it as
//     "trust: canonical template authority key: object length is invalid". It
//     fires when input.TemplateAuthorityKey is empty (or over-length), reached
//     only after BOTH the descriptor and the template decode successfully, so
//     both must be valid and only the authority key empty.
//
// The existing deployment_loader_test.go covers the symmetric descriptor case
// ("missing descriptor" -> in.Descriptor = nil fires the :64 wrap) and the
// malformed-decode cases ("truncated template" / "trailing authority key" fire
// the reader.Err / !EOF guards at :75 / :85), but it never passes an empty
// Template or an empty TemplateAuthorityKey while keeping the earlier objects
// valid, so :70 and :82 stayed count-0. This test fills that gap by reusing
// the existing canonicalDeploymentInputForTest builder (which encodes the
// fixture's valid descriptor/template/authority key) and cloneCanonicalDeploymentInput
// (deep copy), then nil-ing exactly one of Template / TemplateAuthorityKey.
//
// A happy-path lock first confirms the unmodified canonical input verifies
// with a nil error, so the two rejections are meaningful contrasts. (The full
// pass-report assertions are covered by
// TestVerifyCanonicalRelayDeploymentAcceptsCompleteTrustedObjects; here we
// only lock the nil-error contract.)
//
// This file adds no helpers: it reuses newDeploymentFixture,
// canonicalDeploymentInputForTest, and cloneCanonicalDeploymentInput (each
// already referenced by deployment_loader_test.go), so there is no staticcheck
// U1000 surface. No context.Context (no SA1012 surface), no goroutines, no
// network, no filesystem, no cryptography touched directly — the fixture
// performs the signing; this test only nils an input slice and asserts the
// wrapped length error.

import (
	"strings"
	"testing"
)

func TestVerifyCanonicalRelayDeploymentRejectsEmptyTemplate(t *testing.T) {
	// 70-72: an empty Template reaches decodeCanonicalCoverTemplate (the
	// descriptor decoded cleanly first), where validateCanonicalDeploymentObject
	// rejects it and the helper wraps the error.
	fixture := newDeploymentFixture(t)
	input := cloneCanonicalDeploymentInput(canonicalDeploymentInputForTest(t, fixture.input))
	input.Template = nil
	_, err := VerifyCanonicalRelayDeployment(input)
	if err == nil {
		t.Fatal("VerifyCanonicalRelayDeployment(empty Template) err = nil, want non-nil (:70 should fire)")
	}
	if !strings.Contains(err.Error(), "canonical cover template:") {
		t.Fatalf("VerifyCanonicalRelayDeployment(empty Template) err = %v, want substring \"canonical cover template:\"", err)
	}
	if !strings.Contains(err.Error(), "object length is invalid") {
		t.Fatalf("VerifyCanonicalRelayDeployment(empty Template) err = %v, want substring \"object length is invalid\"", err)
	}
}

func TestVerifyCanonicalRelayDeploymentRejectsEmptyTemplateAuthorityKey(t *testing.T) {
	// 82-84: an empty TemplateAuthorityKey reaches decodeCanonicalPublicKeyRecord
	// (the descriptor and template decoded cleanly first), where
	// validateCanonicalDeploymentObject rejects it and the helper wraps the error.
	fixture := newDeploymentFixture(t)
	input := cloneCanonicalDeploymentInput(canonicalDeploymentInputForTest(t, fixture.input))
	input.TemplateAuthorityKey = nil
	_, err := VerifyCanonicalRelayDeployment(input)
	if err == nil {
		t.Fatal("VerifyCanonicalRelayDeployment(empty TemplateAuthorityKey) err = nil, want non-nil (:82 should fire)")
	}
	if !strings.Contains(err.Error(), "canonical template authority key:") {
		t.Fatalf("VerifyCanonicalRelayDeployment(empty TemplateAuthorityKey) err = %v, want substring \"canonical template authority key:\"", err)
	}
	if !strings.Contains(err.Error(), "object length is invalid") {
		t.Fatalf("VerifyCanonicalRelayDeployment(empty TemplateAuthorityKey) err = %v, want substring \"object length is invalid\"", err)
	}
}

func TestVerifyCanonicalRelayDeploymentAcceptsCompleteObjects(t *testing.T) {
	// Happy-path lock so the :70/:82 rejections are meaningful contrasts: the
	// unmodified canonical input (valid descriptor + template + authority key)
	// verifies with a nil error.
	fixture := newDeploymentFixture(t)
	input := canonicalDeploymentInputForTest(t, fixture.input)
	if _, err := VerifyCanonicalRelayDeployment(input); err != nil {
		t.Fatalf("VerifyCanonicalRelayDeployment(complete) err = %v, want nil", err)
	}
}
