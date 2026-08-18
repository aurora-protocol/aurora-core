package trust

// Adversarial white-box coverage for the one reachable count-0 branch in
// trust/deployment.go's VerifyRelayDeployment: the selected-suite support
// guard at 148-150.
//
//   - 148-150 — `if !containsDeploymentID(descriptor.SupportedSuiteIDs,
//     in.Suite) { return ..., "trust: relay descriptor does not support
//     selected suite" }`. VerifyRelayDeployment is the public entry point for
//     pinning a relay deployment to a caller-selected suite (in.Suite) and
//     method (in.Method). The descriptor's SupportedSuiteIDs is a SIGNED field
//     (covered by the relay's longterm PQ signature at 92-102), so the selected
//     suite is NOT signed — it is the verifier's choice. Reachability hinges on
//     that asymmetry: a caller may select ANY suite for a validly-signed
//     descriptor, and if that suite is not in the descriptor's signed
//     SupportedSuiteIDs, :148 rejects it.
//
// The existing deployment_test.go "suite unsupported" mutation does NOT reach
// :148: it mutates in.Descriptor.SupportedSuiteIDs (a signed field), which
// invalidates the descriptor's PQ signature, so verification fails at :100
// ("relay descriptor PQ signature") before :148 is ever reached. The clean
// way to reach :148 is the opposite — leave the signed descriptor untouched
// and swap the UNSIGNED in.Suite to a production suite the descriptor does not
// list (registry.SuiteHybrid1024AESGCM, while the fixture's descriptor lists
// only registry.SuiteHybrid768P256AESGCM). in.Suite is not part of any signed
// payload, so swapping it does not disturb the descriptor or template
// signatures, and it passes every earlier gate:
//   - :105 validateDeploymentTemplate(template, in.Suite, ...) only uses the
//     suite to pick min request/response size thresholds (2048/8192 for the
//     1024 suites); the fixture template's MaxRequestBodySize=4096 /
//     MaxResponseBodySize=8192 satisfy those, so :105 still passes.
//   - :108/:112/:115/:119/:122/:126/:135/:139 use the template, the descriptor
//     hash, and in.Method — none inspect in.Suite — so they all pass with the
//     fixture's unchanged, validly-signed descriptor and the unchanged H2
//     method.
// Then :148 sees containsDeploymentID([Hybrid768P256AESGCM], Hybrid1024AESGCM)
// == false and fires. That is precisely the "caller selected a suite the
// pinned descriptor does not commit to" state the guard exists to catch, so
// reaching it is not contrived: it is the guard's purpose.
//
// A happy-path lock first confirms the unchanged fixture (in.Suite ==
// Hybrid768P256AESGCM, which the descriptor does list) verifies with a nil
// error, so the :148 rejection is a meaningful contrast, not just a nil-check.
// (The full pass-report assertions are covered by deployment_test.go's
// TestVerifyRelayDeploymentAcceptsSignedPinnedDeployment; here we only lock
// the nil-error contract against the suite-swap rejection.)
//
// Dead-by-design (documented, NOT covered):
//   - 154-156, arm A (in.Method != registry.MethodWebH2Stream): blocked by
//     :115 deploymentRequestClass, which rejects any non-H2 method via the
//     `method != registry.MethodWebH2Stream` clause in its own guard
//     (deploymentRequestClass returns "request class does not match HTTP/2
//     method" before VerifyRelayDeployment reaches :154). So no input with
//     in.Method != H2 survives :115.
//   - 154-156, arm B (in.Method == H2 but SupportedMethodIDs does not contain
//     H2): SupportedMethodIDs is a signed descriptor field; removing H2 from
//     it invalidates the descriptor signature at :100. Reaching arm B requires
//     a custom-signed descriptor whose SupportedMethodIDs deliberately omits
//     H2 while the request class still allows H2 — that needs a parallel
//     signing harness (the fixture's newDeploymentFixture hardcodes
//     SupportedMethodIDs=[H2] and signs it), so it is out of scope for a
//     pure-input-swap test.
//   - 151-153 (in.Suite is supported but not a production suite): to pass :148
//     in.Suite must already be in the descriptor's SupportedSuiteIDs, and to
//     fire :151 that supported suite must be non-production (the only
//     non-production suite is registry.SuiteLabClassical). That needs a
//     custom-signed descriptor that commits to SuiteLabClassical — again a
//     parallel signing harness, out of scope. (The isProductionSuite function
//     itself is already covered by deployment_coverage_test.go:319-324.)
//
// This file adds no helpers: it reuses newDeploymentFixture (already
// referenced by many tests in deployment_test.go) and swaps an unsigned input
// field, so there is no staticcheck U1000 surface. No context.Context (no
// SA1012 surface), no goroutines, no network, no filesystem. The fixture
// performs the signing internally; this test only swaps in.Suite and asserts
// the error, so it touches no cryptography directly.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestVerifyRelayDeploymentRejectsUnsupportedSelectedSuite(t *testing.T) {
	// 148-150: the caller selects a production suite the validly-signed
	// descriptor does not commit to. in.Suite is unsigned, so swapping it
	// does not disturb the descriptor or template signatures and passes every
	// earlier gate; :148 then rejects it.
	fixture := newDeploymentFixture(t)
	in := fixture.input
	in.Suite = registry.SuiteHybrid1024AESGCM // descriptor lists only Hybrid768P256AESGCM
	_, err := VerifyRelayDeployment(in)
	if err == nil {
		t.Fatal("VerifyRelayDeployment(supported-by-descriptor-absent suite) err = nil, want non-nil (:148 should fire)")
	}
	if !strings.Contains(err.Error(), "does not support selected suite") {
		t.Fatalf("VerifyRelayDeployment(swapped suite) err = %v, want substring \"does not support selected suite\"", err)
	}
}

func TestVerifyRelayDeploymentAcceptsSupportedSelectedSuite(t *testing.T) {
	// Happy-path lock so the :148 rejection is a meaningful contrast: the
	// unchanged fixture (in.Suite == Hybrid768P256AESGCM, which the descriptor
	// lists) verifies with a nil error.
	fixture := newDeploymentFixture(t)
	if _, err := VerifyRelayDeployment(fixture.input); err != nil {
		t.Fatalf("VerifyRelayDeployment(unchanged fixture) err = %v, want nil (suite is supported, :148 should pass)", err)
	}
}
