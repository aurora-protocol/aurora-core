package relay

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/trust"
)

func TestVerifyCoverOriginDeploymentAcceptsHardenedGatewayProfile(t *testing.T) {
	report, err := RunCoverOriginDeploymentHarness(150)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("cover-origin deployment harness failed: %+v", report)
	}
	for name, passed := range map[string]bool{
		"template":              report.TemplateValidated,
		"gateway_owned_failure": report.GatewayOwnedFailureNeutral,
		"sidecar_failure":       report.SidecarFailureSanitized,
		"pass_through":          report.PassThroughForwarded,
		"oversize_failure":      report.OversizeFailureNeutral,
		"active_probe":          report.ActiveProbeNeutral,
	} {
		if !passed {
			t.Fatalf("%s control was not covered: %+v", name, report)
		}
	}
}

func TestVerifyCoverOriginDeploymentRejectsForwardableFailedCapsules(t *testing.T) {
	profile := coverOriginDeploymentHarnessProfile(t, 150)
	profile.Template.CapsuleEnvelope.ConsumeFailedBodyLocally = false
	refreshRelayCoverCommitment(t, &profile.Template)

	report, err := VerifyCoverOriginDeployment(profile)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("forwardable failed capsule deployment passed: %+v", report)
	}
	if !coverDeploymentReportHasFinding(report, "cover template validation failed") {
		t.Fatalf("report missing cover template validation finding: %+v", report)
	}
}

func TestVerifyCoverOriginDeploymentRejectsMissingGatewayOwnedRoute(t *testing.T) {
	profile := coverOriginDeploymentHarnessProfile(t, 150)
	profile.Routes = profile.Routes[1:]

	report, err := VerifyCoverOriginDeployment(profile)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("deployment without gateway-owned route passed: %+v", report)
	}
	if !coverDeploymentReportHasFinding(report, "no gateway-owned capsule route configured") {
		t.Fatalf("report missing gateway-owned route finding: %+v", report)
	}
}

func coverOriginDeploymentHarnessProfile(t *testing.T, now uint64) CoverOriginDeploymentProfile {
	t.Helper()
	profile, err := DefaultCoverOriginDeploymentProfile(now)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func refreshRelayCoverCommitment(t *testing.T, tpl *protocol.CoverTemplate) {
	t.Helper()
	commitment, err := trust.CoverOriginCommitment(*tpl)
	if err != nil {
		t.Fatal(err)
	}
	tpl.CoverOriginCommitment = commitment
}

func coverDeploymentReportHasFinding(report CoverOriginDeploymentReport, want string) bool {
	for _, finding := range report.Findings {
		if finding == want {
			return true
		}
	}
	return false
}
