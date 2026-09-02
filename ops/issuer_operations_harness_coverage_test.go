package ops

// Coverage for the issuer operations harness entry points that no existing
// test reaches: RunIssuerOperationsHarness (:98) and the
// issuerOperationsHarnessProfile fixture builder (:134) it drives. The
// harness mints fresh authority/service keys and a signed metadata profile on
// every call, so both the happy path (report passes inside the validity
// window) and the operational failure paths (expired metadata, expired hint
// epoch) are exercised hermetically — no filesystem or network IO.

import (
	"testing"
)

func TestRunIssuerOperationsHarnessPassesInsideValidityWindow(t *testing.T) {
	// Harness metadata and hint epochs are valid over [100, 1000) / [100, 500).
	report, err := RunIssuerOperationsHarness(200)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("issuer operations harness failed inside validity window: %+v", report)
	}
	for name, passed := range map[string]bool{
		"metadata":             report.MetadataVerified,
		"hint_provisioning":    report.HintProvisioning,
		"atomic_replay_store":  report.AtomicReplayStore,
		"verifier_fail_closed": report.VerifierFailClosed,
		"redacted_logs":        report.SensitiveLogsRedacted,
		"public_relay_policy":  report.PublicRelayProofPolicy,
	} {
		if !passed {
			t.Fatalf("%s control was not covered: %+v", name, report)
		}
	}
	if len(report.Findings) != 0 {
		t.Fatalf("harness reported findings inside validity window: %v", report.Findings)
	}
}

func TestRunIssuerOperationsHarnessFailsOutsideValidityWindow(t *testing.T) {
	// now=2000 is past the harness metadata validity (until 1000), so metadata
	// verification must fail closed and the report must not pass.
	report, err := RunIssuerOperationsHarness(2000)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("issuer operations harness passed with expired metadata: %+v", report)
	}
	if report.MetadataVerified {
		t.Fatalf("expired harness metadata verified: %+v", report)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expired harness metadata produced no findings")
	}

	// now=600 is inside the metadata window but past the harness hint epoch
	// (until 500), so hint provisioning must fail while metadata still verifies.
	report, err = RunIssuerOperationsHarness(600)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("issuer operations harness passed with expired hint epoch: %+v", report)
	}
	if !report.MetadataVerified {
		t.Fatalf("harness metadata did not verify at now=600: %+v", report)
	}
	if report.HintProvisioning {
		t.Fatalf("expired harness hint epoch provisioned cleanly: %+v", report)
	}
}
