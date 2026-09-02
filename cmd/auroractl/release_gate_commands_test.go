package main

// Tests for the operator-facing release-gate and ops commands that main_test.go
// does not invoke directly:
//
//   - checkConfig: parse a fixture config from a temp dir, plus the
//     missing-file and invalid-config failure paths. checkConfig prints to
//     os.Stdout via fmt.Printf, so the success-path output is captured with an
//     os.Pipe redirect.
//   - capabilities: the command entrypoint itself (the report content is
//     already pinned by TestCapabilitiesCommandReportsMLDSAVerification through
//     capabilitiesReport).
//   - perfCheck: the impairment harness is hermetic (no network, no exec), so
//     the real report is asserted.
//   - releaseGateCheck: the checklist reads the vector snapshots relative to
//     the working directory, so the passing test chdirs to the repository root
//     (the same layout TestCIWorkflowRunsVectorAndWireChecks assumes); a second
//     test runs it from the package directory to exercise the failure
//     aggregation and the untagged branch.
//   - hostBuildCheck: only the argument-validation path is exercised directly;
//     the real execHostBuildRunner path is covered through the p0-p8 gate run
//     below (hostBuildCheckWithRunner is already covered with a fake runner in
//     main_test.go).
//   - p0P8Check / p0P11Check: run for real from the repository root. These are
//     the slowest tests in the package (~10s each with a warm build cache)
//     because the host-build-portable gate cross-compiles the module; they are
//     kept because a silently broken milestone gate is exactly what these tests
//     exist to catch, and CI already pays the same cost running the commands.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfigCommandPrintsParsedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aurora.conf")
	if err := os.WriteFile(path, []byte("[aurora]\nprofile = \"adversarial-dpi\"\nroute = \"split-2\"\nspeed = \"balanced\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	output := captureStdoutForTest(t, func() {
		if err := checkConfig(path); err != nil {
			t.Fatal(err)
		}
	})
	if got, want := output, "ok profile=adversarial-dpi route=split-2 speed=balanced effective=adversarial-dpi\n"; got != want {
		t.Fatalf("check-config output = %q, want %q", got, want)
	}
}

func TestCheckConfigCommandAppliesDefaultsForEmptyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aurora.conf")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	output := captureStdoutForTest(t, func() {
		if err := checkConfig(path); err != nil {
			t.Fatal(err)
		}
	})
	if got, want := output, "ok profile=smart route=auto speed=balanced effective=adversarial-dpi\n"; got != want {
		t.Fatalf("check-config output = %q, want %q", got, want)
	}
}

func TestCheckConfigCommandRejectsMissingFileAndInvalidConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.conf")
	if err := checkConfig(missing); err == nil {
		t.Fatal("check-config accepted a missing file")
	}

	invalid := filepath.Join(t.TempDir(), "aurora.conf")
	if err := os.WriteFile(invalid, []byte("[aurora]\nunsafe = \"true\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkConfig(invalid); err == nil {
		t.Fatal("check-config accepted an invalid config")
	}
}

func TestCapabilitiesCommandPrintsReport(t *testing.T) {
	output := captureStdoutForTest(t, capabilities)
	for _, want := range []string{"implemented:\n", "not production-complete:\n"} {
		if !strings.Contains(output, want) {
			t.Fatalf("capabilities output missing %q:\n%s", want, output)
		}
	}
}

func TestPerfCheckCommandPrintsImpairmentReport(t *testing.T) {
	var out bytes.Buffer
	if err := perfCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"perf_check passed=true scenarios=14 interactive_priority=true udp_stale_policy=true downgrade_no_reconnect_storm=true tuple_cooldown=true padding_reduces_under_congestion=true findings=0\n",
		"perf_scenario loss-0.1pct passed=true",
		"perf_scenario udp-blocked passed=true",
		"perf_scenario peak-hour-congestion passed=true",
		"perf_scenario carrier-path-cache passed=true",
		"perf_scenario packet-protect-throughput passed=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("perf-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "passed=false") {
		t.Fatalf("perf-check output contains failing scenario:\n%s", text)
	}
}

func TestPrototypeInteropTag(t *testing.T) {
	if got := prototypeInteropTag(true); got != "prototype-interop" {
		t.Fatalf("prototypeInteropTag(true) = %q, want prototype-interop", got)
	}
	if got := prototypeInteropTag(false); got != "untagged" {
		t.Fatalf("prototypeInteropTag(false) = %q, want untagged", got)
	}
}

func TestReleaseGateCheckCommandRunsPrototypeInteropChecklist(t *testing.T) {
	chdirToRepoRootForTest(t)

	var out bytes.Buffer
	if err := releaseGateCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"release_gate structural_vectors passed=true\n",
		"release_gate first_hop_split2_admission_replay_keyupdate_vectors passed=true\n",
		"release_gate wrong_token_and_replay_fail_closed passed=true\n",
		"release_gate crypto_fail_closed passed=true\n",
		"release_gate two_independent_builds_and_redacted_diagnostics passed=true\n",
		"release_gate dpi_active_probe_baseline passed=true\n",
		"release_gate_check passed=true items=6 failures=0 tag=prototype-interop\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release-gate-check output missing %q:\n%s", want, text)
		}
	}
}

func TestReleaseGateCheckCommandFailsWithoutVectorSnapshots(t *testing.T) {
	// The test working directory is the package directory, which has no
	// vectors/ snapshots, so both snapshot-backed items must fail and the gate
	// must stay untagged instead of silently passing.
	var out bytes.Buffer
	err := releaseGateCheck(&out)
	if err == nil {
		t.Fatal("release-gate-check passed without vector snapshots")
	}
	text := out.String()
	for _, want := range []string{
		"release_gate structural_vectors passed=false\n",
		"release_gate first_hop_split2_admission_replay_keyupdate_vectors passed=false\n",
		"release_gate_finding structural_vectors: ",
		"release_gate_check passed=false items=6 failures=2 tag=untagged\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release-gate-check failure output missing %q:\n%s", want, text)
		}
	}
}

func TestReleaseGateAndPerfCheckCommandsSurfaceWriterFailure(t *testing.T) {
	// Same failing-writer technique as TestCheckCommandsSurfaceWriterFailure in
	// main_coverage_test.go: the harnesses run and fail/pass as usual; only the
	// report write errors.
	t.Run("releaseGateCheck", func(t *testing.T) {
		if err := releaseGateCheck(failingCoverageWriter{}); err == nil {
			t.Fatal("releaseGateCheck accepted a failing writer")
		}
	})
	t.Run("perfCheck", func(t *testing.T) {
		if err := perfCheck(failingCoverageWriter{}); err == nil {
			t.Fatal("perfCheck accepted a failing writer")
		}
	})
}

func TestHostBuildCheckCommandRejectsUnknownOption(t *testing.T) {
	var out bytes.Buffer
	err := hostBuildCheck([]string{"--bogus"}, &out)
	if err == nil || !strings.Contains(err.Error(), `unknown option "--bogus"`) {
		t.Fatalf("error = %v, want unknown option rejection", err)
	}
	if out.Len() != 0 {
		t.Fatalf("host-build-check wrote output for invalid option: %q", out.String())
	}
}

func TestP0P8CheckCommandRunsFullGateSet(t *testing.T) {
	chdirToRepoRootForTest(t)

	var out bytes.Buffer
	if err := p0P8Check(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"p0_p8_gate host-build-portable passed=true\n",
		"p0_p8_gate vectors-structural passed=true\n",
		"p0_p8_gate crypto passed=true\n",
		"p0_p8_gate client passed=true\n",
		"p0_p8_gate cover passed=true\n",
		"p0_p8_check passed=true gates=24 failures=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("p0-p8-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "passed=false") {
		t.Fatalf("p0-p8-check output contains failing gate:\n%s", text)
	}
}

func TestP0P11CheckCommandExtendsP0P8WithPerfAndReleaseGate(t *testing.T) {
	chdirToRepoRootForTest(t)

	var out bytes.Buffer
	if err := p0P11Check(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"p0_p11_gate host-build-portable passed=true\n",
		"p0_p11_gate perf passed=true\n",
		"p0_p11_gate release-gate passed=true\n",
		"p0_p11_check passed=true gates=26 failures=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("p0-p11-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "passed=false") {
		t.Fatalf("p0-p11-check output contains failing gate:\n%s", text)
	}
}

// captureStdoutForTest redirects os.Stdout for the duration of fn and returns
// what was written. Commands such as checkConfig and capabilities print
// directly to os.Stdout rather than taking an io.Writer.
func captureStdoutForTest(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}

// chdirToRepoRootForTest switches the test's working directory to the
// repository root so commands that resolve the vector snapshots by relative
// path (vectors/...) see the real snapshots, matching how operators and CI run
// the gates.
func chdirToRepoRootForTest(t *testing.T) {
	t.Helper()
	t.Chdir(filepath.Join("..", ".."))
}
