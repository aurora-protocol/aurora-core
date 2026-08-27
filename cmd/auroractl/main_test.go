package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	auroraclient "github.com/aurora-protocol/aurora-core/client"
	auroraperf "github.com/aurora-protocol/aurora-core/perf"
	auroraplatform "github.com/aurora-protocol/aurora-core/platform"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/trust"
)

func TestCheckNativeProvisioningTrustAcceptsCanonicalRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AuroraSignedSeedRoots.bin")
	encoded := nativeProvisioningTrustEncodingForTest(t)
	defer clear(encoded)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := checkNativeProvisioningTrust(path, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "native_provisioning_trust_check passed=true\n"; got != want {
		t.Fatalf("native provisioning trust output = %q, want %q", got, want)
	}
}

func TestCheckNativeProvisioningTrustRejectsMalformedAndNonCanonicalInput(t *testing.T) {
	for _, encoded := range [][]byte{
		nil,
		{0x01, 0x00},
		append(nativeProvisioningTrustEncodingForTest(t), 0x00),
	} {
		path := filepath.Join(t.TempDir(), "AuroraSignedSeedRoots.bin")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := checkNativeProvisioningTrust(path, &out); err == nil {
			t.Fatalf("native provisioning trust checker accepted %x", encoded)
		}
		if out.Len() != 0 {
			t.Fatalf("native provisioning trust checker wrote output for invalid input: %q", out.String())
		}
		clear(encoded)
	}
}

func TestCheckNativeProvisioningTrustRejectsOversizedInputBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AuroraSignedSeedRoots.bin")
	encoded := bytes.Repeat([]byte{0xff}, auroraclient.MaximumNativeProvisioningTrustBytes+1)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := checkNativeProvisioningTrust(path, &out)
	if err == nil || !strings.Contains(err.Error(), "trust input exceeds size limit") {
		t.Fatalf("oversized trust check error = %v, want bounded input rejection", err)
	}
	if out.Len() != 0 {
		t.Fatalf("native provisioning trust checker wrote output for oversized input: %q", out.String())
	}
}

func nativeProvisioningTrustEncodingForTest(t testing.TB) []byte {
	t.Helper()
	curve := elliptic.P256()
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy},
		D:         big.NewInt(1),
	}
	publicKey, err := privateKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	publicRecord := protocol.PublicKeyRecord{
		SignatureScheme: registry.SigECDSAP256SHA384DER,
		KeyEncoding:     registry.KeyP256SEC1Uncompressed,
		PublicKey:       publicKey,
	}
	encodedPublicKey, err := protocol.Encode(publicRecord)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedPublicKey)
	trusted, err := auroraclient.NewNativeProvisioningTrust([]protocol.AuthorityKeyRecord{{
		AuthorityID:    bytes.Repeat([]byte{0x91}, 16),
		AuthorityKeyID: trust.AuthorityKeyID(encodedPublicKey),
		AuthorityRole:  1,
		PublicKey:      publicRecord,
		ValidFromUnix:  1,
		ValidUntilUnix: 4_102_444_800,
		KeyStatus:      registry.AuthorityActive,
		UsageFlags:     registry.UsageMaySignSignedSeedRecord,
	}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := auroraclient.EncodeNativeProvisioningTrust(trusted)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestLoadCheckCommandEmitsPassingJSON(t *testing.T) {
	harness, err := server.NewHarnessHandler(server.HarnessOptions{NowUnix: 1_700_000_000})
	if err != nil {
		t.Fatal(err)
	}
	testServer := httptest.NewServer(harness)
	defer testServer.Close()

	var out bytes.Buffer
	err = loadCheck([]string{
		"--url", testServer.URL + server.DefaultPacketExchangePath,
		"--requests", "1",
		"--concurrency", "1",
		"--packet-bytes", "20",
		"--request-limit", "1s",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}

	var report auroraperf.LoadReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("load-check output is not JSON: %v", err)
	}
	if !report.Passed || report.Requested != 1 || report.Completed != 1 || report.Errors != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestLoadCheckCommandRequiresURL(t *testing.T) {
	var out bytes.Buffer
	err := loadCheck(nil, &out)
	if err == nil || !strings.Contains(err.Error(), "--url is required") {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("load-check wrote output for missing URL: %q", out.String())
	}
}

func TestLoadCheckCommandAppliesDefaultsAndDeadline(t *testing.T) {
	var out bytes.Buffer
	err := loadCheckWithRunner([]string{"--url", "http://example.invalid/load"}, &out, func(ctx context.Context, client *http.Client, endpoint string, options auroraperf.LoadOptions) (auroraperf.LoadReport, error) {
		if client != http.DefaultClient {
			t.Fatalf("client = %p, want http.DefaultClient", client)
		}
		if endpoint != "http://example.invalid/load" {
			t.Fatalf("endpoint = %q", endpoint)
		}
		if options.Requests != 200 || options.Concurrency != 8 || options.PacketBytes != 1200 || options.RequestLimit != 5*time.Second {
			t.Fatalf("options = %+v", options)
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("load-check did not set a parent deadline")
		}
		if duration := time.Until(deadline); duration < 29*time.Second || duration > 30*time.Second {
			t.Fatalf("parent deadline duration = %s", duration)
		}
		return auroraperf.LoadReport{Passed: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var report auroraperf.LoadReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("report = %+v", report)
	}
}

func TestLoadCheckCommandRejectsInvalidFlags(t *testing.T) {
	var out bytes.Buffer
	err := loadCheckWithRunner([]string{"--url", "http://example.invalid", "--requests", "not-a-number"}, &out, nil)
	if err == nil || err.Error() != "load-check: invalid options" {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("load-check wrote output for invalid flags: %q", out.String())
	}
}

func TestLoadCheckCommandRedactsLiveFailure(t *testing.T) {
	const sensitivePath = "/private-carrier-value"
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	var out bytes.Buffer
	err := loadCheck([]string{
		"--url", testServer.URL + sensitivePath,
		"--requests", "1",
		"--concurrency", "1",
		"--packet-bytes", "20",
	}, &out)
	if err == nil || err.Error() != "load-check: carrier load failed" {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), sensitivePath) || strings.Contains(out.String(), sensitivePath) {
		t.Fatalf("load-check exposed endpoint data: error=%q output=%q", err, out.String())
	}
	var report auroraperf.LoadReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Passed || report.Errors != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestCoverageCheckCommandPrintsReportWithoutModifyingProfile(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "coverage.out")
	contents := []byte("mode: atomic\na.go:1.1,2.1 8 1\na.go:3.1,4.1 2 0\n")
	if err := os.WriteFile(profile, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := coverageCheck([]string{"--profile", profile, "--minimum", "70"}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "coverage_check passed=true covered_statements=8 total_statements=10 percent=80.00 minimum_percent=70.00\n"; got != want {
		t.Fatalf("coverage-check output = %q, want %q", got, want)
	}
	after, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, contents) {
		t.Fatalf("coverage-check modified profile: %q", after)
	}
}

func TestCoverageCheckCommandUsesDefaultMinimum(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(profile, []byte("mode: atomic\na.go:1.1,2.1 3 1\na.go:3.1,4.1 1 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := coverageCheck([]string{"--profile", profile}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "coverage_check passed=true covered_statements=3 total_statements=4 percent=75.00 minimum_percent=70.00\n"; got != want {
		t.Fatalf("coverage-check output = %q, want %q", got, want)
	}
}

func TestCoverageCheckCommandRejectsInvalidFlags(t *testing.T) {
	var out bytes.Buffer
	err := coverageCheck([]string{"--profile", "coverage.out", "--minimum", "not-a-number"}, &out)
	if err == nil || err.Error() != "coverage-check: invalid options" {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("coverage-check wrote output for invalid flags: %q", out.String())
	}
}

func TestCoverageCheckCommandRejectsNonRegularProfile(t *testing.T) {
	var out bytes.Buffer
	err := coverageCheck([]string{"--profile", t.TempDir()}, &out)
	if err == nil || err.Error() != "coverage-check: unable to read profile" {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("coverage-check wrote output for non-regular profile: %q", out.String())
	}
}

func TestCoverageCheckCommandDoesNotEmitPartialResult(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(profile, []byte("mode: atomic\na.go:1.1,2.1 1 1\nnot a profile row\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := coverageCheck([]string{"--profile", profile}, &out)
	if err == nil || err.Error() != "coverage-check: coverage gate failed" {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("coverage-check wrote partial report: %q", out.String())
	}
}

func TestCoverageCheckCommandReturnsErrorBelowThreshold(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(profile, []byte("mode: atomic\na.go:1.1,2.1 3 1\na.go:3.1,4.1 1 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := coverageCheck([]string{"--profile", profile, "--minimum", "80"}, &out)
	if err == nil {
		t.Fatal("coverage-check accepted coverage below threshold")
	}
	if got, want := out.String(), "coverage_check passed=false covered_statements=3 total_statements=4 percent=75.00 minimum_percent=80.00\n"; got != want {
		t.Fatalf("coverage-check output = %q, want %q", got, want)
	}
}

func TestActiveProbesCommandPrintsBaselineReport(t *testing.T) {
	var out bytes.Buffer
	if err := activeProbes(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"active_probe_baseline passed=true cases=17\n",
		"gateway_active_probe passed=true cases=17 normal_responses=17 forwarded=0 sidecar_forwarded=0 failure_logs=0\n",
		"canonical http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case bad-access-hint passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case wrong-token passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case malformed-capsule passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case verifier-unavailable passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case rate-limited passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case malformed-key-update passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("active-probes output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "passed=false") {
		t.Fatalf("active-probes output contains failing case:\n%s", text)
	}
}

func TestWireCheckCommandPrintsPublicWireReport(t *testing.T) {
	var out bytes.Buffer
	if err := wireCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"public_wire_check passed=true carriers=5\n",
		"carrier web.h2.stream passed=true\n",
		"carrier web.h1.ws passed=true\n",
		"carrier web.h3.ext-dgram passed=true\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("wire-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("wire-check output contains failing carrier:\n%s", text)
	}
}

func TestTransportCheckCommandPrintsCarrierConformance(t *testing.T) {
	var out bytes.Buffer
	if err := transportCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"transport_check passed=true cases=6 failures=0\n",
		"transport_case h2_baseline_first passed=true",
		"transport_case h1_websocket_fallback passed=true",
		"transport_case shadow_origin_slot passed=true",
		"transport_case h3_ext_datagram_gated passed=true",
		"transport_case masque_visible_opt_in passed=true",
		"transport_case shared_opaque_core_path passed=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("transport-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("transport-check output contains failing case:\n%s", text)
	}
}

func TestFlowCheckCommandPrintsProxyFlowConformance(t *testing.T) {
	var out bytes.Buffer
	if err := flowCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"flow_check passed=true cases=6 failures=0\n",
		"flow_case tcp_open_scheduler_backpressure_close passed=true",
		"flow_case udp_native_and_stream_fallback passed=true",
		"flow_case udp_target_confirm_demux_ttl_idle passed=true",
		"flow_case udp_fqdn_policy_and_fake_ip passed=true",
		"flow_case realtime_stale_drop passed=true",
		"flow_case dns_forwarder_privacy_negative_cache passed=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("flow-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("flow-check output contains failing case:\n%s", text)
	}
}

func TestRouteCheckCommandPrintsSplitRouteConformance(t *testing.T) {
	var out bytes.Buffer
	if err := routeCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"route_check passed=true cases=8 failures=0\n",
		"route_case route_prelude_wrap_replay passed=true",
		"route_case route_hop_binding_separation passed=true",
		"route_case route_capsule_hop_privacy passed=true",
		"route_case split2_forward_opaque_entry passed=true",
		"route_case split2_backward_opaque_entry passed=true",
		"route_case packet_ad_route_hop_binding passed=true",
		"route_case route_rotation_drain_window passed=true",
		"route_case split2_independent_counters passed=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("route-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("route-check output contains failing case:\n%s", text)
	}
}

func TestClassifierCheckCommandPrintsBaselineReport(t *testing.T) {
	var out bytes.Buffer
	if err := classifierCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"classifier_baseline passed=true samples=5 features=21 distinguishers=0 forbidden_markers=0\n",
		"classifier_sample web.h2.stream passed=true distinguishers=0 forbidden_markers=0\n",
		"classifier_sample web.h3.ext-dgram passed=true distinguishers=0 forbidden_markers=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("classifier-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("classifier-check output contains failing sample:\n%s", text)
	}
}

func TestEvaluationCheckCommandPrintsExternalEvidenceReport(t *testing.T) {
	var out bytes.Buffer
	if err := evaluationCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"evaluation_check passed=true classifier=true active_probe=true interoperability=true security_reviews=true release_gates=true deployment_security=true findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("evaluation-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("evaluation-check output contains failing evidence:\n%s", text)
	}
}

func TestDeploymentSecurityCheckCommandPrintsAssessmentReport(t *testing.T) {
	var out bytes.Buffer
	if err := deploymentSecurityCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"deployment_security_check passed=true independent=true real_deployment=true issuer=true relays=true directory=true cover_origins=true client_update=true outage_drills=true redaction=true open_critical=0 open_high=0 findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("deployment-security-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("deployment-security-check output contains failing assessment:\n%s", text)
	}
}

func TestPlatformCheckCommandPrintsAdapterConformance(t *testing.T) {
	var out bytes.Buffer
	if err := platformCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"platform_adapter_check passed=true platforms=7 failures=0\n",
		"platform linux passed=true packet=tun local_proxy=true no_crypto=true boundary=true\n",
		"platform windows passed=true packet=wintun local_proxy=true no_crypto=true boundary=true\n",
		"platform ci passed=true packet=none local_proxy=true no_crypto=true boundary=true\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("platform-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("platform-check output contains failing platform:\n%s", text)
	}
}

func TestHostBuildCheckCommandPrintsPortableMatrixReport(t *testing.T) {
	runner := &recordingCommandHostBuildRunner{}
	var out bytes.Buffer
	if err := hostBuildCheckWithRunner([]string{"--portable"}, &out, runner); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "host_build_check passed=true targets=4 failures=0\n") {
		t.Fatalf("host-build-check output missing summary:\n%s", text)
	}
	if !strings.Contains(text, "host_build_target linux-amd64 passed=true goos=linux goarch=amd64 cgo=0\n") ||
		!strings.Contains(text, "host_build_target android-arm64 passed=true goos=android goarch=arm64 cgo=0\n") {
		t.Fatalf("host-build-check output missing portable targets:\n%s", text)
	}
	wantArgs := []string{"test", "-run", "^$", "-exec=true", "./..."}
	if len(runner.calls) != 4 || !reflect.DeepEqual(runner.calls[0].Args, wantArgs) {
		t.Fatalf("host build runner calls = %+v, want 4 compile-only calls with %v", runner.calls, wantArgs)
	}
}

func TestHostBuildCheckCommandPrintsAppleSimulatorTarget(t *testing.T) {
	runner := &recordingCommandHostBuildRunner{}
	var out bytes.Buffer
	if err := hostBuildCheckWithRunner([]string{"--apple-simulator"}, &out, runner); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "host_build_check passed=true targets=1 failures=0\n") ||
		!strings.Contains(text, "host_build_target ios-simulator-arm64 passed=true goos=ios goarch=arm64 cgo=1\n") {
		t.Fatalf("host-build-check output missing apple simulator target:\n%s", text)
	}
}

func TestHostBuildCheckCommandFailsOnCompileFailure(t *testing.T) {
	runner := &recordingCommandHostBuildRunner{err: errors.New("compile failed")}
	var out bytes.Buffer
	err := hostBuildCheckWithRunner([]string{"--portable"}, &out, runner)
	if err == nil {
		t.Fatalf("host-build-check accepted compile failure")
	}
	if !strings.Contains(out.String(), "host_build_finding linux-amd64: compile failed") {
		t.Fatalf("host-build-check output missing finding:\n%s", out.String())
	}
}

func TestPackagingCheckCommandPrintsEntitlementConformance(t *testing.T) {
	var out bytes.Buffer
	if err := packagingCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"packaging_check passed=true targets=9 release_targets=6 entitlement_free_ci=3 thin_adapters=9 no_crypto=9 mock_packet_flow=3 failures=0\n",
		"packaging_target apple-release passed=true kind=apple release=true ci=false packet=network-extension entitlement_free=false mock_packet_flow=false thin_adapter=true no_crypto=true local_proxy=true\n",
		"packaging_target apple-ci passed=true kind=apple release=false ci=true packet=none entitlement_free=true mock_packet_flow=true thin_adapter=true no_crypto=true local_proxy=true\n",
		"packaging_target portable-ci passed=true kind=ci release=false ci=true packet=none entitlement_free=true mock_packet_flow=true thin_adapter=true no_crypto=true local_proxy=true\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packaging-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("packaging-check output contains failing target:\n%s", text)
	}
}

func TestReleaseCheckCommandPrintsReleaseReadiness(t *testing.T) {
	var out bytes.Buffer
	if err := releaseCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"release_check passed=true artifacts=6 update_roles=4 signatures=true provenance=true reproducible=true signed_update=true provisioning=true incident_response=true findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("release-check output contains failing result:\n%s", text)
	}
}

func TestProofCheckCommandPrintsProductionProofReport(t *testing.T) {
	var out bytes.Buffer
	if err := proofCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"proof_check passed=true blind_rsa=true blind_rsa_tamper_rejected=true blind_rsa_origin_policy_rejected=true voprf_proof_only_rejected=true lab_static_rejected=true\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("proof-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("proof-check output contains failing result:\n%s", text)
	}
}

func TestIssuerCheckCommandPrintsOperationsReport(t *testing.T) {
	var out bytes.Buffer
	if err := issuerCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"issuer_ops_check passed=true metadata=true hint_provisioning=true atomic_replay_store=true verifier_fail_closed=true redacted_logs=true public_relay_policy=true findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("issuer-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("issuer-check output contains failing result:\n%s", text)
	}
}

func TestIssuerDCheckCommandPrintsServiceReadinessReport(t *testing.T) {
	var out bytes.Buffer
	if err := issuerDCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"issuerd_check passed=true metadata_published=true blind_rsa_issue_verify=true voprf_verifier=true voprf_fail_closed=true atomic_spent_store=true redacted_logs=true metadata_hash_bound_token=true findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("issuerd-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("issuerd-check output contains failing result:\n%s", text)
	}
}

func TestIssuerDHTTPCheckCommandPrintsDaemonReadinessReport(t *testing.T) {
	var out bytes.Buffer
	if err := issuerDHTTPCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"issuerd_http_check passed=true health=true metadata=true blind_rsa=true voprf=true voprf_fail_closed=true binary_mtls=true spend=true duplicate_rejected=true redacted_failures=true method_restrictions=true findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("issuerd-http-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("issuerd-http-check output contains failing result:\n%s", text)
	}
}

func TestServerCheckCommandReportsRunnableLinuxServerSurface(t *testing.T) {
	var out bytes.Buffer
	if err := serverCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"server_check passed=true",
		"cover=true",
		"cover_neutral_unknown=true",
		"cover_neutral_issuer_path=true",
		"cover_neutral_health_path=true",
		"issuer_metadata=true",
		"blind_rsa_issue=true",
		"packet_exchange=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("server-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("server-check output contains failing result:\n%s", text)
	}
}

func TestClientCheckCommandReportsLiveServerClientInterop(t *testing.T) {
	var out bytes.Buffer
	if err := clientCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"client_check passed=true",
		"cover_neutral_issuer_path=true",
		"https_cover_neutral_issuer_path=true",
		"cover_neutral_health_path=true",
		"https_cover_neutral_health_path=true",
		"packet_exchange=true",
		"https_packet_exchange=true",
		"issuer_metadata=true",
		"https_issuer_metadata=true",
		"token_issue=true",
		"https_token_issue=true",
		"token_spend=true",
		"https_token_spend=true",
		"duplicate_spend_rejected=true",
		"https_duplicate_spend_rejected=true",
		"cover_neutral_invalid_carrier=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("client-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("client-check output contains failing result:\n%s", text)
	}
}

func TestCoverCheckCommandPrintsDeploymentReport(t *testing.T) {
	var out bytes.Buffer
	if err := coverCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"cover_origin_check passed=true template=true gateway_owned_failure=true sidecar_failure=true pass_through=true oversize_failure=true active_probe=true findings=0\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("cover-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "passed=false") {
		t.Fatalf("cover-check output contains failing result:\n%s", text)
	}
}

func TestCryptoCheckCommandPrintsProviderAgreement(t *testing.T) {
	var out bytes.Buffer
	if err := cryptoCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"crypto_check passed=true backends=2\n",
		"scheme ML-KEM-768 passed=true stdlib=crypto/mlkem cross_check=github.com/cloudflare/circl/kem/mlkem public_key_bytes=1184 ciphertext_bytes=1088 shared_secret_bytes=32\n",
		"scheme ML-KEM-1024 passed=true stdlib=crypto/mlkem cross_check=github.com/cloudflare/circl/kem/mlkem public_key_bytes=1568 ciphertext_bytes=1568 shared_secret_bytes=32\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("crypto-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "passed=false") {
		t.Fatalf("crypto-check output contains failing agreement:\n%s", text)
	}
}

func TestP0P8CheckCommandAggregatesVerificationGates(t *testing.T) {
	var out bytes.Buffer
	checks := []p0P8Gate{
		{
			Name: "wire",
			Run: func(w io.Writer) error {
				fmt.Fprintln(w, "wire_check passed=true")
				return nil
			},
		},
		{
			Name: "client",
			Run: func(w io.Writer) error {
				fmt.Fprintln(w, "client_check passed=true")
				return nil
			},
		},
	}

	if err := runMilestoneGates(&out, "p0_p8", checks); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"p0_p8_gate wire passed=true",
		"wire_check passed=true",
		"p0_p8_gate client passed=true",
		"client_check passed=true",
		"p0_p8_check passed=true gates=2 failures=0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("p0-p8-check output missing %q:\n%s", want, text)
		}
	}
}

func TestP0P8CheckCommandFailsWhenAnyGateFails(t *testing.T) {
	var out bytes.Buffer
	checks := []p0P8Gate{
		{
			Name: "wire",
			Run: func(w io.Writer) error {
				fmt.Fprintln(w, "wire_check passed=false")
				return errors.New("wire failed")
			},
		},
	}

	err := runMilestoneGates(&out, "p0_p8", checks)
	if err == nil {
		t.Fatalf("p0-p8-check accepted failing gate")
	}
	text := out.String()
	if !strings.Contains(text, "p0_p8_gate wire passed=false") ||
		!strings.Contains(text, "p0_p8_finding wire: wire failed") ||
		!strings.Contains(text, "p0_p8_check passed=false gates=1 failures=1") {
		t.Fatalf("p0-p8-check failure output incomplete:\n%s", text)
	}
}

func TestCapabilitiesCommandReportsMLDSAVerification(t *testing.T) {
	var out bytes.Buffer
	capabilitiesReport(&out)
	text := out.String()
	if !strings.Contains(text, "ML-DSA verification") {
		t.Fatalf("capabilities output missing ML-DSA verification:\n%s", text)
	}
	if !strings.Contains(text, "first-hop prelude, first-hop control/application packets, split-2 route-prelude, exit-layer packet, and KEY_UPDATE / KEY_UPDATE_ACK real-crypto vectors") {
		t.Fatalf("capabilities output missing real-crypto vector coverage:\n%s", text)
	}
	if !strings.Contains(text, "signed directory, relay descriptor, and cover-template real-crypto vectors") {
		t.Fatalf("capabilities output missing signed metadata vector coverage:\n%s", text)
	}
	if !strings.Contains(text, "ML-KEM provider agreement") {
		t.Fatalf("capabilities output missing ML-KEM provider agreement:\n%s", text)
	}
	if !strings.Contains(text, "gateway-backed active-probe harness") {
		t.Fatalf("capabilities output missing gateway-backed active-probe harness:\n%s", text)
	}
	if !strings.Contains(text, "HTTP cover-origin gateway handler") {
		t.Fatalf("capabilities output missing HTTP cover-origin gateway handler:\n%s", text)
	}
	if !strings.Contains(text, "HTTP CONNECT/SOCKS5 local interface handlers") {
		t.Fatalf("capabilities output missing concrete local interface handlers:\n%s", text)
	}
	if !strings.Contains(text, "client FLOW_OPEN frame emission") {
		t.Fatalf("capabilities output missing client FLOW_OPEN frame emission:\n%s", text)
	}
	if !strings.Contains(text, "relay frame-block flow demux") {
		t.Fatalf("capabilities output missing relay frame-block flow demux:\n%s", text)
	}
	if !strings.Contains(text, "fake-IP mapped UDP flow integration") {
		t.Fatalf("capabilities output missing fake-IP mapped UDP flow integration:\n%s", text)
	}
	if !strings.Contains(text, "UDP target confirm TTL enforcement") {
		t.Fatalf("capabilities output missing UDP target confirm TTL enforcement:\n%s", text)
	}
	if !strings.Contains(text, "synthetic local DNS forwarder responses") {
		t.Fatalf("capabilities output missing local DNS forwarder response support:\n%s", text)
	}
	if !strings.Contains(text, "negative-cache-aware local DNS responses") {
		t.Fatalf("capabilities output missing negative DNS cache response support:\n%s", text)
	}
	if !strings.Contains(text, "shared opaque carrier session adapters") {
		t.Fatalf("capabilities output missing shared carrier session adapters:\n%s", text)
	}
	if !strings.Contains(text, "P7 transport conformance harness") {
		t.Fatalf("capabilities output missing P7 transport conformance harness:\n%s", text)
	}
	if !strings.Contains(text, "P6 proxy-flow conformance harness") {
		t.Fatalf("capabilities output missing P6 proxy-flow conformance harness:\n%s", text)
	}
	if !strings.Contains(text, "P5 split-route conformance harness") {
		t.Fatalf("capabilities output missing P5 split-route conformance harness:\n%s", text)
	}
	if !strings.Contains(text, "DPI/classifier baseline harness") {
		t.Fatalf("capabilities output missing classifier baseline harness:\n%s", text)
	}
	if !strings.Contains(text, "external evaluation evidence verifier") {
		t.Fatalf("capabilities output missing external evaluation evidence verifier:\n%s", text)
	}
	if !strings.Contains(text, "deployment security assessment evidence verifier") {
		t.Fatalf("capabilities output missing deployment security verifier:\n%s", text)
	}
	if !strings.Contains(text, "platform adapter conformance profiles") {
		t.Fatalf("capabilities output missing platform adapter conformance:\n%s", text)
	}
	if !strings.Contains(text, "packet, DNS, socket, and network-path platform ABI forwarding") {
		t.Fatalf("capabilities output missing full platform ABI forwarding:\n%s", text)
	}
	if !strings.Contains(text, "packet-to-core platform ABI forwarding") {
		t.Fatalf("capabilities output missing packet-to-core platform ABI forwarding:\n%s", text)
	}
	if !strings.Contains(text, "platform packaging and entitlement conformance matrix") {
		t.Fatalf("capabilities output missing platform packaging conformance:\n%s", text)
	}
	if !strings.Contains(text, "Privacy Pass Blind RSA production proof harness") {
		t.Fatalf("capabilities output missing production proof harness:\n%s", text)
	}
	if !strings.Contains(text, "private proof-type validation gates") {
		t.Fatalf("capabilities output missing private proof-type validation gates:\n%s", text)
	}
	if !strings.Contains(text, "append-only file replay cache") {
		t.Fatalf("capabilities output missing persistent replay cache support:\n%s", text)
	}
	if !strings.Contains(text, "protocol decode fuzz harness") {
		t.Fatalf("capabilities output missing decode fuzz harness:\n%s", text)
	}
	if !strings.Contains(text, "opaque8/16/24 boundary test coverage") {
		t.Fatalf("capabilities output missing opaque boundary test coverage:\n%s", text)
	}
	if !strings.Contains(text, "vector element-count boundary coverage") {
		t.Fatalf("capabilities output missing vector element-count coverage:\n%s", text)
	}
	if !strings.Contains(text, "reserved enum rejection coverage") {
		t.Fatalf("capabilities output missing reserved enum rejection coverage:\n%s", text)
	}
	if !strings.Contains(text, "bootstrap critical extension rejection coverage") {
		t.Fatalf("capabilities output missing bootstrap critical extension coverage:\n%s", text)
	}
	if !strings.Contains(text, "all-object canonical round-trip coverage") {
		t.Fatalf("capabilities output missing all-object round-trip coverage:\n%s", text)
	}
	if !strings.Contains(text, "P2 negative vector harness") {
		t.Fatalf("capabilities output missing P2 negative vector coverage:\n%s", text)
	}
	if !strings.Contains(text, "issuer operations conformance harness") {
		t.Fatalf("capabilities output missing issuer operations harness:\n%s", text)
	}
	if !strings.Contains(text, "cover-origin deployment conformance harness") {
		t.Fatalf("capabilities output missing cover-origin deployment harness:\n%s", text)
	}
	if !strings.Contains(text, "issuer service lab readiness harness") {
		t.Fatalf("capabilities output missing issuer service readiness harness:\n%s", text)
	}
	if !strings.Contains(text, "issuer HTTP lab-handler readiness harness") {
		t.Fatalf("capabilities output missing issuer HTTP daemon harness:\n%s", text)
	}
	if !strings.Contains(text, "loopback-only gateway-mTLS Blind RSA backend") || !strings.Contains(text, "public cover-gateway admission/integration") {
		t.Fatalf("capabilities output does not preserve the private/public issuer boundary:\n%s", text)
	}
	if !strings.Contains(text, "live HTTP/HTTPS server-client interop harness") {
		t.Fatalf("capabilities output missing HTTP/HTTPS interop harness:\n%s", text)
	}
	if !strings.Contains(text, "binary issuer verifier mTLS handler") {
		t.Fatalf("capabilities output missing binary issuer verifier mTLS handler:\n%s", text)
	}
	if !strings.Contains(text, "release readiness evidence verifier") {
		t.Fatalf("capabilities output missing release readiness verifier:\n%s", text)
	}
	if strings.Contains(text, "not production-complete:\n- ML-DSA") {
		t.Fatalf("capabilities output still reports ML-DSA work as the first missing item:\n%s", text)
	}
	if strings.Contains(text, "full real-crypto vector package") {
		t.Fatalf("capabilities output still lists the real-crypto vector package as remaining:\n%s", text)
	}
	if strings.Contains(text, "production issuer operations") {
		t.Fatalf("capabilities output still lists local issuer operations as unimplemented:\n%s", text)
	}
	if strings.Contains(text, "production cover-origin deployment") {
		t.Fatalf("capabilities output still lists local cover-origin deployment conformance as unimplemented:\n%s", text)
	}
	if strings.Contains(text, "production platform packaging/device entitlements") {
		t.Fatalf("capabilities output still lists local platform packaging conformance as unimplemented:\n%s", text)
	}
	if !strings.Contains(text, "external live issuer deployment, real signed platform release execution/device provisioning, real deployment security assessment, external DPI/classifier evaluation, external active-probe evaluation") {
		t.Fatalf("capabilities output stopped tracking remaining production work:\n%s", text)
	}
}

func TestNegativeVectorsCheckCommandPrintsRequiredCases(t *testing.T) {
	var out bytes.Buffer
	if err := negativeVectorsCheck(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"negative_vectors_check passed=true cases=6 failures=0\n",
		"negative_vector malformed_public_key rejected=true",
		"negative_vector wrong_key_encoding rejected=true",
		"negative_vector wrong_signature rejected=true",
		"negative_vector wrong_aead_tag rejected=true",
		"negative_vector replay rejected=true",
		"negative_vector wrong_token rejected=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("negative-vectors-check output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "rejected=false") {
		t.Fatalf("negative-vectors-check output contains accepted negative case:\n%s", text)
	}
}

func TestVectorsCommandPrintsNegativeVectors(t *testing.T) {
	var out bytes.Buffer
	if err := vectors([]string{"--negative"}, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"negative_vector malformed_public_key rejected=true",
		"negative_vector wrong_key_encoding rejected=true",
		"negative_vector wrong_signature rejected=true",
		"negative_vector wrong_aead_tag rejected=true",
		"negative_vector replay rejected=true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("negative vector output missing %q:\n%s", want, text)
		}
	}
}

func TestVectorsCommandPrintsFlowManagementVectors(t *testing.T) {
	var out bytes.Buffer
	if err := vectors(nil, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"object_signature: ",
		"object_signature_unsigned: ",
		"object_signature_hash: c1e422a891bccf2deb21a7192d5d185ae5388daaeb4b986eb5eb3b915f3082ef1dd565c2b74a1b5460b589d5030b9c98\n",
		"directory_consensus: ",
		"relay_descriptor: ",
		"cover_template: ",
		"flow_open: 420007020100045db8d82201bb01515151515151515151515151515151510000525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252020300\n",
		"udp_target_confirm: 070100045db8d82201bb5252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252520000003c0100\n",
		"flow_close: 07000100000000000000630004646f6e6500\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("vectors output missing %q:\n%s", want, text)
		}
	}
}

func TestVectorsCommandPrintsFirstHopRealCryptoVectors(t *testing.T) {
	var out bytes.Buffer
	if err := vectors([]string{"--real-crypto"}, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"metadata_directory_consensus: ",
		"metadata_directory_consensus_hash: ",
		"metadata_directory_consensus_signature_pq: ",
		"metadata_relay_descriptor: ",
		"metadata_relay_descriptor_hash: ",
		"metadata_relay_descriptor_signature_pq: ",
		"metadata_cover_template: ",
		"metadata_cover_template_hash: ",
		"metadata_cover_template_family_signature: ",
		"metadata_cover_template_instance_signature: ",
		"first_hop_cover_prelude0: ",
		"first_hop_cover_prelude1: ",
		"first_hop_prelude_transcript_hash: ",
		"first_hop_mlkem_shared_secret: ",
		"first_hop_server_prelude_signature_pq: ",
		"first_hop_handshake_binding_context: ",
		"first_hop_cover_capsule1_plaintext: ",
		"first_hop_cover_capsule1_ciphertext: ",
		"first_hop_client_finished: ",
		"first_hop_cover_capsule2_plaintext: ",
		"first_hop_cover_capsule2_ciphertext: ",
		"first_hop_server_finished: ",
		"first_hop_application_transcript_hash: ",
		"first_hop_client_app_secret0: ",
		"first_hop_client_app_key0: ",
		"first_hop_client_app_iv0: ",
		"first_hop_first_application_packet_frame_block: ",
		"first_hop_first_application_packet: ",
		"first_hop_first_application_packet_auth_tag: ",
		"split2_route_prelude_envelope: ",
		"split2_route_prelude0_plaintext: ",
		"split2_route_prelude1: ",
		"split2_route_prelude_transcript_hash: ",
		"split2_route_server_prelude_signature_pq: ",
		"exit_layer_route_capsule1_plaintext: ",
		"exit_layer_route_client_finished: ",
		"exit_layer_route_capsule2_plaintext: ",
		"exit_layer_route_server_finished: ",
		"exit_layer_application_transcript_hash: ",
		"exit_layer_frame_block: ",
		"exit_layer_aurora_packet: ",
		"exit_layer_packet_auth_tag: ",
		"key_update_frame: ",
		"key_update_ack: ",
		"key_update_next_app_secret: ",
		"key_update_next_key: ",
		"key_update_next_iv: ",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("real crypto vectors output missing %q:\n%s", want, text)
		}
	}
}

func TestVectorsCheckAcceptsGeneratedSnapshot(t *testing.T) {
	var generated bytes.Buffer
	if err := vectors(nil, &generated); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "structural_vectors.txt")
	if err := os.WriteFile(snapshot, generated.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := vectors([]string{"--check", snapshot}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("vectors --check wrote unexpected output: %q", out.String())
	}
}

func TestVectorsCheckAcceptsCRLFSnapshot(t *testing.T) {
	var generated bytes.Buffer
	if err := vectors(nil, &generated); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "structural_vectors.txt")
	windowsCheckout := bytes.ReplaceAll(generated.Bytes(), []byte("\n"), []byte("\r\n"))
	if err := os.WriteFile(snapshot, windowsCheckout, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := vectors([]string{"--check", snapshot}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("vectors --check wrote unexpected output: %q", out.String())
	}
}

func TestVectorsCheckRejectsSnapshotDrift(t *testing.T) {
	snapshot := filepath.Join(t.TempDir(), "structural_vectors.txt")
	if err := os.WriteFile(snapshot, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := vectors([]string{"--check", snapshot}, &out)
	if err == nil {
		t.Fatalf("vectors --check accepted stale snapshot")
	}
	if !strings.Contains(err.Error(), "structural vector snapshot drift") {
		t.Fatalf("vectors --check drift error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("vectors --check wrote output on drift: %q", out.String())
	}
}

func TestRealCryptoVectorsCheckAcceptsGeneratedSnapshot(t *testing.T) {
	var generated bytes.Buffer
	if err := vectors([]string{"--real-crypto"}, &generated); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "real_crypto_vectors.txt")
	if err := os.WriteFile(snapshot, generated.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := vectors([]string{"--real-crypto", "--check", snapshot}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("vectors --real-crypto --check wrote unexpected output: %q", out.String())
	}
}

func TestRealCryptoVectorsCheckRejectsSnapshotDrift(t *testing.T) {
	snapshot := filepath.Join(t.TempDir(), "real_crypto_vectors.txt")
	if err := os.WriteFile(snapshot, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := vectors([]string{"--real-crypto", "--check", snapshot}, &out)
	if err == nil {
		t.Fatalf("vectors --real-crypto --check accepted stale snapshot")
	}
	if !strings.Contains(err.Error(), "real crypto vector snapshot drift") {
		t.Fatalf("vectors --real-crypto --check drift error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("vectors --real-crypto --check wrote output on drift: %q", out.String())
	}
}

func TestCIWorkflowRunsVectorAndWireChecks(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, want := range []string{
		"go test ./...",
		"go run ./cmd/auroractl vectors --check",
		"go run ./cmd/auroractl vectors --real-crypto --check",
		"go run ./cmd/auroractl vectors --negative --check",
		"go run ./cmd/auroractl negative-vectors-check",
		"go run ./cmd/auroractl crypto-check",
		"go run ./cmd/auroractl wire-check",
		"go run ./cmd/auroractl transport-check",
		"go run ./cmd/auroractl flow-check",
		"go run ./cmd/auroractl route-check",
		"go run ./cmd/auroractl host-build-check --portable",
		"go run ./cmd/auroractl host-build-check --apple-simulator",
		"go run ./cmd/auroractl active-probes",
		"go run ./cmd/auroractl classifier-check",
		"go run ./cmd/auroractl evaluation-check",
		"go run ./cmd/auroractl deployment-security-check",
		"go run ./cmd/auroractl platform-check",
		"go run ./cmd/auroractl release-check",
		"go run ./cmd/auroractl proof-check",
		"go run ./cmd/auroractl issuer-check",
		"go run ./cmd/auroractl issuerd-check",
		"go run ./cmd/auroractl issuerd-http-check",
		"go run ./cmd/auroractl server-check",
		"go run ./cmd/auroractl client-check",
		"go run ./cmd/auroractl cover-check",
		"go run ./cmd/auroractl packaging-check",
		"go run ./cmd/auroractl perf-check",
		"go run ./cmd/auroractl release-gate-check",
		"go run ./cmd/auroractl p0-p11-check",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CI workflow missing %q:\n%s", want, text)
		}
	}
}

type recordingCommandHostBuildRunner struct {
	err   error
	calls []commandHostBuildRunnerCall
}

type commandHostBuildRunnerCall struct {
	Target auroraplatform.HostBuildTarget
	Args   []string
}

func (r *recordingCommandHostBuildRunner) RunHostBuild(target auroraplatform.HostBuildTarget, args []string) ([]byte, error) {
	r.calls = append(r.calls, commandHostBuildRunnerCall{
		Target: target,
		Args:   append([]string(nil), args...),
	})
	if r.err != nil {
		return []byte(r.err.Error()), r.err
	}
	return []byte("ok"), nil
}
