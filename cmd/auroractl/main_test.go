package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActiveProbesCommandPrintsBaselineReport(t *testing.T) {
	var out bytes.Buffer
	if err := activeProbes(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"active_probe_baseline passed=true cases=14\n",
		"canonical http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case bad-access-hint passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case verifier-unavailable passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
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

func TestCapabilitiesCommandReportsMLDSAVerification(t *testing.T) {
	var out bytes.Buffer
	capabilitiesReport(&out)
	text := out.String()
	if !strings.Contains(text, "ML-DSA verification") {
		t.Fatalf("capabilities output missing ML-DSA verification:\n%s", text)
	}
	if !strings.Contains(text, "first-hop, split-2 route-prelude, and KEY_UPDATE / KEY_UPDATE_ACK real-crypto vectors") {
		t.Fatalf("capabilities output missing real-crypto vector coverage:\n%s", text)
	}
	if !strings.Contains(text, "ML-KEM provider agreement") {
		t.Fatalf("capabilities output missing ML-KEM provider agreement:\n%s", text)
	}
	if strings.Contains(text, "not production-complete:\n- ML-DSA") {
		t.Fatalf("capabilities output still reports ML-DSA work as the first missing item:\n%s", text)
	}
	if !strings.Contains(text, "full real-crypto vector package") {
		t.Fatalf("capabilities output stopped tracking the remaining real-crypto vector package:\n%s", text)
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
		"first_hop_cover_prelude0: ",
		"first_hop_cover_prelude1: ",
		"first_hop_prelude_transcript_hash: ",
		"first_hop_mlkem_shared_secret: ",
		"first_hop_server_prelude_signature_pq: ",
		"split2_route_prelude_envelope: ",
		"split2_route_prelude0_plaintext: ",
		"split2_route_prelude1: ",
		"split2_route_prelude_transcript_hash: ",
		"split2_route_server_prelude_signature_pq: ",
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
		"go run ./cmd/auroractl crypto-check",
		"go run ./cmd/auroractl wire-check",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CI workflow missing %q:\n%s", want, text)
		}
	}
}
