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
	if !strings.Contains(text, "first-hop prelude, first-hop control/application packets, split-2 route-prelude, exit-layer packet, and KEY_UPDATE / KEY_UPDATE_ACK real-crypto vectors") {
		t.Fatalf("capabilities output missing real-crypto vector coverage:\n%s", text)
	}
	if !strings.Contains(text, "signed directory, relay descriptor, and cover-template real-crypto vectors") {
		t.Fatalf("capabilities output missing signed metadata vector coverage:\n%s", text)
	}
	if !strings.Contains(text, "ML-KEM provider agreement") {
		t.Fatalf("capabilities output missing ML-KEM provider agreement:\n%s", text)
	}
	if strings.Contains(text, "not production-complete:\n- ML-DSA") {
		t.Fatalf("capabilities output still reports ML-DSA work as the first missing item:\n%s", text)
	}
	if strings.Contains(text, "full real-crypto vector package") {
		t.Fatalf("capabilities output still lists the real-crypto vector package as remaining:\n%s", text)
	}
	if !strings.Contains(text, "Privacy Pass production proof verification, cover-origin gateway, active-probe harness, platform adapters, DPI evaluation") {
		t.Fatalf("capabilities output stopped tracking remaining production work:\n%s", text)
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
