package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/internal/labfixture"
)

func TestImportCodeValidatesFlags(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"extra"},
		{"--dir", " "},
		{"--wallet", filepath.Join(t.TempDir(), "missing.bin")},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"import-code"}, args...), &stdout, &stderr); code == 0 {
			t.Fatalf("import-code %v succeeded, want failure", args)
		}
	}
}

// TestImportCodeRoundTripsMintedWallet proves the printed provisioning code
// decodes through the production client decoder to exactly the wallet bytes
// with zero spent hint keys.
func TestImportCodeRoundTripsMintedWallet(t *testing.T) {
	dir, _ := mintDeploymentForServeTest(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"import-code", "--dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("import-code code = %d, stderr=%s", code, stderr.String())
	}
	codeText, err := os.ReadFile(filepath.Join(dir, importCodeFileName))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dir, importCodeFileName))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("import-code file permissions = %o, want 600", info.Mode().Perm())
	}
	trimmed := strings.TrimSpace(string(codeText))
	if !strings.Contains(stdout.String(), trimmed) {
		t.Fatal("printed provisioning code does not match the written file")
	}
	envelope, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		t.Fatalf("provisioning code is not canonical base64: %v", err)
	}
	// Canonical base64: re-encoding must be identical.
	if base64.StdEncoding.EncodeToString(envelope) != trimmed {
		t.Fatal("provisioning code is not canonically encoded")
	}
	source, spentHintKeys, err := client.DecodeNativeProvisioningImportEnvelope(envelope)
	if err != nil {
		t.Fatalf("provisioning code rejected by the client decoder: %v", err)
	}
	if len(spentHintKeys) != 0 {
		t.Fatalf("import code carries %d spent hint keys, want 0", len(spentHintKeys))
	}
	wallet, err := os.ReadFile(filepath.Join(dir, labfixture.FileWallet))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, wallet) {
		t.Fatal("import code source does not equal the minted wallet bytes")
	}
	// The wrapped wallet must still parse under the minted trust.
	trustEncoded, err := os.ReadFile(filepath.Join(dir, labfixture.FileNativeProvisioningTrust))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := client.ParseNativeProvisioningTrust(trustEncoded)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := client.ParseNativeProvisioningWalletWithTrust(source, trusted, time.Now().UTC())
	if err != nil {
		t.Fatalf("import code wallet does not parse with the minted trust: %v", err)
	}
	parsed.Zero()

	// The same code path works with an explicit --wallet path.
	altDir := t.TempDir()
	altWallet := filepath.Join(altDir, "w.bin")
	if err := os.WriteFile(altWallet, wallet, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := run([]string{"import-code", "--wallet", altWallet}, &stdout, &stderr); code != 0 {
		t.Fatalf("import-code --wallet code = %d", code)
	}
	if _, err := os.Stat(filepath.Join(altDir, importCodeFileName)); err != nil {
		t.Fatalf("import-code.txt was not written beside --wallet: %v", err)
	}
}

// TestImportCodeLimitsMatchAndroidParser cross-checks the envelope limits the
// production client package exports against the Android parser's constants,
// so the minted import code can never exceed what the app accepts.
func TestImportCodeLimitsMatchAndroidParser(t *testing.T) {
	kotlinPath := filepath.Join("..", "..", "..", "aurora-android", "app", "src", "main", "kotlin", "org", "aurora", "protocol", "android", "core", "NativeProvisioningReservationRequest.kt")
	encoded, err := os.ReadFile(kotlinPath)
	if err != nil {
		t.Skipf("Android parser source not available at %s", kotlinPath)
	}
	source := string(encoded)
	for _, constant := range []string{
		"sourceLengthBytes = Int.SIZE_BYTES", // uint32-BE, 4 bytes
		"countBytes = 1",
		"spentHintKeyBytes = 48",
		"maximumSourceBytes = 16 * 1024 * 1024",
		"maximumSpentHintKeys = 64",
	} {
		if !strings.Contains(source, constant) {
			t.Fatalf("Android parser no longer pins %q; reconcile with client import envelope limits", constant)
		}
	}
	if client.NativeProvisioningImportSpentHintKeyBytes != 48 ||
		client.MaximumNativeProvisioningImportSpentHintKeys != 64 ||
		client.MaximumNativeProvisioningImportEnvelopeBytes != client.MaximumNativeProvisioningWalletBytes+4+1+64*48 {
		t.Fatal("client import envelope limits diverged from the Android parser")
	}
}
