package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildNativeProvisioningTrustForceDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	specPath := writeNativeProvisioningTrustSpecForTest(t, nativeProvisioningTrustSpecForTest(t))
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "adjacent-secret")
	if err := os.WriteFile(targetPath, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(directory, "AuroraSignedSeedTrust.bin")
	if err := os.Symlink(targetPath, outPath); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := buildNativeProvisioningTrust([]string{"--spec", specPath, "--out", outPath, "--force"}, &out)
	if err != nil && !strings.Contains(err.Error(), "build native provisioning trust") {
		t.Fatalf("error = %v, want a build native provisioning trust error", err)
	}
	target, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(target) != "sentinel" {
		t.Fatalf("build with --force clobbered the symlink target: %q", target)
	}
	if err == nil {
		info, statErr := os.Lstat(outPath)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("build with --force left a non-regular output: %v", info.Mode())
		}
	}
}
