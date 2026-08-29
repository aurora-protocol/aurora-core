package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestImportCodeDoesNotFollowPlantedSymlink proves a pre-existing
// import-code.txt symlink beside the wallet is replaced rather than followed:
// the live lab credentials must never be written through it into an
// unrelated file.
func TestImportCodeDoesNotFollowPlantedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on windows")
	}
	dir := t.TempDir()
	walletPath := filepath.Join(dir, "wallet.bin")
	if err := os.WriteFile(walletPath, bytes.Repeat([]byte{0x42}, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	victimDir := t.TempDir()
	victimPath := filepath.Join(victimDir, "victim.txt")
	victimContent := []byte("unrelated file that must survive\n")
	if err := os.WriteFile(victimPath, victimContent, 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, importCodeFileName)
	if err := os.Symlink(victimPath, outputPath); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"import-code", "--wallet", walletPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("import-code code = %d, stderr=%s", code, stderr.String())
	}

	survived, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(survived, victimContent) {
		t.Fatalf("import-code wrote through the planted symlink: victim now holds %q", survived)
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("import-code output mode = %v, want a regular file replacing the symlink", info.Mode())
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("import-code output permissions = %o, want 600", info.Mode().Perm())
	}
}

// TestImportCodeRestrictsPreExistingOutputPermissions proves regenerating the
// code over a previously world-readable import-code.txt leaves the credential
// owner-only instead of inheriting the stale mode.
func TestImportCodeRestrictsPreExistingOutputPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	dir := t.TempDir()
	walletPath := filepath.Join(dir, "wallet.bin")
	if err := os.WriteFile(walletPath, bytes.Repeat([]byte{0x42}, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, importCodeFileName)
	if err := os.WriteFile(outputPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"import-code", "--wallet", walletPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("import-code code = %d, stderr=%s", code, stderr.String())
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("import-code output permissions = %o, want 600", info.Mode().Perm())
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("stale")) {
		t.Fatal("import-code output still carries the stale contents")
	}
}
