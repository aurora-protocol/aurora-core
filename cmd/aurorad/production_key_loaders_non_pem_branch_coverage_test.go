package main

// Adversarial white-box coverage for the count-0 nil/trailing-block guard bodies
// in the two production key loaders that pem.Decode their restricted file:
// loadProductionBlindRSAKey and loadClassicalTranscriptSigner. Both share the
// same guard shape and the same count-0 nil-safety clause.
//
//   - issuer_production.go:280 loadProductionBlindRSAKey
//     block, rest := pem.Decode(encoded); if block == nil || len(bytes.TrimSpace(rest)) != 0 {
//         return nil, fmt.Errorf("issuer: Blind RSA key must contain one PEM block")
//     }
//   - production.go:479 loadClassicalTranscriptSigner
//     block, rest := pem.Decode(encoded); if block == nil || len(bytes.TrimSpace(rest)) != 0 {
//         return nil, fmt.Errorf("server: classical signer key must contain one PEM block")
//     }
//
// In each, the FIRST clause (block == nil) is the nil-safety clause: pem.Decode
// returns a nil block for input that is not a PEM block, and the subsequent
// defer zeroPrivatePEMBlock(block) + switch block.Type would dereference the nil
// block without the guard. (The trailing-rest clause is a VALIDATION guard,
// off-pillar; these tests target block == nil.)
//
// The existing cmd/aurorad tests drive both loaders only with a valid
// single-PEM-block key file (block != nil, rest empty) — measured:
// issuer_production.go:278.2,280.53 3 4 / production.go:477.2,479.53 3 4 (the
// pem.Decode + condition evaluated 4x each) but :280.53,282.3 1 0 /
// :479.53,481.3 1 0 (the bodies, COUNT 0). So the block == nil clause is plainly
// reachable with a non-PEM file but never exercised.
//
// Proof: a 0600 temp file owned by the current user containing non-PEM bytes
// passes readRestrictedProductionFile (regular file; unix: 0o077 perm bits zero
// + uid == os.Geteuid() via validateProductionFileOwner; windows: those checks
// are skipped/no-op), so each loader reaches its pem.Decode, which returns a nil
// block for the non-PEM content; block == nil short-circuits before the
// zeroPrivatePEMBlock(block) / block.Type nil-deref; the loader returns its "one
// PEM block" error. No real key material is involved.
//
// Cross-platform: the 0600 mode is honored on unix and ignored on windows;
// readRestrictedProductionFile skips the 0o077 + owner checks on windows, so the
// non-PEM file is read and rejected identically on every CI platform (no build
// tag, no t.Skip — these tests exercise PEM parsing, not permission rejection).
//
// No context is involved, so there is no SA1012 surface. The only IO is a
// throwaway t.TempDir() file, removed automatically. In-package (package main)
// because both loaders are unexported.
//
// This test file adds only TestXxx entry points and references existing
// in-package (loadProductionBlindRSAKey, loadClassicalTranscriptSigner) symbols
// and the standard library os / path/filepath / strings / testing packages, so
// it adds no U1000 surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProductionBlindRSAKeyRejectsNonPEMContent(t *testing.T) {
	// 280: a 0600 temp file owned by the current user with non-PEM content passes
	// readRestrictedProductionFile, so loadProductionBlindRSAKey reaches pem.Decode,
	// which returns a nil block; block == nil short-circuits :280 before :283
	// zeroPrivatePEMBlock(block) / :285 block.Type would nil-deref; :281 returns
	// "one PEM block".
	directory := t.TempDir()
	path := filepath.Join(directory, "blind-rsa.key")
	if err := os.WriteFile(path, []byte("not a pem block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProductionBlindRSAKey(path)
	if err == nil {
		t.Fatal("loadProductionBlindRSAKey(non-PEM) err = nil, want non-nil (:281 should reject)")
	}
	if !strings.Contains(err.Error(), "one PEM block") {
		t.Fatalf("non-PEM err = %q, want substring \"one PEM block\" (:281)", err.Error())
	}
}

func TestLoadClassicalTranscriptSignerRejectsNonPEMContent(t *testing.T) {
	// 479: same shape as the Blind RSA loader — a 0600 temp file with non-PEM
	// content passes readRestrictedProductionFile, so loadClassicalTranscriptSigner
	// reaches pem.Decode, which returns a nil block; block == nil short-circuits
	// :479 before :482 zeroPrivatePEMBlock(block) / :484 block.Type would nil-deref;
	// :480 returns "one PEM block".
	directory := t.TempDir()
	path := filepath.Join(directory, "classical-signer.key")
	if err := os.WriteFile(path, []byte("not a pem block\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadClassicalTranscriptSigner(path)
	if err == nil {
		t.Fatal("loadClassicalTranscriptSigner(non-PEM) err = nil, want non-nil (:480 should reject)")
	}
	if !strings.Contains(err.Error(), "one PEM block") {
		t.Fatalf("non-PEM err = %q, want substring \"one PEM block\" (:480)", err.Error())
	}
}
