package main

// Adversarial white-box coverage for the count-0 payload-rejection branches of
// loadClassicalTranscriptSigner (cmd/aurorad/production.go) that sit BEHIND the
// already-covered :479 block==nil / trailing-rest guard. After pem.Decode
// succeeds (a valid single PEM block), the switch on block.Type and the
// EC/PKCS8 parse + ECDSA type-assert have several count-0 error branches the
// existing tests never reach — they only feed one valid ECDSA key via the "EC
// PRIVATE KEY" case (and the :479 non-PEM test feeds a nil block).
//
// Count-0 branches targeted (baseline measured; all four bodies COUNT 0 while
// their conditions/cases were already evaluated):
//   - production.go:487.21,488.52 1 0  — the "PRIVATE KEY" (PKCS8) case
//   - production.go:489.10,490.77 1 0  — :489 default { return "PEM type invalid" }
//   - production.go:492.16,494.3 1 0  — :492 if err != nil { return "parse ..." }
//   - production.go:496.9,498.3 1 0   — :496 if !ok { return "must be ECDSA" }
//
// All reachable with a 0600 temp file owned by the current user (same
// readRestrictedProductionFile path the :479 non-PEM test uses) whose content is
// a single, well-formed PEM block carrying a deliberately broken or non-ECDSA
// payload. No real production key material is involved; the RSA PKCS8 key is
// generated on the fly.
//
// Cross-platform: 0600 is honored on unix and ignored on windows;
// readRestrictedProductionFile skips the o077 + owner checks on windows, so the
// crafted-PEM file is read and rejected identically on every CI platform (no
// build tag, no t.Skip — these tests exercise PEM/key parsing, not permission
// rejection).
//
// No context is involved, so there is no SA1012 surface. The only IO is a
// throwaway t.TempDir() file, removed automatically. In-package (package main)
// because loadClassicalTranscriptSigner is unexported.
//
// This test file adds only TestXxx entry points and references existing in-package
// (loadClassicalTranscriptSigner) symbols and the standard library crypto/rand /
// crypto/rsa / crypto/x509 / encoding/pem / os / path/filepath / strings / testing
// packages, so it adds no U1000 surface.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeClassicalSignerPEM(t *testing.T, block *pem.Block) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "classical-signer.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadClassicalTranscriptSignerRejectsInvalidPKCS8Payload(t *testing.T) {
	// :487 "PRIVATE KEY" case entered + :492 err != nil: a well-formed PEM block
	// of Type "PRIVATE KEY" whose Bytes are not valid PKCS8 ASN.1. pem.Decode
	// returns a non-nil block, so :479 passes; the switch takes the "PRIVATE KEY"
	// case (:487); x509.ParsePKCS8PrivateKey fails; :492 returns.
	path := writeClassicalSignerPEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not valid pkcs8 asn.1")})
	_, err := loadClassicalTranscriptSigner(path)
	if err == nil {
		t.Fatal("loadClassicalTranscriptSigner(invalid PKCS8) err = nil, want non-nil (:492 should reject)")
	}
	if !strings.Contains(err.Error(), "parse classical signer key") {
		t.Fatalf("invalid PKCS8 err = %q, want substring \"parse classical signer key\" (:493)", err.Error())
	}
}

func TestLoadClassicalTranscriptSignerRejectsInvalidPEMType(t *testing.T) {
	// :489 default: a well-formed PEM block whose Type is neither "EC PRIVATE KEY"
	// nor "PRIVATE KEY". pem.Decode succeeds; the switch takes no case and falls
	// to :489 default; :490 returns "PEM type is invalid".
	path := writeClassicalSignerPEM(t, &pem.Block{Type: "BOGUS KEY", Bytes: []byte("anything")})
	_, err := loadClassicalTranscriptSigner(path)
	if err == nil {
		t.Fatal("loadClassicalTranscriptSigner(bogus type) err = nil, want non-nil (:490 should reject)")
	}
	if !strings.Contains(err.Error(), "PEM type is invalid") {
		t.Fatalf("bogus type err = %q, want substring \"PEM type is invalid\" (:490)", err.Error())
	}
}

func TestLoadClassicalTranscriptSignerRejectsRSAPKCS8Key(t *testing.T) {
	// :495 type-assert + :496 !ok: a valid PKCS8 key that is NOT ECDSA (RSA). pem.Decode
	// succeeds; the "PRIVATE KEY" case; ParsePKCS8PrivateKey returns a
	// *rsa.PrivateKey (parse succeeds, err == nil, so :492 is skipped); the :495
	// type assertion to *ecdsa.PrivateKey fails (ok == false); :496 returns "must
	// be ECDSA".
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writeClassicalSignerPEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	_, err = loadClassicalTranscriptSigner(path)
	if err == nil {
		t.Fatal("loadClassicalTranscriptSigner(RSA PKCS8) err = nil, want non-nil (:496 should reject)")
	}
	if !strings.Contains(err.Error(), "must be ECDSA") {
		t.Fatalf("RSA PKCS8 err = %q, want substring \"must be ECDSA\" (:497)", err.Error())
	}
}
