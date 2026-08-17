package main

// Adversarial white-box coverage for the count-0 PARSE-ERROR branches of the
// production file loaders in cmd/aurorad that sit BEHIND the readRestricted/
// readProductionFile read step. Each loader reads a restricted (0600) or plain
// (any-perm) config file and then parses/validates its bytes; the parse-error
// returns are count-0 because the existing tests only feed valid material.
//
// The read step (readProductionFile / readRestrictedProductionFile) succeeds for a
// regular t.TempDir() file (restricted=false skips the o077 + owner checks; the
// 0600 mode + current-user ownership passes the restricted path on every
// platform — unix checks o077 bits + uid==Geteuid, windows skips them). So a
// crafted-content file reaches the parser, which then rejects it.
//
// Coverage targets (baseline measured on main; all four bodies COUNT 0):
//   - production.go:466  loadProductionTLSConfig: tls.X509KeyPair err
//   - production.go:509  loadPQTranscriptSigner:  mldsa65 UnmarshalBinary err
//   - issuer_production.go:254 loadProductionIssuerMetadata:    wire decode err
//   - issuer_production.go:267 loadProductionIssuerAuthorityKey: wire decode err
//
// No real production key material is involved: the broken payloads are arbitrary
// bytes. No context is involved, so there is no SA1012 surface. The only IO is
// throwaway t.TempDir() files, removed automatically. In-package (package main)
// because all four loaders are unexported.
//
// This test file adds only TestXxx entry points and references existing in-package
// (loadProductionTLSConfig, loadPQTranscriptSigner, loadProductionIssuerMetadata,
// loadProductionIssuerAuthorityKey) symbols and the standard library os /
// path/filepath / strings / testing packages, so it adds no U1000 surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProductionTLSConfigRejectsInvalidPEMPair(t *testing.T) {
	// :466 tls.X509KeyPair err: a readable cert file (readProductionFile, any
	// perms) and a 0600 private-key file (readRestrictedProductionFile) whose
	// contents are not PEM, so tls.X509KeyPair fails to find any PEM data.
	directory := t.TempDir()
	certPath := filepath.Join(directory, "cert.pem")
	if err := os.WriteFile(certPath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(keyPath, []byte("not a private key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProductionTLSConfig(certPath, keyPath)
	if err == nil {
		t.Fatal("loadProductionTLSConfig(non-PEM pair) err = nil, want non-nil (:466 should reject)")
	}
	if !strings.Contains(err.Error(), "load TLS certificate") {
		t.Fatalf("non-PEM pair err = %q, want substring \"load TLS certificate\" (:467)", err.Error())
	}
}

func TestLoadPQTranscriptSignerRejectsInvalidBinary(t *testing.T) {
	// :509 mldsa65 UnmarshalBinary err: a 0600 file owned by the current user
	// whose bytes are not a valid mldsa65 private key, so UnmarshalBinary fails.
	directory := t.TempDir()
	path := filepath.Join(directory, "pq-signer.key")
	if err := os.WriteFile(path, []byte("not a valid mldsa65 private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadPQTranscriptSigner(path)
	if err == nil {
		t.Fatal("loadPQTranscriptSigner(invalid binary) err = nil, want non-nil (:509 should reject)")
	}
	if !strings.Contains(err.Error(), "parse PQ signer key") {
		t.Fatalf("invalid binary err = %q, want substring \"parse PQ signer key\" (:510)", err.Error())
	}
}

func TestLoadProductionIssuerMetadataRejectsInvalidWireBytes(t *testing.T) {
	// :254 wire decode err (reader.Err() != nil || !reader.EOF()): a readable
	// file (readProductionFile, any perms) whose bytes do not decode to a valid
	// issuer metadata record, so the decoder errors or leaves trailing bytes.
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer-metadata.bin")
	// Trailing/short bytes: a few bytes that the metadata decoder cannot consume
	// as a complete record (it either errors or leaves !EOF).
	if err := os.WriteFile(path, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProductionIssuerMetadata(path)
	if err == nil {
		t.Fatal("loadProductionIssuerMetadata(invalid bytes) err = nil, want non-nil (:254 should reject)")
	}
	if !strings.Contains(err.Error(), "decode issuer metadata failed") {
		t.Fatalf("invalid metadata err = %q, want substring \"decode issuer metadata failed\" (:255)", err.Error())
	}
}

func TestLoadProductionIssuerAuthorityKeyRejectsInvalidWireBytes(t *testing.T) {
	// :267 wire decode err (reader.Err() != nil || !reader.EOF()): a readable
	// file whose bytes do not decode to a valid authority key record.
	directory := t.TempDir()
	path := filepath.Join(directory, "authority-key.bin")
	if err := os.WriteFile(path, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProductionIssuerAuthorityKey(path)
	if err == nil {
		t.Fatal("loadProductionIssuerAuthorityKey(invalid bytes) err = nil, want non-nil (:267 should reject)")
	}
	if !strings.Contains(err.Error(), "decode metadata authority key failed") {
		t.Fatalf("invalid authority key err = %q, want substring \"decode metadata authority key failed\" (:268)", err.Error())
	}
}
