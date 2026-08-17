package main

// Adversarial white-box coverage for the count-0 payload-rejection branches of
// loadProductionBlindRSAKey (issuer_production.go) that sit BEHIND the already-
// covered :280 block==nil / trailing-rest guard. After pem.Decode succeeds (a
// valid single PEM block), the switch on block.Type and the PKCS1/PKCS8 parse +
// Validate calls have several count-0 error branches that the existing tests
// never reach because they only feed a single valid RSA key.
//
// Count-0 branches targeted (baseline measured on this branch):
//   - issuer_production.go:288.21,290.22 2 0  — the "PRIVATE KEY" (PKCS8) case
//   - issuer_production.go:290.22,292.4 1 0  — :290 if parseErr != nil { return }
//   - issuer_production.go:293.3,295.10 3 0  — the ok/type-assert block after parse
//   - issuer_production.go:295.10,297.4 1 0  — :295 if !ok { return "must be RSA" }
//   - issuer_production.go:298.10,299.70 1 0  — :298 default { return "PEM type invalid" }
//   - issuer_production.go:301.16,303.3 1 0  — :301 if err != nil { return } (PKCS1 err)
//
// The :304 privateKey.Validate() branch is NOT covered: in this Go version
// x509.ParsePKCS1PrivateKey rejects malformed keys itself (composite primes fail
// parse with "crypto/rsa: p is even", surfacing through :301, not :304), so a key
// that passes parse but fails the standalone :304 Validate appears unreachable —
// :304 looks like a dead re-check (same shape as the validateOpen / conformance
// dead-by-design guards). Deliberately left uncovered (not a pillar).
//
// All are reachable with a 0600 temp file owned by the current user (same
// readRestrictedProductionFile path the :280 non-PEM test uses) whose content is
// a single, well-formed PEM block carrying a deliberately broken payload. No real
// production key material is involved; ECDSA/PKCS8 keys and inconsistent RSA keys
// are generated on the fly.
//
// Cross-platform: 0600 is honored on unix and ignored on windows;
// readRestrictedProductionFile skips the o077 + owner checks on windows, so the
// crafted-PEM file is read and rejected identically on every CI platform (no build
// tag, no t.Skip — these tests exercise PEM/key parsing, not permission rejection).
//
// No context is involved, so there is no SA1012 surface. The only IO is a throwaway
// t.TempDir() file, removed automatically. In-package (package main) because
// loadProductionBlindRSAKey is unexported.
//
// This test file adds only TestXxx entry points and references existing in-package
// (loadProductionBlindRSAKey) symbols and the standard library crypto/ecdsa /
// crypto/elliptic / crypto/rand / crypto/x509 / encoding/pem / os / path/filepath /
// strings / testing packages, so it adds no U1000 surface.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePEMBlock writes a single PEM block (Type/Bytes) to a 0600 temp file and
// returns its path, passing readRestrictedProductionFile on every platform.
func writePEMBlock(t *testing.T, block *pem.Block) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "blind-rsa.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProductionBlindRSAKeyRejectsInvalidPKCS8Payload(t *testing.T) {
	// :288 "PRIVATE KEY" case entered + :290 parseErr != nil: a well-formed PEM
	// block of Type "PRIVATE KEY" whose Bytes are not valid PKCS8 ASN.1. pem.Decode
	// returns a non-nil block, so :280 passes; the switch takes the "PRIVATE KEY"
	// case (:288); x509.ParsePKCS8PrivateKey fails; :290 returns.
	path := writePEMBlock(t, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not valid pkcs8 asn.1")})
	_, err := loadProductionBlindRSAKey(path)
	if err == nil {
		t.Fatal("loadProductionBlindRSAKey(invalid PKCS8) err = nil, want non-nil (:290 should reject)")
	}
	if !strings.Contains(err.Error(), "parse Blind RSA key") {
		t.Fatalf("invalid PKCS8 err = %q, want substring \"parse Blind RSA key\" (:291)", err.Error())
	}
}

func TestLoadProductionBlindRSAKeyRejectsNonRSAPKCS8Key(t *testing.T) {
	// :293 ok/type-assert + :295 !ok: a valid PKCS8 key that is NOT RSA (ECDSA
	// P-256). pem.Decode succeeds; the "PRIVATE KEY" case; ParsePKCS8PrivateKey
	// returns a *ecdsa.PrivateKey; the :294 type assertion to *rsa.PrivateKey fails
	// (ok == false); :295 returns "must be RSA".
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEMBlock(t, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	_, err = loadProductionBlindRSAKey(path)
	if err == nil {
		t.Fatal("loadProductionBlindRSAKey(ECDSA PKCS8) err = nil, want non-nil (:295 should reject)")
	}
	if !strings.Contains(err.Error(), "must be RSA") {
		t.Fatalf("ECDSA PKCS8 err = %q, want substring \"must be RSA\" (:296)", err.Error())
	}
}

func TestLoadProductionBlindRSAKeyRejectsInvalidPEMType(t *testing.T) {
	// :298 default: a well-formed PEM block whose Type is neither "RSA PRIVATE
	// KEY" nor "PRIVATE KEY". pem.Decode succeeds; the switch takes no case and
	// falls to :298 default; :299 returns "PEM type is invalid".
	path := writePEMBlock(t, &pem.Block{Type: "BOGUS KEY", Bytes: []byte("anything")})
	_, err := loadProductionBlindRSAKey(path)
	if err == nil {
		t.Fatal("loadProductionBlindRSAKey(bogus type) err = nil, want non-nil (:299 should reject)")
	}
	if !strings.Contains(err.Error(), "PEM type is invalid") {
		t.Fatalf("bogus type err = %q, want substring \"PEM type is invalid\" (:299)", err.Error())
	}
}

func TestLoadProductionBlindRSAKeyRejectsInvalidPKCS1Payload(t *testing.T) {
	// :301 err != nil (PKCS1 path): a well-formed PEM block of Type "RSA PRIVATE
	// KEY" whose Bytes are not valid PKCS1 ASN.1. pem.Decode succeeds; the "RSA
	// PRIVATE KEY" case; x509.ParsePKCS1PrivateKey fails and sets err; the switch
	// ends; :301 returns.
	path := writePEMBlock(t, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not valid pkcs1 asn.1")})
	_, err := loadProductionBlindRSAKey(path)
	if err == nil {
		t.Fatal("loadProductionBlindRSAKey(invalid PKCS1) err = nil, want non-nil (:301 should reject)")
	}
	if !strings.Contains(err.Error(), "parse Blind RSA key") {
		t.Fatalf("invalid PKCS1 err = %q, want substring \"parse Blind RSA key\" (:302)", err.Error())
	}
}

// NOTE: the :304 privateKey.Validate() branch is NOT covered here. In this Go
// version x509.ParsePKCS1PrivateKey itself rejects malformed keys (e.g. composite
// primes fail parse with "crypto/rsa: p is even", surfacing through :301 not :304),
// so a key that passes parse but fails the standalone :304 Validate appears
// unreachable — :304 looks like a dead re-check (same shape as the validateOpen /
// conformance dead-by-design guards). It is deliberately left uncovered (not a
// pillar).
