package auroracrypto

// Adversarial white-box coverage for the uncovered branches of crypto/aead.go.
// aead.go wraps crypto/aes + crypto/cipher (AES-256-GCM) and
// golang.org/x/crypto/chacha20poly1305 for the protocol's suites. The uncovered
// branches are the input-validation guards on the AEAD constructors and the
// standalone seal/open helpers, plus the nil-receiver guard on SealTo. Every
// reachable branch below is a deterministic validation outcome: a wrong-length
// key fails the cipher constructor BEFORE any AEAD operation is established,
// and a wrong-length nonce fails our own guard BEFORE a.aead.Seal/Open runs.
// The only cipher construction that succeeds is a deterministic, key-material-
// free setup (a 32-byte zero key for the nonce-length tests), and no Seal/Open
// is ever executed on a valid key on the covered paths — the guard returns
// first. No network, no filesystem, no goroutines.
//
// Targets covered:
//
//   - NewSuiteAEAD:36-38 — the cipher-constructor error propagation. The
//     existing suite always passes a 32-byte key, so a short key makes
//     aes256gcm (AES suites) or chacha20poly1305.New (ChaCha suites) fail and
//     NewSuiteAEAD surfaces the error before the SuiteAEAD is built.
//   - SuiteAEAD.SealTo:48-50 — the `a == nil || a.aead == nil` guard. The
//     existing suite always holds a constructed AEAD, so the nil-receiver
//     return is unreached. A nil *SuiteAEAD hits it before the nonce is
//     inspected. (OpenTo's symmetric guard at 67-70 is already covered by the
//     existing Open-path tests, so only SealTo's nil guard is claimed here.)
//   - SuiteAEAD.SealTo:51-53 — the nonce-length guard, reached after the nil
//     guard passes against a real AEAD. The existing suite always passes a
//     NonceSize-length nonce, so the wrong-length return is unreached. A
//     one-byte nonce against a 12-byte-nonce AES-GCM AEAD fails the guard
//     before a.aead.Seal runs.
//   - SealForSuite:78-80 — the NewSuiteAEAD error propagation. The existing
//     suite only drives SealForSuite with a valid suite+key, so the
//     unsupported-suite propagation is unreached. An unsupported suite
//     (0xBAD) makes NewSuiteAEAD fail (its default case at 34, already covered)
//     and SealForSuite surfaces it.
//   - AES256GCMSeal:94-96 / AES256GCMOpen:105-107 — the aes256gcm error
//     propagation on the standalone helpers. A 31-byte key fails aes256gcm's
//     own length guard (137) and the helpers surface the error before the
//     nonce is inspected.
//   - AES256GCMSeal:97-99 / AES256GCMOpen:108-110 — the nonce-length guard on
//     the standalone helpers, reached after a 32-byte key constructs the
//     AEAD. A one-byte nonce fails the guard before a.Seal/a.Open runs.
//   - ChaCha20Poly1305Seal:116-118 / ChaCha20Poly1305Open:127-129 — the
//     chacha20poly1305.New error propagation on the standalone helpers. A
//     31-byte key fails chacha20poly1305.New (which requires 32 bytes) and the
//     helpers surface the error.
//   - ChaCha20Poly1305Seal:119-121 / ChaCha20Poly1305Open:130-132 — the
//     nonce-length guard on the standalone helpers, reached after a 32-byte
//     key constructs the AEAD. A one-byte nonce fails the guard.
//   - aes256gcm:137-139 — the `len(key) != 32` guard, the inner gate shared by
//     NewSuiteAEAD (AES suites) and the AES256GCM* helpers. A 31-byte key hits
//     it directly (anchoring the shared guard independently of its callers).
//
// Dead-by-design (documented, NOT claimed):
//   - aes256gcm:141-143 — the aes.NewCipher error. The length guard at 137
//     already confirmed len(key) == 32, and aes.NewCipher accepts exactly the
//     16/24/32-byte key lengths (32 among them), so it cannot fail once 137
//     has passed. Validated-input-can't-fail.
//
// No new package-level helpers or types are introduced (only test functions and
// inline byte slices), so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestNewSuiteAEADRejectsShortKey(t *testing.T) {
	// 36-38: a 31-byte key fails the cipher constructor for BOTH suite families
	// and NewSuiteAEAD surfaces the error before the SuiteAEAD is built.
	if _, err := NewSuiteAEAD(registry.SuiteHybrid768AESGCM, make([]byte, 31)); err == nil ||
		!strings.Contains(err.Error(), "AES-256 key length 31, want 32") {
		t.Fatalf("NewSuiteAEAD(AES, 31-byte key) err = %v, want substring \"AES-256 key length 31, want 32\"", err)
	}
	if _, err := NewSuiteAEAD(registry.SuiteHybrid768ChaCha20, make([]byte, 31)); err == nil {
		t.Fatalf("NewSuiteAEAD(ChaCha, 31-byte key) err = nil, want chacha20poly1305 invalid-key error")
	}
}

func TestSuiteAEADSealToRejectsNilAndBadNonce(t *testing.T) {
	// 48-50: a nil *SuiteAEAD hits the nil/aead guard before the nonce is
	// inspected.
	var nilAEAD *SuiteAEAD
	if _, err := nilAEAD.SealTo(nil, make([]byte, 1), nil, nil); err == nil ||
		!strings.Contains(err.Error(), "missing AEAD") {
		t.Fatalf("nilAEAD.SealTo err = %v, want substring \"missing AEAD\"", err)
	}
	// 51-53: a real AEAD but a one-byte nonce fails the nonce-length guard
	// before a.aead.Seal runs. The 32-byte zero key constructs the cipher
	// deterministically; no Seal is executed (the guard returns first).
	aead, err := NewSuiteAEAD(registry.SuiteHybrid768AESGCM, make([]byte, 32))
	if err != nil {
		t.Fatalf("NewSuiteAEAD(valid): %v", err)
	}
	if _, err := aead.SealTo(nil, make([]byte, 1), nil, nil); err == nil ||
		!strings.Contains(err.Error(), "nonce length 1, want 12") {
		t.Fatalf("aead.SealTo(1-byte nonce) err = %v, want substring \"nonce length 1, want 12\"", err)
	}
}

func TestSealForSuitePropagatesUnsupportedSuite(t *testing.T) {
	// 78-80: an unsupported suite makes NewSuiteAEAD fail (its default case at
	// 34, already covered) and SealForSuite surfaces the propagation.
	if _, err := SealForSuite(0xBAD, make([]byte, 32), nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "unsupported AEAD suite 0xbad") {
		t.Fatalf("SealForSuite(0xBAD) err = %v, want substring \"unsupported AEAD suite 0xbad\"", err)
	}
}

func TestAES256GCMHelpersRejectShortKeyAndBadNonce(t *testing.T) {
	shortKey := make([]byte, 31)
	validKey := make([]byte, 32)
	oneByteNonce := make([]byte, 1)

	// 94-96 / 137-139: a 31-byte key fails aes256gcm and AES256GCMSeal surfaces
	// the error before the nonce is inspected.
	if _, err := AES256GCMSeal(shortKey, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "AES-256 key length 31, want 32") {
		t.Fatalf("AES256GCMSeal(31-byte key) err = %v, want substring \"AES-256 key length 31, want 32\"", err)
	}
	// 105-107 / 137-139: the same guard on AES256GCMOpen.
	if _, err := AES256GCMOpen(shortKey, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "AES-256 key length 31, want 32") {
		t.Fatalf("AES256GCMOpen(31-byte key) err = %v, want substring \"AES-256 key length 31, want 32\"", err)
	}
	// 97-99: a 32-byte key constructs the AEAD, then a one-byte nonce fails the
	// nonce-length guard before a.Seal runs.
	if _, err := AES256GCMSeal(validKey, oneByteNonce, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "nonce length 1, want 12") {
		t.Fatalf("AES256GCMSeal(1-byte nonce) err = %v, want substring \"nonce length 1, want 12\"", err)
	}
	// 108-110: the same nonce guard on AES256GCMOpen.
	if _, err := AES256GCMOpen(validKey, oneByteNonce, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "nonce length 1, want 12") {
		t.Fatalf("AES256GCMOpen(1-byte nonce) err = %v, want substring \"nonce length 1, want 12\"", err)
	}
}

func TestChaCha20Poly1305HelpersRejectShortKeyAndBadNonce(t *testing.T) {
	shortKey := make([]byte, 31)
	validKey := make([]byte, 32)
	oneByteNonce := make([]byte, 1)

	// 116-118: a 31-byte key fails chacha20poly1305.New (which requires 32
	// bytes) and ChaCha20Poly1305Seal surfaces the error. The exact Go message
	// is version-dependent, so assert non-nil.
	if _, err := ChaCha20Poly1305Seal(shortKey, nil, nil, nil); err == nil {
		t.Fatal("ChaCha20Poly1305Seal(31-byte key) err = nil, want chacha20poly1305 invalid-key error")
	}
	// 127-129: the same guard on ChaCha20Poly1305Open.
	if _, err := ChaCha20Poly1305Open(shortKey, nil, nil, nil); err == nil {
		t.Fatal("ChaCha20Poly1305Open(31-byte key) err = nil, want chacha20poly1305 invalid-key error")
	}
	// 119-121: a 32-byte key constructs the AEAD, then a one-byte nonce fails
	// the nonce-length guard before a.Seal runs.
	if _, err := ChaCha20Poly1305Seal(validKey, oneByteNonce, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "nonce length 1, want 12") {
		t.Fatalf("ChaCha20Poly1305Seal(1-byte nonce) err = %v, want substring \"nonce length 1, want 12\"", err)
	}
	// 130-132: the same nonce guard on ChaCha20Poly1305Open.
	if _, err := ChaCha20Poly1305Open(validKey, oneByteNonce, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "nonce length 1, want 12") {
		t.Fatalf("ChaCha20Poly1305Open(1-byte nonce) err = %v, want substring \"nonce length 1, want 12\"", err)
	}
}

func TestAES256GCMRejectsShortKey(t *testing.T) {
	// 137-139: the inner length guard shared by NewSuiteAEAD (AES suites) and
	// the AES256GCM* helpers, anchored by a direct call.
	if _, err := aes256gcm(make([]byte, 31)); err == nil ||
		!strings.Contains(err.Error(), "AES-256 key length 31, want 32") {
		t.Fatalf("aes256gcm(31-byte key) err = %v, want substring \"AES-256 key length 31, want 32\"", err)
	}
}
