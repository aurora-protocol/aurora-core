package auroracrypto

// Adversarial white-box coverage for the uncovered branches of crypto/dh.go.
// dh.go wraps Go's crypto/ecdh for the protocol's hybrid suites. The uncovered
// branches are the nil-receiver guards on the ECDHPrivateKey accessors, the
// suite/key validation guards on the constructors, and the ECDH-degenerate-peer
// error. Every reachable branch below is a deterministic nil or validation
// outcome — no successful key material is established on the covered paths
// except the single ECDH-degenerate test, which mints a real X25519 key (rand
// succeeds deterministically in tests) and then provokes a deterministic
// all-zero shared secret that Go's ecdh.X25519 rejects. No network, no
// filesystem, no goroutine beyond the accessor mutexes (which the nil guards
// return before touching).
//
// Targets covered:
//
//   - ECDHPrivateKey.Suite:63-64, CurveName:72-73, PrivateKeyBytes:81-82,
//     PublicKeyBytes:93-94, SharedSecret:105-106, Destroy:125-126 — the
//     `if k == nil` guards on every method. The existing suite always holds a
//     constructed key, so the nil-receiver returns are unreached. A nil
//     *ECDHPrivateKey hits each guard before the mutex is touched; SharedSecret
//     returns the "missing ECDH private key" sentinel and Destroy is a no-op.
//   - NewECDHPrivateKeyForSuite:39-41 — the ecdhCurveForSuite error propagation.
//     The existing suite only passes protocol suites, so the unsupported-suite
//     propagation is unreached. A suite outside the hybrid family (0xBAD)
//     fails the curve switch before any key bytes are inspected.
//   - NewECDHPrivateKeyForSuite:43-45 — the curve.NewPrivateKey error. The
//     existing suite always passes a 32-byte X25519 / P-256 / P-384 private key,
//     so the wrong-length propagation is unreached. A single byte is not a
//     valid X25519 private key, so curve.NewPrivateKey fails before the
//     ECDHPrivateKey is built.
//   - ECDHPrivateKey.SharedSecret:118-120 — the ecdh.ECDH error after a
//     syntactically valid peer public key. The existing suite always pairs
//     valid keys, so the ECDH failure is unreached. An all-zero 32-byte X25519
//     public key is accepted by NewPublicKey (X25519 does not validate points)
//     but yields an all-zero shared secret, which Go's x25519 ECDH rejects.
//
// Dead-by-design (documented, NOT claimed):
//   - GenerateECDHForSuite:31-33 — the curve.GenerateKey(rand.Reader) error.
//     crypto/rand.Reader does not fail in the test environment, so the key
//     generation error is not inducible from a unit test. System-entropy-gated.
//
// No new package-level helpers or types are introduced (only test functions and
// inline byte slices), so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestECDHPrivateKeyNilReceiversAreSafe(t *testing.T) {
	// 63/72/81/93/105/125: every method guards a nil receiver and returns its
	// zero value (or a no-op for Destroy) before touching the mutex.
	var nilKey *ECDHPrivateKey
	if got := nilKey.Suite(); got != 0 {
		t.Fatalf("nilKey.Suite() = %d, want 0", got)
	}
	if got := nilKey.CurveName(); got != "" {
		t.Fatalf("nilKey.CurveName() = %q, want empty", got)
	}
	if got := nilKey.PrivateKeyBytes(); got != nil {
		t.Fatalf("nilKey.PrivateKeyBytes() = %v, want nil", got)
	}
	if got := nilKey.PublicKeyBytes(); got != nil {
		t.Fatalf("nilKey.PublicKeyBytes() = %v, want nil", got)
	}
	if _, err := nilKey.SharedSecret(nil); err == nil {
		t.Fatal("nilKey.SharedSecret() err = nil, want the missing-key error")
	}
	// Destroy on a nil receiver must not panic.
	nilKey.Destroy()
}

func TestNewECDHPrivateKeyForSuiteRejectsUnsupportedSuite(t *testing.T) {
	// 39-41: a suite outside the hybrid family fails ecdhCurveForSuite before
	// any key bytes are inspected, so the private-key argument is irrelevant.
	if _, err := NewECDHPrivateKeyForSuite(0xBAD, []byte("ignored")); err == nil {
		t.Fatal("NewECDHPrivateKeyForSuite(0xBAD) err = nil, want unsupported-suite error")
	}
	// The unsupported-suite error is also surfaced by the accessors that take
	// only a suite, anchoring that the curve switch is the single gate.
	if _, err := ECDHCurveNameForSuite(0xBAD); err == nil {
		t.Fatal("ECDHCurveNameForSuite(0xBAD) err = nil, want unsupported-suite error")
	}
}

func TestNewECDHPrivateKeyForSuiteRejectsInvalidPrivateKey(t *testing.T) {
	// 43-45: a valid hybrid suite but a single-byte private key is not a valid
	// X25519 scalar, so curve.NewPrivateKey fails before the ECDHPrivateKey is
	// constructed.
	if _, err := NewECDHPrivateKeyForSuite(registry.SuiteHybrid768AESGCM, []byte{0x01}); err == nil {
		t.Fatal("NewECDHPrivateKeyForSuite(short key) err = nil, want invalid private key error")
	}
}

func TestECDHSharedSecretRejectsDegeneratePeer(t *testing.T) {
	// 118-120: a real X25519 private key paired with an all-zero 32-byte peer
	// public key. NewPublicKey accepts it (X25519 does not validate points), so
	// execution reaches ECDH; the all-zero shared secret is then rejected by
	// Go's x25519 implementation. The failure is independent of the random
	// private key, so the test is deterministic.
	key, err := GenerateECDHForSuite(registry.SuiteHybrid768AESGCM)
	if err != nil {
		t.Fatalf("GenerateECDHForSuite: %v", err)
	}
	if _, err := key.SharedSecret(make([]byte, 32)); err == nil {
		t.Fatal("SharedSecret(all-zero peer) err = nil, want ECDH degenerate-peer error")
	}
}
