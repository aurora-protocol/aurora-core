package auroracrypto

// Adversarial white-box coverage for the uncovered branches of crypto/mlkem.go.
// mlkem.go wraps Go's crypto/mlkem (ML-KEM-768 and ML-KEM-1024) for the
// protocol's hybrid suites. The uncovered branches are the nil-receiver and
// destroyed-key guards on the decapsulation-key accessors and the bad-seed
// guard on the 1024 constructor. Every reachable branch below is a
// deterministic nil or validation outcome — no successful ML-KEM key
// encapsulation or decapsulation is performed on the covered paths. The
// destroyed-key branches (111/123) use a bare &MLKEM1024DecapsulationKey{},
// whose zero-value key is nil, so the guards fire without ever constructing a
// real mlkem.DecapsulationKey1024 (which would need a valid 64-byte seed). No
// network, no filesystem, no goroutine beyond the accessor mutexes (which the
// nil guards return before touching and the destroyed guards touch only after
// the key is already nil).
//
// Targets covered:
//
//   - MLKEM768DecapsulationKey.EncapsulationKeyBytes:39-41 — the `k == nil`
//     guard. The existing suite always holds a constructed 768 key, so the
//     nil-receiver return is unreached. A nil *MLKEM768DecapsulationKey returns
//     nil before the mutex is touched.
//   - MLKEM768DecapsulationKey.Decapsulate:51-53 — the `k == nil` guard. The
//     existing suite always holds a constructed key, so the "missing ML-KEM-768
//     decapsulation key" return is unreached. A nil receiver hits it before the
//     mutex is touched.
//   - MLKEM768DecapsulationKey.Destroy:67-69 — the `k == nil` guard. The
//     existing suite always destroys a constructed key, so the nil-receiver
//     no-op is unreached. A nil receiver returns before the mutex is touched.
//   - NewMLKEM1024DecapsulationKey:99-101 — the
//     `mlkem.NewDecapsulationKey1024(seed)` error propagation. The existing
//     suite always passes a valid 64-byte seed, so the wrong-length propagation
//     is unreached. A single byte is not a valid ML-KEM-1024 seed, so the
//     constructor fails before the wrapper struct is built. (The 768 sibling's
//     symmetric guard at 32 is already covered by the existing suite.)
//   - MLKEM1024DecapsulationKey.EncapsulationKeyBytes:106-108 — the `k == nil`
//     guard. The existing suite only exercises the 768 key's nil guard, so the
//     1024 nil-receiver return is unreached. A nil *MLKEM1024DecapsulationKey
//     returns nil before the mutex is touched.
//   - MLKEM1024DecapsulationKey.EncapsulationKeyBytes:111-113 — the
//     `k.key == nil` destroyed-key guard, reached after the receiver guard
//     passes against a non-nil wrapper. A bare &MLKEM1024DecapsulationKey{}
//     has a nil key field, so the guard returns nil without constructing a
//     real decapsulation key.
//   - MLKEM1024DecapsulationKey.Decapsulate:118-120 — the `k == nil` guard.
//     A nil receiver hits the "missing ML-KEM-1024 decapsulation key" return
//     before the mutex is touched.
//   - MLKEM1024DecapsulationKey.Decapsulate:123-125 — the `k.key == nil`
//     destroyed-key guard, reached after the receiver guard passes against a
//     non-nil wrapper. The bare wrapper returns the "decapsulation key
//     destroyed" error without constructing a real key.
//   - MLKEM1024DecapsulationKey.Destroy:134-136 — the `k == nil` guard. A nil
//     receiver returns before the mutex is touched.
//
// Dead-by-design (documented, NOT claimed):
//   - GenerateMLKEM768:24-26 and GenerateMLKEM1024:91-93 — the
//     mlkem.GenerateKey768/GenerateKey1024 errors. Both call crypto/rand
//     internally for seed material, which does not fail in the test
//     environment, so the key-generation error is not inducible from a unit
//     test. System-entropy-gated (the same family as dh.go's
//     GenerateECDHForSuite:31, which is likewise left uncovered).
//
// No new package-level helpers or types are introduced (only test functions and
// inline byte slices), so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"strings"
	"testing"
)

func TestMLKEM768DecapsulationKeyNilReceiversAreSafe(t *testing.T) {
	// 39/51/67: every method guards a nil receiver and returns its zero value
	// (or a no-op for Destroy) before touching the mutex.
	var nilKey *MLKEM768DecapsulationKey
	if got := nilKey.EncapsulationKeyBytes(); got != nil {
		t.Fatalf("nilKey.EncapsulationKeyBytes() = %v, want nil", got)
	}
	if _, err := nilKey.Decapsulate([]byte{0x01}); err == nil ||
		!strings.Contains(err.Error(), "missing ML-KEM-768 decapsulation key") {
		t.Fatalf("nilKey.Decapsulate() err = %v, want substring \"missing ML-KEM-768 decapsulation key\"", err)
	}
	// Destroy on a nil receiver must not panic.
	nilKey.Destroy()
}

func TestNewMLKEM1024DecapsulationKeyRejectsBadSeed(t *testing.T) {
	// 99-101: a single byte is not a valid ML-KEM-1024 seed (the seed is 64
	// bytes), so mlkem.NewDecapsulationKey1024 fails before the wrapper is
	// built. The exact Go error string is version-dependent, so assert
	// non-nil. (The 768 sibling's symmetric guard at 32 is already covered.)
	if _, err := NewMLKEM1024DecapsulationKey([]byte{0x01}); err == nil {
		t.Fatal("NewMLKEM1024DecapsulationKey(short seed) err = nil, want invalid-seed error")
	}
}

func TestMLKEM1024DecapsulationKeyNilReceiversAreSafe(t *testing.T) {
	// 106/118/134: every method guards a nil receiver and returns its zero
	// value (or a no-op for Destroy) before touching the mutex.
	var nilKey *MLKEM1024DecapsulationKey
	if got := nilKey.EncapsulationKeyBytes(); got != nil {
		t.Fatalf("nilKey.EncapsulationKeyBytes() = %v, want nil", got)
	}
	if _, err := nilKey.Decapsulate([]byte{0x01}); err == nil ||
		!strings.Contains(err.Error(), "missing ML-KEM-1024 decapsulation key") {
		t.Fatalf("nilKey.Decapsulate() err = %v, want substring \"missing ML-KEM-1024 decapsulation key\"", err)
	}
	// Destroy on a nil receiver must not panic.
	nilKey.Destroy()
}

func TestMLKEM1024DecapsulationKeyDestroyedGuardsFireWithoutRealKey(t *testing.T) {
	// 111/123: a bare &MLKEM1024DecapsulationKey{} has a nil key field, so the
	// destroyed-key guards fire without ever constructing a real
	// mlkem.DecapsulationKey1024 (which would need a valid 64-byte seed). The
	// receiver guard passes (k is non-nil), then the inner k.key==nil guard
	// returns before any mlkem operation runs.
	destroyed := &MLKEM1024DecapsulationKey{}
	if got := destroyed.EncapsulationKeyBytes(); got != nil {
		t.Fatalf("destroyed.EncapsulationKeyBytes() = %v, want nil (key destroyed)", got)
	}
	if _, err := destroyed.Decapsulate([]byte{0x01}); err == nil ||
		!strings.Contains(err.Error(), "ML-KEM-1024 decapsulation key destroyed") {
		t.Fatalf("destroyed.Decapsulate() err = %v, want substring \"ML-KEM-1024 decapsulation key destroyed\"", err)
	}
}
