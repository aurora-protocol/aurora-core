package auroracrypto

// Adversarial white-box coverage for the uncovered branches of
// crypto/control.go. control.go imports only encoding/binary, fmt, and the
// registry/wire packages; the cryptography it performs is deterministic hashing
// (SuiteHash/AppendSuiteHash — no key material, no AEAD, no network, no
// filesystem, no goroutines). The existing crypto_test.go and append_test.go
// cover the happy paths and the direction/msg-type validation, so the branches
// below are the error-propagation and whole-function gaps those suites leave.
//
// Targets covered:
//
//   - ControlAAD:63-65 — the `err != nil` propagation of a
//     ControlAADPreimage validation failure. The existing
//     TestControlAADRejectsReservedOrMismatchedDirection drives the validation
//     errors through ControlAADPreimage directly (line 101), never through
//     ControlAAD, so ControlAAD's own propagation return is unreached. A
//     reserved control direction (2) fails validateControlAADInput at its
//     first guard, and ControlAAD surfaces it.
//   - FirstHopRouteInstanceID:70-79 + :83 — the entire function is 0%-covered
//     because it is only reached from handshake/client.go and handshake/relay.go
//     (integration paths not exercised by the unit suite). A valid suite hashes
//     the parts and returns the masked (low 62 bits) route id (the happy return
//     at 83); an unsupported suite makes SuiteHash fail and the function
//     propagates it (77-79). Both are reachable with plain byte slices and a
//     direct call.
//   - AppendPacketAD:100-102 — the `wire.AppendVarint` error for an
//     out-of-range route instance id. The existing append suite uses in-range
//     ids, so the varint range guard is unreached. A route instance id above
//     wire.MaxVarint (1<<62 - 1) — math.MaxUint64 — makes AppendVarint fail
//     before the packet-number append.
//   - AppendPacketAD:105-107 — the same AppendVarint error for an
//     out-of-range packet number, reached after the route-instance append
//     succeeds.
//
// Dead-by-design (documented, NOT claimed):
//   - FirstHopRouteInstanceID:80-82 — the `len(sum) < 8` "suite hash too short"
//     guard. SuiteHash returns a full digest (48 bytes for the 768 suites, 64
//     for the 1024 suites, 32 for the lab-classical suite) for every suite it
//     accepts, and errors for every other suite (which the 77-79 propagation
//     returns first). sum is therefore always >= 32 bytes when execution
//     reaches 80, so the `len(sum) < 8` branch cannot fire for any input.
//
// No new package-level helpers or types are introduced (only test functions),
// so there is nothing for staticcheck U1000. No context.Context (no SA1012
// surface), no goroutines, no real network or filesystem.

import (
	"math"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestControlAADPropagatesReservedDirectionError(t *testing.T) {
	// 63-65: a reserved control direction (2) fails validateControlAADInput at
	// its first guard (control.go:45) before any encoding, and ControlAAD
	// surfaces the ControlAADPreimage error.
	in := ControlAADInput{
		SelectedVersion:  registry.Version20,
		SelectedSuite:    registry.SuiteHybrid768AESGCM,
		MsgType:          registry.MsgCoverCapsule1,
		RouteInstanceID:  1,
		ControlDirection: 2,
	}
	_, err := ControlAAD(in)
	if err == nil || !strings.Contains(err.Error(), "reserved control direction") {
		t.Fatalf("ControlAAD(reserved direction) err = %v, want substring \"reserved control direction\"", err)
	}
}

func TestFirstHopRouteInstanceIDReturnsMaskedIDForValidSuite(t *testing.T) {
	// 83: a valid suite hashes the parts and returns the low 62 bits of the
	// digest. The result is deterministic and strictly below 1<<62.
	parts := [][]byte{[]byte("prelude"), []byte("descriptor"), []byte("binding"), []byte("nonce")}
	id, err := FirstHopRouteInstanceID(registry.SuiteHybrid768AESGCM, parts[0], parts[1], parts[2], parts[3])
	if err != nil {
		t.Fatalf("FirstHopRouteInstanceID(valid) err = %v, want nil", err)
	}
	if id >= 1<<62 {
		t.Fatalf("FirstHopRouteInstanceID id = %#x, want < 1<<62 (not masked)", id)
	}
	again, err := FirstHopRouteInstanceID(registry.SuiteHybrid768AESGCM, parts[0], parts[1], parts[2], parts[3])
	if err != nil || again != id {
		t.Fatalf("FirstHopRouteInstanceID not deterministic: first=%#x again=%#x err=%v", id, again, err)
	}
}

func TestFirstHopRouteInstanceIDRejectsUnsupportedSuite(t *testing.T) {
	// 77-79: an unsupported suite makes SuiteHash return "unsupported suite",
	// which FirstHopRouteInstanceID propagates before the digest is inspected.
	_, err := FirstHopRouteInstanceID(0xBAD, []byte("prelude"), []byte("descriptor"), []byte("binding"), []byte("nonce"))
	if err == nil || !strings.Contains(err.Error(), "unsupported suite") {
		t.Fatalf("FirstHopRouteInstanceID(0xBAD) err = %v, want substring \"unsupported suite\"", err)
	}
}

func TestAppendPacketADRejectsOutOfRangeRouteInstanceID(t *testing.T) {
	// 100-102: a route instance id above wire.MaxVarint makes AppendVarint fail
	// at the first append, before the packet-number append runs.
	_, err := AppendPacketAD(nil, registry.SuiteHybrid768AESGCM, math.MaxUint64, 1, 0, 0, 1)
	if err == nil || !strings.Contains(err.Error(), "varint out of range") {
		t.Fatalf("AppendPacketAD(max route id) err = %v, want substring \"varint out of range\"", err)
	}
}

func TestAppendPacketADRejectsOutOfRangePacketNumber(t *testing.T) {
	// 105-107: an in-range route id lets the first append succeed, then an
	// out-of-range packet number fails the second AppendVarint.
	_, err := AppendPacketAD(nil, registry.SuiteHybrid768AESGCM, 1, 1, 0, 0, math.MaxUint64)
	if err == nil || !strings.Contains(err.Error(), "varint out of range") {
		t.Fatalf("AppendPacketAD(max packet number) err = %v, want substring \"varint out of range\"", err)
	}
}
