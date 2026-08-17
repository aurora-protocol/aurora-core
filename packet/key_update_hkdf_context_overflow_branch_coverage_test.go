package packet_test

// Adversarial white-box branch coverage for the count-0 HKDF context-too-long
// error guard in DeriveKeyUpdate (packet/key_update.go:72):
//
//	func DeriveKeyUpdate(suite uint64, currentAppSecret []byte, frame protocol.KeyUpdate) (KeyMaterial, error) {
//	    if err := protocol.ValidateKeyUpdate(frame); err != nil { return ... err }   // :74
//	    context, err := KeyUpdateContext(frame); if err != nil { return ... err }    // :77
//	    hashLen, err := auroracrypto.SuiteHashLength(suite); if err != nil { ... }   // :81
//	    nextSecret, err := auroracrypto.HKDFExpandLabelForSuite(suite, currentAppSecret, "traffic upd", context, hashLen)
//	    if err != nil { return KeyMaterial{}, err }                                  // :86  <-- COUNT 0
//	    ...
//	}
//
// The existing packet/key_update_coverage_test.go documents :86/90/95/100 as
// dead-by-design (lines 34-43), reasoning that HKDFExpandLabelForSuite runs "with
// the fixed label 'traffic upd' ... and a KeyUpdateContext digest (SHA-384,
// 48 bytes, well under 255), so hkdfExpandLabel's encoder writes never fail".
//
// That classification is OVERBROAD for :86. The `context` passed to
// HKDFExpandLabelForSuite at :85 is NOT a 48-byte SHA-384 digest — it is the RAW
// encoded KeyUpdateContext buffer (key_update.go:131-141: e.WriteBytes("aurora
// v2.0 key update") + WriteVarint(RouteInstanceID) + 4×WriteUint8 +
// WriteOpaque16(UpdateNonce)), whose length is 28+len(UpdateNonce). ValidateKeyUpdate
// (protocol/frames.go:371) bounds only Direction and the phase increment, NOT
// UpdateNonce length, so a structurally-valid KeyUpdate carrying an oversized
// UpdateNonce makes the encoded context exceed 255 bytes. hkdfExpandLabel
// (crypto/hkdf.go:66) then returns "crypto: HKDF context too long", :85 returns
// the error, and :86 fires. DeriveKeyUpdate is exported and deterministic (HKDF
// + suite lookups, no rand/signing), so the guard is reachable from a test
// without faulting globals.
//
// The sibling guards remain dead-by-design and are NOT claimed:
//   - :90 (AEADKeyLength err) — same suite set as SuiteHashLength (:81), so a
//     suite valid at :81 cannot fail at :89.
//   - :95/:100 (the "key"/"iv" HKDF expansions) — reached only after :85
//     succeeds, and use a nil context + short hardcoded labels, so none of
//     hkdfExpandLabel's failure conditions (label>255, context>255, encoder
//     write err, hkdf.Expand length overflow) can fire.
//
// The per-line coverage flip (:86 0 -> 1) is the rigorous proof.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestDeriveKeyUpdateHKDFContextOverflowGuard(t *testing.T) {
	// key_update.go:86 — an oversized UpdateNonce (300 bytes) makes
	// KeyUpdateContext encode a 328-byte context (21-byte prefix + 1-byte varint
	// + 4 uint8s + 2+300 opaque16). 328 > 255, so hkdfExpandLabel returns
	// "crypto: HKDF context too long", :85 surfaces it, and DeriveKeyUpdate
	// returns (zero KeyMaterial, err) at :87. ValidateKeyUpdate passes first
	// (Direction 0 <= 1, NewKeyPhase 1 == OldKeyPhase 0 + 1).
	_, err := packet.DeriveKeyUpdate(registry.SuiteHybrid768AESGCM, make([]byte, 48), protocol.KeyUpdate{
		Direction:   0,
		OldKeyPhase: 0,
		NewKeyPhase: 1,
		UpdateNonce: make([]byte, 300),
	})
	if err == nil {
		t.Fatal("DeriveKeyUpdate(oversize UpdateNonce) err = nil, want non-nil (:86 HKDF context-too-long guard should fire)")
	}
	if !strings.Contains(err.Error(), "HKDF context too long") {
		t.Fatalf("DeriveKeyUpdate(oversize) err = %v, want substring \"HKDF context too long\"", err)
	}

	// Contrast: a short UpdateNonce (16 bytes) encodes a 44-byte context (< 255),
	// so HKDFExpandLabelForSuite succeeds and DeriveKeyUpdate returns a fully
	// populated KeyMaterial with a nil error. Proves the error above is the
	// oversize context, not some earlier validation, and locks the happy path.
	got, err := packet.DeriveKeyUpdate(registry.SuiteHybrid768AESGCM, make([]byte, 48), protocol.KeyUpdate{
		Direction:   0,
		OldKeyPhase: 0,
		NewKeyPhase: 1,
		UpdateNonce: make([]byte, 16),
	})
	if err != nil {
		t.Fatalf("DeriveKeyUpdate(short UpdateNonce) err = %v, want nil", err)
	}
	if len(got.AppSecret) == 0 || len(got.Key) == 0 || len(got.IV) == 0 {
		t.Fatalf("DeriveKeyUpdate(short valid) returned empty material: %+v", got)
	}
}
