package packet

// Adversarial white-box coverage for the uncovered branches of
// packet/receiver.go. receiver.go imports only the protocol package plus the
// standard library; the branches below are exercised either as pure
// nil/invalidity guards (no cryptography at all) or through the package's
// existing in-process AEAD helpers (NewProtector / transactionalDirectionState),
// which perform real but deterministic in-memory AEAD — no network, no
// goroutine, no filesystem.
//
// Targets covered:
//
// Pure guards (no crypto operation):
//   - PreparedOpen.Block:60-62 — the `p == nil || !p.valid` guard. The existing
//     suite only ever calls Block on a successfully prepared open, so the
//     nil-receiver and zero-value (invalid) cases are unreached.
//   - PreparedOpen.TakeBlock:68-70 — the same guard for the transfer path.
//   - PreparedOpen.Destroy:78-80 — the `p == nil` no-op guard.
//   - NewReceiver:99-101 — the `windowSize == 0` default. The existing suite
//     always passes an explicit window size.
//   - Receiver.Destroy:129-131 — the `r == nil` no-op guard.
//   - PrepareOpenWithDirectionState:198-200 — the `state == nil` guard. The
//     existing suite always passes a non-nil DirectionState.
//   - PrepareOpenOwnedWithDirectionState:216-218 — the `state == nil` guard.
//     The existing suite never calls the Owned variant at all, so its entire
//     body is uncovered.
//   - prepareOpenWithProtector:231-233 — the `protector == nil` guard. The
//     public callers always pass a non-nil protector (the receiver's own or a
//     cached one), so this is only reachable via a direct white-box call.
//
// Crypto-backed (deterministic in-memory AEAD via existing helpers):
//   - PrepareOpenOwnedWithDirectionState:219-222 — the materialForPacketView
//     error propagation on the Owned path. A packet whose route instance
//     differs from the state's makes materialForPacketView fail here.
//   - PrepareOpenWithDirectionState:206-208 and 273-275 — the
//     destroyed-receiver propagation. After r.Destroy(), directionProtector
//     returns errReceiverDestroyed, which PrepareOpenWithDirectionState
//     surfaces at 206 (and directionProtector itself reaches the destroyed
//     check at 273).
//   - PrepareOpenOwnedWithDirectionState:223-226 — the same destroyed-receiver
//     propagation on the Owned path.
//   - directionProtector:276-278 — the cache-hit branch. A second
//     PrepareOpenWithDirectionState call with the same state/packet reuses the
//     cached protector instead of building a new one.
//   - directionProtector:280-282 — the NewProtector error propagation. A
//     DirectionState whose material carries a non-12-byte IV makes
//     ReplaceMaterial (called by NewProtector) fail at its IV-length guard.
//   - PrepareOpenOwnedWithDirectionState:227 and prepareOpenWithProtector
//     :245-247,250-252 — the Owned success path that reaches the owned
//     OpenOwned branch and its error return. A packet with a well-formed
//     header but garbage ciphertext makes OpenOwned fail authentication.
//   - Receiver.Destroy:135-137 — the directionProtectors release loop. After a
//     PrepareOpenWithDirectionState call caches a direction protector,
//     Destroy iterates and destroys each one.
//
// Dead-by-design (documented, NOT claimed):
//   - Open:165-168 and OpenWithDirectionState:180-183 — the CommitPreparedOpen
//     error path. Open runs PrepareOpen (whose checkPacketNumberLocked at 235
//     rejects duplicates/outside-window) and only commits after a successful
//     open; the commit's own check at 293 inspects the same key, so a packet
//     number that passed prepare cannot fail commit — the failing replay is
//     caught by prepare first. Shadowed-by-earlier-check.
//   - prepareOpenWithProtector:255-259 — the second checkPacketNumberLocked
//     error after a successful Open. Between the first check (235) and this
//     second check (255) no marking occurs, so a number that passed the first
//     check passes the second; only concurrent marking could differ, which the
//     single-threaded API cannot express.
//   - markPacketNumberKeyLocked:324-326 — the `r.windows == nil` guard.
//     r.windows is nil only after Destroy, which also sets destroyed; commit
//     reaches mark only after the destroyed check at 293 returns nil, so the
//     nil-windows state is unreachable on the commit path.
//   - markPacketNumberKeyLocked:339-341 — the outside-window early return.
//     checkPacketNumberLocked (305) rejects `distance > windowSize` before
//     mark is ever called, so mark never sees an outside-window number.
//
// The matching-packet helper receiverMaterialPacket is referenced by every
// crypto-backed test (>= 2 references), and receiverConfigProtector by every
// NewReceiver construction, so there is nothing for staticcheck U1000. No
// context.Context (no SA1012 surface), no goroutines, no real network or
// filesystem.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

// receiverConfigProtector returns a valid Protector value suitable for
// NewReceiver's config; it only needs to survive NewReceiver's Prepare() call.
func receiverConfigProtector() Protector {
	return Protector{
		Suite:    registry.SuiteHybrid768AESGCM,
		Key:      bytesOf(0x33, 32),
		StaticIV: bytesOf(0x44, 12),
	}
}

// receiverMaterialPacket returns an AuroraPacket whose header fields match
// transactionalDirectionState (route 0x50, hop 1, direction 0, key phase 0) so
// materialForPacketView succeeds; the ciphertext is intentionally garbage so
// protector.Open/OpenOwned fails authentication deterministically.
func receiverMaterialPacket() AuroraPacket {
	return AuroraPacket{
		RouteInstanceID: 0x50,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		PacketNumber:    0,
		Ciphertext:      bytesOf(0, 16),
		AuthTag:         bytesOf(0, 16),
	}
}

func TestPreparedOpenBlockReturnsEmptyForNilAndInvalid(t *testing.T) {
	// 60-62: a nil receiver and a zero-value (invalid) preparation both return
	// the empty FrameBlock.
	var nilPrepared *PreparedOpen
	if got := nilPrepared.Block(); len(got.Frames) != 0 {
		t.Fatalf("nilPrepared.Block() = %+v, want empty", got)
	}
	zero := PreparedOpen{}
	if got := zero.Block(); len(got.Frames) != 0 {
		t.Fatalf("zero-value Block() = %+v, want empty", got)
	}
}

func TestPreparedOpenTakeBlockReturnsEmptyForNilAndInvalid(t *testing.T) {
	// 68-70: same guard on the transfer path.
	var nilPrepared *PreparedOpen
	if got := nilPrepared.TakeBlock(); len(got.Frames) != 0 {
		t.Fatalf("nilPrepared.TakeBlock() = %+v, want empty", got)
	}
	zero := PreparedOpen{}
	if got := zero.TakeBlock(); len(got.Frames) != 0 {
		t.Fatalf("zero-value TakeBlock() = %+v, want empty", got)
	}
}

func TestPreparedOpenDestroyIsNoOpForNil(t *testing.T) {
	// 78-80: Destroy on a nil preparation must not panic.
	var nilPrepared *PreparedOpen
	nilPrepared.Destroy()
}

func TestNewReceiverAppliesDefaultWindowSize(t *testing.T) {
	// 99-101: a zero WindowSize falls back to defaultReceiverWindowSize.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	if r.windowSize != defaultReceiverWindowSize {
		t.Fatalf("windowSize = %d, want default %d", r.windowSize, defaultReceiverWindowSize)
	}
}

func TestReceiverDestroyIsNoOpForNil(t *testing.T) {
	// 129-131: Destroy on a nil receiver must not panic.
	var r *Receiver
	r.Destroy()
}

func TestPrepareOpenWithProtectorRejectsNilProtector(t *testing.T) {
	// 231-233: the nil-protector guard is only reachable via a direct
	// white-box call; public callers always pass a non-nil protector.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	_, err := r.prepareOpenWithProtector(AuroraPacket{}, nil, false)
	if err == nil || !strings.Contains(err.Error(), "missing protector") {
		t.Fatalf("prepareOpenWithProtector(nil) err = %v, want substring \"missing protector\"", err)
	}
}

func TestPrepareOpenWithDirectionStateRejectsNilState(t *testing.T) {
	// 198-200: nil state returns before any material or receiver inspection.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	_, err := r.PrepareOpenWithDirectionState(receiverMaterialPacket(), nil, registry.SuiteHybrid768AESGCM, time.Now())
	if err == nil || !strings.Contains(err.Error(), "missing direction state") {
		t.Fatalf("PrepareOpenWithDirectionState(nil state) err = %v, want substring \"missing direction state\"", err)
	}
}

func TestPrepareOpenOwnedWithDirectionStateRejectsNilState(t *testing.T) {
	// 216-218: same nil-state guard on the Owned path.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	_, err := r.PrepareOpenOwnedWithDirectionState(receiverMaterialPacket(), nil, registry.SuiteHybrid768AESGCM, time.Now())
	if err == nil || !strings.Contains(err.Error(), "missing direction state") {
		t.Fatalf("PrepareOpenOwnedWithDirectionState(nil state) err = %v, want substring \"missing direction state\"", err)
	}
}

func TestPrepareOpenOwnedWithDirectionStateRejectsMaterialMismatch(t *testing.T) {
	// 219-222: a packet whose route instance differs from the state's makes
	// materialForPacketView fail, propagated on the Owned path. The suite is
	// never reached.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	state := transactionalDirectionState()
	mismatched := receiverMaterialPacket()
	mismatched.RouteInstanceID = 0x99
	_, err := r.PrepareOpenOwnedWithDirectionState(mismatched, &state, registry.SuiteHybrid768AESGCM, time.Now())
	if err == nil || !strings.Contains(err.Error(), "route instance mismatch") {
		t.Fatalf("PrepareOpenOwnedWithDirectionState(route mismatch) err = %v, want substring \"route instance mismatch\"", err)
	}
}

func TestPrepareOpenWithDirectionStateRejectsDestroyedReceiver(t *testing.T) {
	// 206-208 + 273-275: after Destroy, directionProtector returns
	// errReceiverDestroyed, which PrepareOpenWithDirectionState surfaces.
	// materialForPacketView runs on the state (not the receiver), so it
	// succeeds and execution reaches the destroyed check.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	r.Destroy()
	state := transactionalDirectionState()
	_, err := r.PrepareOpenWithDirectionState(receiverMaterialPacket(), &state, registry.SuiteHybrid768AESGCM, time.Now())
	if !errors.Is(err, errReceiverDestroyed) {
		t.Fatalf("PrepareOpenWithDirectionState(destroyed) err = %v, want errReceiverDestroyed", err)
	}
}

func TestPrepareOpenOwnedWithDirectionStateRejectsDestroyedReceiver(t *testing.T) {
	// 223-226: same destroyed-receiver propagation on the Owned path.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	r.Destroy()
	state := transactionalDirectionState()
	_, err := r.PrepareOpenOwnedWithDirectionState(receiverMaterialPacket(), &state, registry.SuiteHybrid768AESGCM, time.Now())
	if !errors.Is(err, errReceiverDestroyed) {
		t.Fatalf("PrepareOpenOwnedWithDirectionState(destroyed) err = %v, want errReceiverDestroyed", err)
	}
}

func TestDirectionProtectorCachesAcrossCallsThenDestroyReleases(t *testing.T) {
	// 276-278 (cache hit) + 135-137 (destroy loop) + 250-252 (Open error).
	// The first PrepareOpenWithDirectionState call caches a direction protector
	// (NewProtector at 279) and then fails Open on the garbage ciphertext; the
	// second call reuses the cached protector (276) rather than building a new
	// one, so the map still holds exactly one entry. Destroy then iterates the
	// map (135) and releases it.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	state := transactionalDirectionState()
	pkt := receiverMaterialPacket()
	now := time.Now()
	if _, err := r.PrepareOpenWithDirectionState(pkt, &state, registry.SuiteHybrid768AESGCM, now); err == nil {
		t.Fatal("first PrepareOpenWithDirectionState succeeded on garbage ciphertext, want auth error")
	}
	if _, err := r.PrepareOpenWithDirectionState(pkt, &state, registry.SuiteHybrid768AESGCM, now); err == nil {
		t.Fatal("second PrepareOpenWithDirectionState succeeded on garbage ciphertext, want auth error")
	}
	if got := len(r.directionProtectors); got != 1 {
		t.Fatalf("directionProtectors = %d entries, want 1 (second call must hit the cache)", got)
	}
	r.Destroy()
	if r.directionProtectors != nil {
		t.Fatalf("directionProtectors = %v after Destroy, want nil", r.directionProtectors)
	}
}

func TestDirectionProtectorRejectsInvalidMaterialIV(t *testing.T) {
	// 280-282 + 206-208: a DirectionState whose material carries a non-12-byte
	// IV makes NewProtector's ReplaceMaterial fail at its IV-length guard
	// (before any AEAD or suite logic), propagated through directionProtector
	// and PrepareOpenWithDirectionState.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	state := DirectionState{
		RouteInstanceID: 0x50,
		HopLayer:        1,
		Direction:       0,
		KeyPhase:        0,
		Material: KeyMaterial{
			AppSecret: bytesOf(0x51, 48),
			Key:       bytesOf(0x52, 32),
			IV:        bytesOf(0x53, 5),
		},
	}
	_, err := r.PrepareOpenWithDirectionState(receiverMaterialPacket(), &state, registry.SuiteHybrid768AESGCM, time.Now())
	if err == nil || !strings.Contains(err.Error(), "static IV length 5, want 12") {
		t.Fatalf("PrepareOpenWithDirectionState(bad IV) err = %v, want substring \"static IV length 5, want 12\"", err)
	}
}

func TestPrepareOpenOwnedWithDirectionStateFailsOnMalformedPacket(t *testing.T) {
	// 227 (success path reaches prepareOpenWithProtector) + 245-247 (owned
	// OpenOwned branch) + 250-252 (Open error). A valid state and a
	// header-matching packet with garbage ciphertext make NewProtector succeed
	// (caching a protector) and OpenOwned fail authentication.
	r := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	state := transactionalDirectionState()
	_, err := r.PrepareOpenOwnedWithDirectionState(receiverMaterialPacket(), &state, registry.SuiteHybrid768AESGCM, time.Now())
	if err == nil {
		t.Fatal("PrepareOpenOwnedWithDirectionState succeeded on garbage ciphertext, want auth error")
	}
}
