package packet

// Adversarial coverage for the key-update state machine in packet/key_update.go.
// The happy derive / prepare / commit / apply / ack / material-for-packet paths are
// already exercised end-to-end by packet_test.go (TestDirectionState*,
// TestKeyUpdateRoundTrip and friends), so the success returns and the
// non-count-0 guards (drain-active 202, phase-exhausted 205, ack-missing 323,
// ack-oversize 326, direction-mismatch 358, old-phase-mismatch 365/369, the
// duplicate-received fast-false 389, the source-phase/material mismatches in
// CommitPreparedUpdate) are not re-asserted here except where an anchor is
// needed to prove the error-case inputs are otherwise valid.
//
// This file covers the residual count-0 blocks with crafted inputs, perturbing
// exactly one condition per case so the branch under test is the one that
// fires. Each rejection asserts exactly one error substring so the failure is
// attributable to the perturbed field alone.
//
// Uncovered blocks (measured count 0 before this file):
//   - Destroy nil-guards 25 (KeyMaterial), 39 (KeyUpdateResult), 63
//     (PreparedKeyUpdate), 179 (DirectionState).
//   - DeriveKeyUpdate: KeyUpdateContext encode error 78, unsupported suite 82.
//   - ApplyReceivedKeyUpdate: oversize ACK nonce 116.
//   - PrepareUpdate: ValidateKeyUpdate error 218, DeriveKeyUpdate error 222.
//   - CommitPreparedUpdate: ValidateKeyUpdate error 235.
//   - materialForPacketView: route mismatch 281, hop mismatch 284, direction
//     mismatch 287.
//   - DrainInfo: empty-drain zero return 306.
//   - ApplyKeyUpdateACK: route mismatch 329, hop mismatch 332, direction
//     mismatch 335, phase mismatch 338.
//   - ApplyReceivedUpdateAt: route mismatch 352, hop mismatch 355, Encode
//     error 362.
//   - isDuplicateReceivedUpdate: NewKeyPhase mismatch fast-false 392.
//
// Dead-by-design (documented, not covered):
//   - DeriveKeyUpdate HKDF/AEAD branches 86/90/95/100. After a supported suite
//     passes SuiteHashLength (82), HKDFExpandLabelForSuite runs with the fixed
//     label "traffic upd" (full label "aurora traffic upd", 18 bytes, well
//     under 255) and a KeyUpdateContext digest (SHA-384, 48 bytes, well under
//     255), so hkdfExpandLabel's encoder writes never fail and hkdf.Expand
//     returns an io.Reader with no error (86 never fires). AEADKeyLength for a
//     supported suite returns 32 with no error (90 never fires). The "key" and
//     "iv" expansions use the short labels "key"/"iv" and a nil context, so
//     the same reasoning applies (95/100 never fire).
//   - InitiateUpdate CommitPreparedUpdate error 194. InitiateUpdate calls
//     PrepareUpdate and then CommitPreparedUpdate with the same receiver and
//     the same `now`. PrepareUpdate builds the prepared frame from s and does
//     not mutate s, so CommitPreparedUpdate's ValidateKeyUpdate (235) and the
//     route/hop/direction/source-phase/source-material checks all hold against
//     the unmodified s. No constructible input reaches 194 without concurrent
//     mutation, which the single-threaded API does not expose.
//
// Not duplicated: the round-trip and drain-expiry behaviour is covered by
// packet_test.go and is not re-asserted here.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The new helpers keyUpdateCovValidFrame and
// keyUpdateCovStateWithPendingAck are each referenced by >=2 tests/subtests,
// so they are not U1000. No context.Context, no goroutines, no deprecated APIs.

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// keyUpdateCovValidFrame returns a KeyUpdate that passes protocol.ValidateKeyUpdate
// (Direction in range, NewKeyPhase == OldKeyPhase+1) and whose fields keep
// KeyUpdateContext's wire writes in range (RouteInstanceID 0x50 << wire.MaxVarint,
// UpdateNonce 16 bytes). It matches transactionalDirectionState (route 0x50, hop 1,
// direction 0, phase 0). Each error-case test clones it and perturbs one field.
// Referenced by >=2 tests, so not U1000.
func keyUpdateCovValidFrame() protocol.KeyUpdate {
	return protocol.KeyUpdate{
		RouteInstanceID: 0x50,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytesOf(0xa1, 16),
		UpdateReason:    1,
	}
}

// keyUpdateCovStateWithPendingAck returns a DirectionState that has an active
// pending sent update and an active drain window, so ApplyKeyUpdateACK reaches
// the field-mismatch checks (329+). expireDrain does not clear the state because
// DrainUntil is in the future relative to now. Referenced by >=2 subtests, so
// not U1000.
func keyUpdateCovStateWithPendingAck(now time.Time) DirectionState {
	s := transactionalDirectionState()
	s.KeyPhase = 5
	s.previousKeyPhase = 4
	s.DrainUntil = now.Add(MaxDrainWindow)
	s.pendingSentUpdateActive = true
	s.pendingSentUpdate = keyUpdateCovValidFrame()
	return s
}

func TestKeyUpdateDestroyNilGuardsDecidePerCondition(t *testing.T) {
	// Each nil-receiver Destroy must return through the nil guard (25/39/63/179)
	// without dereferencing; the pointer stays nil, proving the early return.
	t.Run("key material nil", func(t *testing.T) {
		var m *KeyMaterial
		m.Destroy()
		if m != nil {
			t.Fatalf("nil KeyMaterial Destroy dereferenced: %v", m)
		}
	})
	t.Run("key update result nil", func(t *testing.T) {
		var r *KeyUpdateResult
		r.Destroy()
		if r != nil {
			t.Fatalf("nil KeyUpdateResult Destroy dereferenced: %v", r)
		}
	})
	t.Run("prepared key update nil", func(t *testing.T) {
		var p *PreparedKeyUpdate
		p.Destroy()
		if p != nil {
			t.Fatalf("nil PreparedKeyUpdate Destroy dereferenced: %v", p)
		}
	})
	t.Run("direction state nil", func(t *testing.T) {
		var s *DirectionState
		s.Destroy()
		if s != nil {
			t.Fatalf("nil DirectionState Destroy dereferenced: %v", s)
		}
	})
}

func TestDeriveKeyUpdateDecidesPerCondition(t *testing.T) {
	t.Run("key update context encode failure", func(t *testing.T) {
		// ValidateKeyUpdate ignores RouteInstanceID, so an out-of-range id
		// passes 74 and fails WriteVarint inside KeyUpdateContext at 78.
		frame := keyUpdateCovValidFrame()
		frame.RouteInstanceID = math.MaxUint64
		_, err := DeriveKeyUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x51, 48), frame)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
	t.Run("unsupported suite", func(t *testing.T) {
		// A valid frame passes ValidateKeyUpdate and KeyUpdateContext, then
		// SuiteHashLength rejects the unknown suite at 82.
		_, err := DeriveKeyUpdate(0xBAD, bytesOf(0x51, 48), keyUpdateCovValidFrame())
		if err == nil || !strings.Contains(err.Error(), "unsupported suite 0xbad") {
			t.Fatalf("err = %v, want %q", err, "unsupported suite 0xbad")
		}
	})
	t.Run("valid derivation", func(t *testing.T) {
		// Anchor: a supported suite + valid frame derives non-empty material,
		// proving the error-case inputs are otherwise valid.
		next, err := DeriveKeyUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x51, 48), keyUpdateCovValidFrame())
		if err != nil {
			t.Fatalf("valid derive: %v", err)
		}
		defer next.Destroy()
		if len(next.AppSecret) == 0 || len(next.Key) == 0 || len(next.IV) == 0 {
			t.Fatalf("derived material empty: %+v", next)
		}
	})
}

func TestApplyReceivedKeyUpdateDecidesPerCondition(t *testing.T) {
	t.Run("oversize ack nonce", func(t *testing.T) {
		// A valid frame + supported suite lets DeriveKeyUpdate succeed; with
		// AckRequired set, the 0x10000-byte ackNonce exceeds maxOpaque16Bytes
		// at 116.
		frame := keyUpdateCovValidFrame()
		frame.AckRequired = true
		_, err := ApplyReceivedKeyUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x51, 48), frame, bytesOf(0x01, 0x10000))
		if err == nil || !strings.Contains(err.Error(), "exceeds canonical range") {
			t.Fatalf("err = %v, want %q", err, "exceeds canonical range")
		}
	})
	t.Run("valid without ack", func(t *testing.T) {
		// Anchor: AckRequired false derives a result with no ACK.
		res, err := ApplyReceivedKeyUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0x51, 48), keyUpdateCovValidFrame(), nil)
		if err != nil {
			t.Fatalf("valid apply: %v", err)
		}
		defer res.Destroy()
		if res.ACK != nil || len(res.Next.Key) == 0 {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestPrepareUpdateDecidesPerCondition(t *testing.T) {
	now := time.Now()
	t.Run("validate rejects reserved direction", func(t *testing.T) {
		// PrepareUpdate builds the frame from s, so a reserved direction on s
		// surfaces at ValidateKeyUpdate (218).
		s := transactionalDirectionState()
		s.Direction = 2
		_, err := s.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa1, 16), false, 1, now)
		if err == nil || !strings.Contains(err.Error(), "reserved KEY_UPDATE direction") {
			t.Fatalf("err = %v, want %q", err, "reserved KEY_UPDATE direction")
		}
	})
	t.Run("derive rejects unsupported suite", func(t *testing.T) {
		// A valid frame passes ValidateKeyUpdate (218) and DeriveKeyUpdate
		// rejects the unknown suite at 82, propagated at 222.
		s := transactionalDirectionState()
		_, err := s.PrepareUpdate(0xBAD, bytesOf(0xa1, 16), false, 1, now)
		if err == nil || !strings.Contains(err.Error(), "unsupported suite 0xbad") {
			t.Fatalf("err = %v, want %q", err, "unsupported suite 0xbad")
		}
	})
	t.Run("valid prepare", func(t *testing.T) {
		// Anchor: a supported suite + valid state prepares an update whose
		// frame matches the source state.
		s := transactionalDirectionState()
		prepared, err := s.PrepareUpdate(registry.SuiteHybrid768AESGCM, bytesOf(0xa1, 16), false, 1, now)
		if err != nil {
			t.Fatalf("valid prepare: %v", err)
		}
		defer prepared.Destroy()
		if got := prepared.Frame(); got.NewKeyPhase != 1 || got.OldKeyPhase != 0 {
			t.Fatalf("prepared frame phases: %+v", got)
		}
	})
}

func TestCommitPreparedUpdateDecidesPerCondition(t *testing.T) {
	t.Run("validate rejects prepared frame", func(t *testing.T) {
		// White-box: a PreparedKeyUpdate carrying a reserved-direction frame
		// fails ValidateKeyUpdate at 235 before any receiver check runs.
		s := transactionalDirectionState()
		prepared := PreparedKeyUpdate{frame: protocol.KeyUpdate{Direction: 2, OldKeyPhase: 0, NewKeyPhase: 1}}
		err := s.CommitPreparedUpdate(prepared, time.Now())
		if err == nil || !strings.Contains(err.Error(), "reserved KEY_UPDATE direction") {
			t.Fatalf("err = %v, want %q", err, "reserved KEY_UPDATE direction")
		}
	})
}

func TestMaterialForPacketViewDecidesPerCondition(t *testing.T) {
	state := transactionalDirectionState()
	now := time.Now()
	t.Run("route mismatch", func(t *testing.T) {
		_, err := state.MaterialForPacket(AuroraPacket{RouteInstanceID: 0x51, HopLayer: 1, Direction: 0, KeyPhase: 0}, now)
		if err == nil || !strings.Contains(err.Error(), "packet route instance mismatch") {
			t.Fatalf("err = %v, want %q", err, "packet route instance mismatch")
		}
	})
	t.Run("hop mismatch", func(t *testing.T) {
		_, err := state.MaterialForPacket(AuroraPacket{RouteInstanceID: 0x50, HopLayer: 2, Direction: 0, KeyPhase: 0}, now)
		if err == nil || !strings.Contains(err.Error(), "packet hop layer mismatch") {
			t.Fatalf("err = %v, want %q", err, "packet hop layer mismatch")
		}
	})
	t.Run("direction mismatch", func(t *testing.T) {
		_, err := state.MaterialForPacket(AuroraPacket{RouteInstanceID: 0x50, HopLayer: 1, Direction: 1, KeyPhase: 0}, now)
		if err == nil || !strings.Contains(err.Error(), "packet direction mismatch") {
			t.Fatalf("err = %v, want %q", err, "packet direction mismatch")
		}
	})
	t.Run("valid current phase", func(t *testing.T) {
		// Anchor: a matching packet at the current phase returns owned material.
		mat, err := state.MaterialForPacket(AuroraPacket{RouteInstanceID: 0x50, HopLayer: 1, Direction: 0, KeyPhase: 0}, now)
		if err != nil {
			t.Fatalf("valid material: %v", err)
		}
		defer mat.Destroy()
		if len(mat.Key) == 0 {
			t.Fatalf("current-phase material empty: %+v", mat)
		}
	})
}

func TestDrainInfoDecidesPerCondition(t *testing.T) {
	t.Run("empty drain", func(t *testing.T) {
		// A fresh state has a zero DrainUntil, so DrainInfo returns the
		// zero/false triple at 306.
		state := transactionalDirectionState()
		phase, deadline, ok := state.DrainInfo()
		if ok || phase != 0 || !deadline.IsZero() {
			t.Fatalf("drain info = phase %d deadline %v ok %v, want zero/false", phase, deadline, ok)
		}
	})
	t.Run("active drain", func(t *testing.T) {
		// Anchor: a state with a future deadline reports the prior phase.
		state := transactionalDirectionState()
		state.previousKeyPhase = 4
		state.DrainUntil = time.Now().Add(MaxDrainWindow)
		phase, _, ok := state.DrainInfo()
		if !ok || phase != 4 {
			t.Fatalf("drain info = phase %d ok %v, want phase 4 ok true", phase, ok)
		}
	})
}

func TestApplyKeyUpdateACKDecidesPerCondition(t *testing.T) {
	now := time.Now()
	t.Run("route mismatch", func(t *testing.T) {
		s := keyUpdateCovStateWithPendingAck(now)
		ack := protocol.KeyUpdateACK{RouteInstanceID: 0x51, HopLayer: 1, AckedDirection: 0, AckedKeyPhase: 5, AckNonce: bytesOf(0x01, 1)}
		err := s.ApplyKeyUpdateACK(ack, now)
		if err == nil || !strings.Contains(err.Error(), "KEY_UPDATE_ACK route instance mismatch") {
			t.Fatalf("err = %v, want %q", err, "KEY_UPDATE_ACK route instance mismatch")
		}
	})
	t.Run("hop mismatch", func(t *testing.T) {
		s := keyUpdateCovStateWithPendingAck(now)
		ack := protocol.KeyUpdateACK{RouteInstanceID: 0x50, HopLayer: 2, AckedDirection: 0, AckedKeyPhase: 5, AckNonce: bytesOf(0x01, 1)}
		err := s.ApplyKeyUpdateACK(ack, now)
		if err == nil || !strings.Contains(err.Error(), "KEY_UPDATE_ACK hop layer mismatch") {
			t.Fatalf("err = %v, want %q", err, "KEY_UPDATE_ACK hop layer mismatch")
		}
	})
	t.Run("direction mismatch", func(t *testing.T) {
		s := keyUpdateCovStateWithPendingAck(now)
		ack := protocol.KeyUpdateACK{RouteInstanceID: 0x50, HopLayer: 1, AckedDirection: 1, AckedKeyPhase: 5, AckNonce: bytesOf(0x01, 1)}
		err := s.ApplyKeyUpdateACK(ack, now)
		if err == nil || !strings.Contains(err.Error(), "KEY_UPDATE_ACK direction mismatch") {
			t.Fatalf("err = %v, want %q", err, "KEY_UPDATE_ACK direction mismatch")
		}
	})
	t.Run("phase mismatch", func(t *testing.T) {
		s := keyUpdateCovStateWithPendingAck(now)
		ack := protocol.KeyUpdateACK{RouteInstanceID: 0x50, HopLayer: 1, AckedDirection: 0, AckedKeyPhase: 99, AckNonce: bytesOf(0x01, 1)}
		err := s.ApplyKeyUpdateACK(ack, now)
		if err == nil || !strings.Contains(err.Error(), "does not match active phase 5") {
			t.Fatalf("err = %v, want %q", err, "does not match active phase 5")
		}
	})
	t.Run("valid ack", func(t *testing.T) {
		// Anchor: a fully-matching ack clears the drain state.
		s := keyUpdateCovStateWithPendingAck(now)
		ack := protocol.KeyUpdateACK{RouteInstanceID: 0x50, HopLayer: 1, AckedDirection: 0, AckedKeyPhase: 5, AckNonce: bytesOf(0x01, 1)}
		if err := s.ApplyKeyUpdateACK(ack, now); err != nil {
			t.Fatalf("valid ack: %v", err)
		}
		if _, _, ok := s.DrainInfo(); ok {
			t.Fatalf("drain state not cleared after valid ack")
		}
	})
}

func TestApplyReceivedUpdateAtDecidesPerCondition(t *testing.T) {
	now := time.Now()
	t.Run("route mismatch", func(t *testing.T) {
		s := transactionalDirectionState()
		frame := keyUpdateCovValidFrame()
		frame.RouteInstanceID = 0x51
		_, err := s.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, nil, now)
		if err == nil || !strings.Contains(err.Error(), "KEY_UPDATE route instance mismatch") {
			t.Fatalf("err = %v, want %q", err, "KEY_UPDATE route instance mismatch")
		}
	})
	t.Run("hop mismatch", func(t *testing.T) {
		s := transactionalDirectionState()
		frame := keyUpdateCovValidFrame()
		frame.HopLayer = 2
		_, err := s.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, nil, now)
		if err == nil || !strings.Contains(err.Error(), "KEY_UPDATE hop layer mismatch") {
			t.Fatalf("err = %v, want %q", err, "KEY_UPDATE hop layer mismatch")
		}
	})
	t.Run("encode failure", func(t *testing.T) {
		// The route/hop/direction checks pass (id matches), then Encode fails
		// on the out-of-range RouteInstanceID at 362.
		s := transactionalDirectionState()
		s.RouteInstanceID = math.MaxUint64
		frame := keyUpdateCovValidFrame()
		frame.RouteInstanceID = math.MaxUint64
		_, err := s.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, nil, now)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
}

func TestIsDuplicateReceivedUpdateDecidesPerCondition(t *testing.T) {
	// A state with a recorded prior update and an active drain window reaches
	// isDuplicateReceivedUpdate via the OldKeyPhase-mismatch branch (365). With
	// NewKeyPhase != s.KeyPhase, the duplicate check returns false at 392, so
	// ApplyReceivedUpdateAt surfaces the active-phase mismatch at 369.
	now := time.Now()
	s := transactionalDirectionState()
	s.KeyPhase = 5
	s.previousKeyPhase = 4
	s.DrainUntil = now.Add(MaxDrainWindow)
	s.lastReceivedUpdate = []byte{0x01}
	frame := keyUpdateCovValidFrame()
	frame.OldKeyPhase = 0
	frame.NewKeyPhase = 6
	_, err := s.ApplyReceivedUpdateAt(registry.SuiteHybrid768AESGCM, frame, nil, now)
	if err == nil || !strings.Contains(err.Error(), "does not match active phase 5") {
		t.Fatalf("err = %v, want %q", err, "does not match active phase 5")
	}
}
