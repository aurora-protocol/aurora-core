package protocol

// Adversarial coverage for the two packet-direction validators in frames.go
// that the existing TestValidateFrameBlockRejectsMalformedKeyUpdatePayloads and
// TestValidateFrameBlockForDirectionRejectsKeyUpdateForOtherDirection suites
// reach only partially:
//   - ValidateFrameBlockForDirection (line 135, 50% before): the reserved-
//     packet-direction guard (136-137), the ValidateFrameBlock error propagation
//     (139-140), the FLOW_OPEN-in-backward-direction rejection (146-147), and
//     the happy-path return nil (150) stay uncovered. The existing
//     TestValidateFrameBlockForDirectionRejectsKeyUpdateForOtherDirection only
//     exercises the per-frame ValidateKeyUpdateFrameForDirection propagation
//     (143-144) via a direction mismatch.
//   - ValidateKeyUpdateFrameForDirection (line 153, 61.5% before): the non-
//     KeyUpdate early return nil (154-155), the r.Err malformed-payload branch
//     (159-160), the trailing-bytes branch (162-163), the ValidateKeyUpdate
//     propagation (165-166), and the happy-path return nil (171) are uncovered.
//     The existing suite only reaches the direction-mismatch error (168-169).
//
// Both validators are exported and read only their arguments, so each branch is
// isolated by crafting a minimal FrameBlock / AuroraFrame. ValidateFrameBlock
// (line 111, already 100%) is relied on for the propagation case via a block
// whose frame count exceeds MaxFrameBlockFrames. The valid KEY_UPDATE / FLOW_OPEN
// frames reuse the existing keyUpdateFrameForTest helper and NewFlowOpenFrame.
//
// Coverage is re-measured per target to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one error so the
// failure is attributable to the perturbed input alone. New helpers are each
// referenced by >=2 tests so there is no U1000. No context.Context, no
// deprecated APIs.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestValidateFrameBlockForDirectionRejectsEachCondition(t *testing.T) {
	flowOpen := validFlowOpenFrameForCoverage(t)
	cases := []struct {
		name      string
		block     FrameBlock
		direction uint8
		wantSub   string
	}{
		{
			name:      "reserved packet direction",
			block:     FrameBlock{},
			direction: 2,
			wantSub:   "reserved packet direction",
		},
		{
			// A block exceeding MaxFrameBlockFrames is rejected by ValidateFrameBlock
			// (line 112-113) before any per-frame validation, so the error is
			// propagated cleanly by ValidateFrameBlockForDirection at 139-140.
			name:      "ValidateFrameBlock error propagates",
			block:     FrameBlock{Frames: make([]AuroraFrame, MaxFrameBlockFrames+1)},
			direction: 0,
			wantSub:   "frame count exceeds limit",
		},
		{
			// A valid FLOW_OPEN frame passes ValidateFrameBlock; with direction==1
			// the per-frame loop reaches 146 and rejects FLOW_OPEN in backward
			// direction (the prior ValidateKeyUpdateFrameForDirection call returns
			// nil early because FLOW_OPEN is not KEY_UPDATE).
			name:      "FLOW_OPEN in backward direction",
			block:     FrameBlock{Frames: []AuroraFrame{flowOpen}},
			direction: 1,
			wantSub:   "FLOW_OPEN is malformed in backward direction",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFrameBlockForDirection(tc.block, tc.direction)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestValidateFrameBlockForDirectionAcceptsValidForwardBlock(t *testing.T) {
	// A structurally-valid KEY_UPDATE whose Direction matches the packet
	// direction passes ValidateFrameBlock and the per-frame direction check,
	// reaching the happy-path return nil at line 150.
	frame := keyUpdateFrameForTest(t, KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytes.Repeat([]byte{0x16}, 16),
		UpdateReason:    1,
	})
	if err := ValidateFrameBlockForDirection(FrameBlock{Frames: []AuroraFrame{frame}}, 0); err != nil {
		t.Fatalf("valid forward block rejected: %v", err)
	}
}

func TestValidateKeyUpdateFrameForDirectionDecidesPerCondition(t *testing.T) {
	valid := KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytes.Repeat([]byte{0x16}, 16),
		UpdateReason:    1,
	}
	matchingFrame := keyUpdateFrameForTest(t, valid)
	trailingFrame := keyUpdateFrameForTest(t, valid)
	trailingFrame.Payload = append(trailingFrame.Payload, 0x00)
	directionMismatchFrame := keyUpdateFrameForTest(t, KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       1,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     bytes.Repeat([]byte{0x17}, 16),
		UpdateReason:    1,
	})
	validateKeyUpdateErrFrame := keyUpdateFrameForTest(t, KeyUpdate{
		RouteInstanceID: 7,
		HopLayer:        1,
		Direction:       2, // >1 fails ValidateKeyUpdate ("reserved KEY_UPDATE direction")
		OldKeyPhase:     1,
		NewKeyPhase:     2,
		UpdateNonce:     bytes.Repeat([]byte{0x12}, 16),
		UpdateReason:    1,
	})
	cases := []struct {
		name       string
		frame      AuroraFrame
		direction  uint8
		wantSub    string // expected error substring; empty means expect nil
		wantAnyErr bool   // expect any non-nil error (decode failure has no stable message)
	}{
		{"non-KeyUpdate frame returns nil early", validFlowOpenFrameForCoverage(t), 0, "", false},
		{"malformed payload returns decode error", AuroraFrame{FrameType: registry.FrameKeyUpdate, Payload: []byte{0x00}}, 0, "", true},
		{"trailing KEY_UPDATE payload bytes rejected", trailingFrame, 0, "trailing KEY_UPDATE payload bytes", false},
		{"ValidateKeyUpdate error propagates", validateKeyUpdateErrFrame, 0, "reserved KEY_UPDATE direction", false},
		{"direction mismatch rejected", directionMismatchFrame, 0, "does not match packet direction", false},
		{"matching direction accepted", matchingFrame, 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKeyUpdateFrameForDirection(tc.frame, tc.direction)
			if tc.wantAnyErr {
				if err == nil {
					t.Fatalf("%s: expected non-nil decode error, got nil", tc.name)
				}
				return
			}
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

// validFlowOpenFrameForCoverage returns a FLOW_OPEN AuroraFrame that passes
// ValidateFrameBlock (and thus ValidateFlowManagementFrame). It is used by the
// FLOW_OPEN-in-backward-direction case of ValidateFrameBlockForDirection and by
// the non-KeyUpdate early-return case of ValidateKeyUpdateFrameForDirection,
// so it is not U1000. Mirrors the fixture at frames_test.go:208.
func validFlowOpenFrameForCoverage(t *testing.T) AuroraFrame {
	t.Helper()
	frame, err := NewFlowOpenFrame(FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           10,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		UDPFQDNMode:      0x00,
		NameBindingID:    bytes.Repeat([]byte{0x11}, 16),
		DNSAnswerSetHash: bytes.Repeat([]byte{0x22}, 48),
		LocalBindingMode: 0x00,
		PriorityClass:    0x01,
	})
	if err != nil {
		t.Fatalf("NewFlowOpenFrame: %v", err)
	}
	return frame
}
