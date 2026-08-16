package flow

// Adversarial coverage for the three pure flow-management helpers in flow.go
// that the existing ConfirmUDPFrame / MarkPeerCloseFrame / ConfirmUDP suite
// reaches only partially:
//   - decodeUDPTargetConfirmFrame (line 179, 33.3% before): only the
//     ValidateFlowManagementFrame rejection (183-185) is covered (via the
//     flow_id-mismatch test at flow_test.go:575). The wrong-frame-type error
//     (180-182) and the full happy path (186-191, decode + return confirm) stay
//     uncovered — the happy-path tests call ConfirmUDP with a struct, bypassing
//     the decoder entirely.
//   - decodeFlowCloseFrame (line 293, 33.3% before): same shape — only the
//     ValidateFlowManagementFrame rejection (297-299) is covered; the
//     wrong-frame-type error (294-296) and happy path (300, 305) are not.
//   - validateUDPConfirmAgainstFlow (line 194, 66.7% before): the confirm-matches
//     error (203-205) is covered once; the non-authoritative-mode early nil
//     (197-198), the non-IP-target early nil (200-202), and the DNS-answer-hash
//     mismatch error (206-208) are not. Driven directly with crafted
//     (FlowState, UDPTargetConfirm) structs — no Manager or flow registry needed.
//
// Dead by design (documented, not contrived):
//   - decodeUDPTargetConfirmFrame 188-190 (r.Err() after validation):
//     ValidateFlowManagementFrame already decodes the same payload via
//     DecodeUDPTargetConfirm (frames.go:642) and checks r.Err() (frames.go:662).
//     When it returns nil the payload decodes cleanly, so the re-decode at 186
//     can never hit r.Err().
//   - decodeFlowCloseFrame 302-304 (r.Err() after validation): same guarantee —
//     ValidateFlowManagementFrame decodes via DecodeFlowClose (frames.go:649)
//     and checks r.Err() (frames.go:662), so the re-decode at 300 cannot error.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one error so
// the failure is attributable to the perturbed field alone.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestDecodeUDPTargetConfirmFrameRejectsWrongFrameType(t *testing.T) {
	frame := protocol.AuroraFrame{FrameType: 0x00, FlowID: 10, Payload: []byte{0x00}}
	_, err := decodeUDPTargetConfirmFrame(frame)
	if err == nil || !strings.Contains(err.Error(), "expected UDP_TARGET_CONFIRM frame") {
		t.Fatalf("err = %v, want \"expected UDP_TARGET_CONFIRM frame\"", err)
	}
}

func TestDecodeUDPTargetConfirmFrameRejectsInvalidConfirm(t *testing.T) {
	// FlowID==0 fails ValidateUDPTargetConfirm ("zero flow_id") inside
	// ValidateFlowManagementFrame (frames.go:645), so the decoder returns that
	// error before reaching the re-decode. The frame is built by hand because
	// NewUDPTargetConfirmFrame itself rejects a zero flow_id.
	bad := validUDPConfirmForCoverage()
	bad.FlowID = 0
	payload, err := protocol.Encode(bad)
	if err != nil {
		t.Fatalf("encode bad confirm: %v", err)
	}
	frame := protocol.AuroraFrame{FrameType: registry.FrameUDPTargetConfirm, FlowID: 0, Payload: payload}
	_, err = decodeUDPTargetConfirmFrame(frame)
	if err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("err = %v, want \"zero flow_id\"", err)
	}
}

func TestDecodeUDPTargetConfirmFrameAcceptsValid(t *testing.T) {
	confirm := validUDPConfirmForCoverage()
	frame, err := protocol.NewUDPTargetConfirmFrame(confirm)
	if err != nil {
		t.Fatalf("NewUDPTargetConfirmFrame: %v", err)
	}
	got, err := decodeUDPTargetConfirmFrame(frame)
	if err != nil {
		t.Fatalf("decodeUDPTargetConfirmFrame: %v", err)
	}
	if got.FlowID != confirm.FlowID || got.TargetKind != confirm.TargetKind ||
		got.SelectedPort != confirm.SelectedPort || !bytes.Equal(got.SelectedIP, confirm.SelectedIP) ||
		!bytes.Equal(got.DNSAnswerSetHash, confirm.DNSAnswerSetHash) {
		t.Fatalf("decoded confirm = %+v, want %+v", got, confirm)
	}
}

func TestDecodeFlowCloseFrameRejectsWrongFrameType(t *testing.T) {
	frame := protocol.AuroraFrame{FrameType: 0x00, FlowID: 23, Payload: []byte{0x00}}
	_, err := decodeFlowCloseFrame(frame)
	if err == nil || !strings.Contains(err.Error(), "expected FLOW_CLOSE frame") {
		t.Fatalf("err = %v, want \"expected FLOW_CLOSE frame\"", err)
	}
}

func TestDecodeFlowCloseFrameRejectsInvalidClose(t *testing.T) {
	// FlowID==0 fails ValidateFlowClose ("zero flow_id") inside
	// ValidateFlowManagementFrame (frames.go:668), so the decoder returns that
	// error before reaching the re-decode.
	bad := validFlowCloseForCoverage()
	bad.FlowID = 0
	payload, err := protocol.Encode(bad)
	if err != nil {
		t.Fatalf("encode bad close: %v", err)
	}
	frame := protocol.AuroraFrame{FrameType: registry.FrameFlowClose, FlowID: 0, Payload: payload}
	_, err = decodeFlowCloseFrame(frame)
	if err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("err = %v, want \"zero flow_id\"", err)
	}
}

func TestDecodeFlowCloseFrameAcceptsValid(t *testing.T) {
	close := validFlowCloseForCoverage()
	frame, err := protocol.NewFlowCloseFrame(close)
	if err != nil {
		t.Fatalf("NewFlowCloseFrame: %v", err)
	}
	got, err := decodeFlowCloseFrame(frame)
	if err != nil {
		t.Fatalf("decodeFlowCloseFrame: %v", err)
	}
	if got.FlowID != close.FlowID || got.CloseCode != close.CloseCode {
		t.Fatalf("decoded close = %+v, want %+v", got, close)
	}
}

func TestValidateUDPConfirmAgainstFlowDecidesPerModeAndTargetMatch(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(state *FlowState, confirm *protocol.UDPTargetConfirm)
		wantError string // "" = expect nil
	}{
		{
			name: "non-authoritative mode returns nil early",
			mutate: func(s *FlowState, c *protocol.UDPTargetConfirm) {
				s.UDPFQDNMode = UDPFQDNStandardsMasqueOnly
			},
		},
		{
			name: "non-IP target kind returns nil early",
			mutate: func(s *FlowState, c *protocol.UDPTargetConfirm) {
				s.TargetKind = TargetKindDomainName
			},
		},
		{
			name: "confirm target kind mismatch",
			mutate: func(s *FlowState, c *protocol.UDPTargetConfirm) {
				c.TargetKind = TargetKindIPv6
			},
			wantError: "does not match IP-authoritative flow target",
		},
		{
			name: "confirm selected port mismatch",
			mutate: func(s *FlowState, c *protocol.UDPTargetConfirm) {
				c.SelectedPort = 80
			},
			wantError: "does not match IP-authoritative flow target",
		},
		{
			name: "confirm selected IP mismatch",
			mutate: func(s *FlowState, c *protocol.UDPTargetConfirm) {
				c.SelectedIP = []byte{198, 51, 100, 1}
			},
			wantError: "does not match IP-authoritative flow target",
		},
		{
			name: "DNS answer hash mismatch with 48-byte state hash",
			mutate: func(s *FlowState, c *protocol.UDPTargetConfirm) {
				c.DNSAnswerSetHash = fb(0xcc, 48) // != state's fb(0xbb, 48)
			},
			wantError: "DNS answer hash mismatch",
		},
		{
			name:   "matching confirm returns nil",
			mutate: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := ipAuthoritativeFlowStateForCoverage()
			confirm := matchingUDPConfirmForCoverage()
			if tc.mutate != nil {
				tc.mutate(&state, &confirm)
			}
			err := validateUDPConfirmAgainstFlow(state, confirm)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("%s: expected nil, got %v", tc.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantError)
			}
		})
	}
}

// validUDPConfirmForCoverage returns a UDPTargetConfirm that passes
// ValidateUDPTargetConfirm and round-trips through NewUDPTargetConfirmFrame /
// decodeUDPTargetConfirmFrame. Mirrors the fixture at flow_test.go:84.
func validUDPConfirmForCoverage() protocol.UDPTargetConfirm {
	return protocol.UDPTargetConfirm{
		FlowID:           19,
		TargetKind:       TargetKindIPv4,
		SelectedIP:       []byte{203, 0, 113, 19},
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0xbb, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	}
}

// validFlowCloseForCoverage returns a FlowClose that passes ValidateFlowClose
// and round-trips through NewFlowCloseFrame / decodeFlowCloseFrame.
func validFlowCloseForCoverage() protocol.FlowClose {
	return protocol.FlowClose{FlowID: 23, CloseCode: protocol.CloseNormal}
}

// ipAuthoritativeFlowStateForCoverage returns a FlowState in an IP-authoritative
// UDP FQDN mode with an IPv4 target, so validateUDPConfirmAgainstFlow proceeds
// past the two early-return nil guards to the match/DNS-hash checks.
func ipAuthoritativeFlowStateForCoverage() FlowState {
	return FlowState{
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 7},
		TargetPort:       443,
		DNSAnswerSetHash: fb(0xbb, 48),
	}
}

// matchingUDPConfirmForCoverage returns a UDPTargetConfirm that matches the
// ipAuthoritativeFlowStateForCoverage target exactly (kind, IP, port, DNS hash),
// so the happy path returns nil.
func matchingUDPConfirmForCoverage() protocol.UDPTargetConfirm {
	return protocol.UDPTargetConfirm{
		TargetKind:       TargetKindIPv4,
		SelectedIP:       []byte{203, 0, 113, 7},
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0xbb, 48),
	}
}
