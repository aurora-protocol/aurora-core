package protocol

// Adversarial coverage for the pure frame validators, EncodedLen guards,
// control-frame dispatch, and frame constructors in protocol/frames.go that
// the existing frames_test.go / frames_direction_coverage_test.go suites reach
// only partially or not at all.
//
// The existing tests exercise the round-trip encoders, the happy constructors,
// and a handful of rejection cases (version, zero flow_id, reserved flow_kind,
// reserved target_kind, two domain-target errors, IPv4/IPv6 confirm target
// length, reserved/target_kind confirm, TTL/resolution-source confirm, reserved
// close code, route-forward malformed payload). The count-0 map shows many
// individual decision branches inside the validators stay uncovered because the
// existing tests drive them only indirectly through ValidateFrameBlock and never
// perturb the specific field that fires the branch. This file calls the
// validators directly (white-box: unexported validateFlowOpenDomainTarget,
// cloneExtensions, validateAuthorityLocator are all reachable from this
// package) with crafted inputs, perturbing exactly one field per case so the
// target branch is the one that fires.
//
// Uncovered blocks (measured count 0 before this file):
//   - AuroraFrame.EncodedLen (line 20, 75%): payload>0xffffff, VarintLen err.
//   - FrameBlock.EncodedLen (line 59, 75%): a contained frame whose EncodedLen
//     returns false (payload>0xffffff).
//   - DecodeFrameBlock (line 92, 91.7%): trailing bytes after a valid block.
//   - ValidateFrameType (line 174, 85.7%): the reserved-range (<=0x6fff) default.
//   - newDataFrame (line 217, 75%): ValidateDataFrame error propagation.
//   - ValidateKeyUpdateFrame (line 336, 71.4%): the r.Err and trailing-bytes
//     branches for all three control types (KEY_UPDATE / ACK / REQUEST).
//   - ValidateKeyUpdateACK (line 381, 66.7%) / ValidateKeyUpdateRequest (line
//     388, 66.7%): the happy-path return nil (the existing suite only exercises
//     the reserved-direction error via the frame-block path).
//   - ValidateFlowOpen (line 445, 66.7%): IPv4/IPv6 host length, reserved
//     udp_fqdn_mode, name_binding_id length, DNS answer hash length, reserved
//     local_binding_mode, reserved priority_class, extension propagation.
//   - validateFlowOpenDomainTarget (line 500, 60.7%): empty, >253, digit label,
//     hyphen-starts-label, valid hyphen, empty-label-after-dot, dot-after-hyphen,
//     label>63, ends-with-hyphen.
//   - ValidateFlowManagementFrame (line 634, 87.5%): UDPTargetConfirm error
//     propagation, r.Err on a truncated FLOW_CLOSE, flow_id mismatch.
//   - ValidateUDPTargetConfirm (line 682, 76.5%): zero flow_id, IPv6 target
//     length, extension propagation.
//   - ValidateFlowClose (line 719, 85.7%): extension propagation.
//   - NewUDPTargetConfirmFrame (line 735, 72.7%) / NewFlowOpenFrame (line 756,
//     70%) / NewFlowCloseFrame (line 776, 70%): the validate-error and
//     encode-error returns.
//   - cloneExtensions (line 805, 28.6%): the non-empty clone path.
//   - ValidateRouteFrame (line 852, 88.9%): r.Err on a truncated ROUTE_FORWARD.
//   - ValidateRouteForwardFrame (line 869, 41.2%): next/prev hash length, routing
//     record id length, IPv4/IPv6 locator length, opaque-empty locator, happy
//     return nil.
//   - validateAuthorityLocator (line 902, 41.7%): trailing bytes, empty name,
//     zero port, happy return nil.
//
// Dead-by-design / not-contrived (documented, not covered):
//   - addEncodedLength overflow (lines 86-88) and the EncodedLen int-overflow
//     returns it guards (AuroraFrame.EncodedLen 32-34, FrameBlock.EncodedLen
//     71-73). addEncodedLength rejects a total that would exceed the platform
//     int max, but every constructible frame/block has a total wire length far
//     below int max (payloads are bounded by the 0xffffff opaque-24 limit and
//     varint lengths are bounded by MaxVarint), so the overflow is unreachable.
//   - FrameBlock.EncodedLen VarintLen(len(Frames)) (61-63): needs a slice with
//     more than MaxVarint (1<<62 - 1) elements, which no constructible Go slice
//     can have.
//   - validateFlowOpenDomainTarget final empty-label (538-540): the loop ends
//     with labelLen == 0 only when the host ends with '.', but a trailing dot is
//     rejected at line 507 before the loop runs, so the post-loop empty check is
//     unreachable.
//   - ValidateFlowManagementFrame outer ValidateExtensions error (673-675): all
//     three per-type validators (ValidateFlowOpen, ValidateUDPTargetConfirm,
//     ValidateFlowClose) already call ValidateExtensions(extensions, nil) with
//     the same nil known map, so a bad extension set is always rejected inside
//     the per-type validator (returning at 645/651/670) before the outer call at
//     673 runs. The outer call is a defensive re-check that no constructible
//     valid-payload frame can trip.
//   - NewUDPTargetConfirmFrame (750-752), NewFlowOpenFrame (770-772),
//     NewFlowCloseFrame (790-792): the post-encode ValidateFlowManagementFrame
//     re-check. A frame built from a struct that passed its own validator and was
//     just encoded round-trips cleanly (Decode matches Encode, flow_id matches,
//     extensions already validated), so the re-check never fails.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). Each rejection case asserts exactly one error so the
// failure is attributable to the perturbed field alone. New helpers are each
// referenced by >=2 tests so there is no U1000. No context.Context, no deprecated
// APIs.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

// covMaxVarint is ^uint64(0), which exceeds wire.MaxVarint (1<<62 - 1) and so
// forces VarintLen / WriteVarint to fail. Used by the AuroraFrame.EncodedLen
// varint-err case and by the three New*Frame encode-error cases, so it is not
// U1000.
const covMaxVarint uint64 = ^uint64(0)

// badCriticalExtension returns an Extension that ValidateExtensions rejects: a
// critical extension whose type is absent from the (nil) known map. Used by the
// ValidateFlowOpen, ValidateUDPTargetConfirm, and ValidateFlowClose extension
// cases, so it is not U1000.
func badCriticalExtension() Extension {
	return Extension{ExtensionType: 0x9999, Critical: true, Body: []byte("x")}
}

// validFlowOpenForCoverage returns a FlowOpen that passes ValidateFlowOpen
// (IPv4 target, 4-byte host, 16-byte name binding id, 48-byte DNS hash, all
// reserved fields in range, no extensions). Used as the base for the
// ValidateFlowOpen perturbation table, the NewFlowOpenFrame encode-error case,
// and the ValidateFlowManagementFrame flow_id-mismatch case, so it is not U1000.
func validFlowOpenForCoverage() FlowOpen {
	return FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           21,
		FlowKind:         0x01,
		TargetKind:       0x01,
		TargetHost:       []byte{93, 184, 216, 34},
		TargetPort:       443,
		UDPFQDNMode:      0x00,
		NameBindingID:    fill(0x01, 16),
		DNSAnswerSetHash: fill(0x02, 48),
		LocalBindingMode: 0x00,
		PriorityClass:    0x01,
	}
}

// validUDPTargetConfirmForCoverage returns a UDPTargetConfirm that passes
// ValidateUDPTargetConfirm. Used as the base for the ValidateUDPTargetConfirm
// perturbation table and the NewUDPTargetConfirmFrame encode-error case, so it
// is not U1000.
func validUDPTargetConfirmForCoverage() UDPTargetConfirm {
	return UDPTargetConfirm{
		FlowID:           10,
		TargetKind:       0x01,
		SelectedIP:       []byte{203, 0, 113, 10},
		SelectedPort:     443,
		DNSAnswerSetHash: fill(0xcc, 48),
		TTLSeconds:       300,
		ResolutionSource: UDPResolutionRelayRecursiveDNS,
	}
}

// validFlowCloseForCoverage returns a FlowClose that passes ValidateFlowClose.
// Used as the base for the ValidateFlowClose perturbation table and the
// NewFlowCloseFrame encode-error case, so it is not U1000.
func validFlowCloseForCoverage() FlowClose {
	return FlowClose{
		FlowID:    13,
		CloseCode: CloseNormal,
	}
}

// validRouteForwardForCoverage returns a RouteForwardFrame that passes
// ValidateRouteForwardFrame (48/48/16-byte fixed fields, an IPv4-port locator of
// exactly 6 bytes, a non-empty prelude). Used as the base for the
// ValidateRouteForwardFrame perturbation table and the ValidateRouteFrame
// truncated-payload case, so it is not U1000.
func validRouteForwardForCoverage() RouteForwardFrame {
	return RouteForwardFrame{
		RouteInstanceID:                1,
		HopIndex:                       0,
		NextRelayDescriptorHash:        fill(0x21, 48),
		PreviousHopRelayDescriptorHash: fill(0x22, 48),
		NextRelayRoutingRecordID:       fill(0x23, 16),
		NextRelayLocatorType:           registry.LocatorIPv4Port,
		NextRelayLocator:               []byte{203, 0, 113, 9, 0x01, 0xbb},
		OpaqueNextHopPrelude:           []byte("prelude"),
	}
}

func TestAuroraFrameEncodedLenDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name   string
		frame  AuroraFrame
		wantOK bool
	}{
		{"payload exceeds 24-bit limit", AuroraFrame{FrameType: registry.FrameStreamData, Payload: make([]byte, 0x1000000)}, false},
		{"flow id varint overflow", AuroraFrame{FrameType: registry.FrameStreamData, FlowID: covMaxVarint, Payload: []byte("x")}, false},
		{"valid frame length", AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte("x")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := tc.frame.EncodedLen()
			if ok != tc.wantOK {
				t.Fatalf("%s: EncodedLen ok = %v, want %v", tc.name, ok, tc.wantOK)
			}
		})
	}
}

func TestFrameBlockEncodedLenRejectsUnencodableFrame(t *testing.T) {
	// A contained frame whose own EncodedLen returns false (payload>0xffffff)
	// propagates as (0, false) from FrameBlock.EncodedLen at 66-68.
	block := FrameBlock{Frames: []AuroraFrame{{FrameType: registry.FrameStreamData, Payload: make([]byte, 0x1000000)}}}
	if _, ok := block.EncodedLen(); ok {
		t.Fatal("FrameBlock.EncodedLen accepted a frame with an oversized payload, want false")
	}
}

func TestDecodeFrameBlockRejectsTrailingBytes(t *testing.T) {
	encoded, err := Encode(FrameBlock{Frames: []AuroraFrame{{FrameType: registry.FrameStreamData, FlowID: 1, Payload: []byte("x")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFrameBlock(append(encoded, 0xff)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("DecodeFrameBlock err = %v, want trailing-bytes error", err)
	}
}

func TestValidateFrameTypeRejectsReservedRange(t *testing.T) {
	// 0x20 is not a known frame type and is <= 0x6fff, so it hits the reserved
	// default at 195-197 (the 0x7f00-0x7fff lab-only default is already covered).
	if err := ValidateFrameType(0x20); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("ValidateFrameType(0x20) err = %v, want reserved-range error", err)
	}
}

func TestNewDataFrameRejectsInvalidDataFrame(t *testing.T) {
	// A stream data frame with a zero flow_id fails ValidateDataFrame inside
	// newDataFrame, returning (AuroraFrame{}, err) at 224-226.
	if _, err := NewStreamDataFrame(0, []byte("x"), 0); err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("NewStreamDataFrame(0, ...) err = %v, want zero flow_id", err)
	}
}

func TestValidateKeyUpdateFrameDecidesPerCondition(t *testing.T) {
	validUpdate := KeyUpdate{RouteInstanceID: 7, HopLayer: 1, Direction: 0, OldKeyPhase: 1, NewKeyPhase: 2, UpdateNonce: fill(0x11, 16), UpdateReason: 1}
	validACK := KeyUpdateACK{RouteInstanceID: 7, HopLayer: 1, AckedDirection: 0, AckedKeyPhase: 2, AckNonce: fill(0x44, 16)}
	validReq := KeyUpdateRequest{RouteInstanceID: 10, HopLayer: 2, RequestedDirection: 0, RequestNonce: fill(0x55, 16), RequestReason: 3}

	validUpdatePayload, err := Encode(validUpdate)
	if err != nil {
		t.Fatal(err)
	}
	validACKPayload, err := Encode(validACK)
	if err != nil {
		t.Fatal(err)
	}
	validReqPayload, err := Encode(validReq)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		frame   AuroraFrame
		wantSub string
	}{
		{"key update truncated", AuroraFrame{FrameType: registry.FrameKeyUpdate, Payload: nil}, ""},
		{"key update trailing", AuroraFrame{FrameType: registry.FrameKeyUpdate, Payload: append(validUpdatePayload, 0xff)}, "trailing KEY_UPDATE"},
		{"key update ack truncated", AuroraFrame{FrameType: registry.FrameKeyUpdateAck, Payload: nil}, ""},
		{"key update ack trailing", AuroraFrame{FrameType: registry.FrameKeyUpdateAck, Payload: append(validACKPayload, 0xff)}, "trailing KEY_UPDATE_ACK"},
		{"key update request truncated", AuroraFrame{FrameType: registry.FrameKeyUpdateRequest, Payload: nil}, ""},
		{"key update request trailing", AuroraFrame{FrameType: registry.FrameKeyUpdateRequest, Payload: append(validReqPayload, 0xff)}, "trailing KEY_UPDATE_REQUEST"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKeyUpdateFrame(tc.frame)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want substring %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestValidateKeyUpdateACKAndRequestAcceptValid(t *testing.T) {
	// The happy-path return nil of ValidateKeyUpdateACK (385) and
	// ValidateKeyUpdateRequest (392) is never reached by the existing suite,
	// which only drives the reserved-direction errors. A direction of 0 is
	// valid for both.
	if err := ValidateKeyUpdateACK(KeyUpdateACK{AckedDirection: 0}); err != nil {
		t.Fatalf("ValidateKeyUpdateACK(valid) err = %v, want nil", err)
	}
	if err := ValidateKeyUpdateRequest(KeyUpdateRequest{RequestedDirection: 0}); err != nil {
		t.Fatalf("ValidateKeyUpdateRequest(valid) err = %v, want nil", err)
	}
}

func TestValidateFlowOpenDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*FlowOpen)
		wantSub string
	}{
		{"IPv4 target wrong length", func(o *FlowOpen) { o.TargetHost = []byte{1, 2, 3} }, "IPv4 target must be 4 bytes"},
		{"IPv6 target wrong length", func(o *FlowOpen) { o.TargetKind = 0x02; o.TargetHost = fill(0x06, 15) }, "IPv6 target must be 16 bytes"},
		{"reserved udp_fqdn_mode", func(o *FlowOpen) { o.UDPFQDNMode = 0x04 }, "reserved udp_fqdn_mode"},
		{"name binding id wrong length", func(o *FlowOpen) { o.NameBindingID = fill(0x01, 15) }, "name_binding_id must be 16 bytes"},
		{"DNS answer hash wrong length", func(o *FlowOpen) { o.DNSAnswerSetHash = fill(0x02, 47) }, "DNS answer hash must be 48 bytes"},
		{"reserved local_binding_mode", func(o *FlowOpen) { o.LocalBindingMode = 0x04 }, "reserved local_binding_mode"},
		{"reserved priority_class", func(o *FlowOpen) { o.PriorityClass = 0x04 }, "reserved priority_class"},
		{"unknown critical extension", func(o *FlowOpen) { o.Extensions = []Extension{badCriticalExtension()} }, "unknown critical extension"},
		{"valid flow open accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			open := validFlowOpenForCoverage()
			if tc.mutate != nil {
				tc.mutate(&open)
			}
			err := ValidateFlowOpen(open)
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

func TestValidateFlowOpenDomainTargetDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		host    []byte
		wantSub string
	}{
		{"empty", []byte(""), "domain target is empty"},
		{"exceeds 253 bytes", fill(0x61, 254), "exceeds 253 bytes"},
		{"digit label", []byte("a1.example.com"), ""},
		{"label starts with hyphen", []byte("-bad"), "starts with hyphen"},
		{"valid hyphen in label", []byte("a-b.example.com"), ""},
		{"empty label after dot", []byte("a..b"), "empty label"},
		{"dot after hyphen", []byte("a-.b"), "ends with hyphen"},
		{"label exceeds 63 bytes", append(fill(0x61, 64), []byte(".com")...), "exceeds 63 bytes"},
		{"ends with hyphen", []byte("ab-"), "ends with hyphen"},
		{"valid domain", []byte("example.com"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFlowOpenDomainTarget(tc.host)
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

func TestValidateFlowManagementFrameDecidesPerCondition(t *testing.T) {
	// ValidateUDPTargetConfirm error propagation (651-653): an encoded confirm
	// with a zero flow_id is decoded and rejected by ValidateUDPTargetConfirm
	// before the flow_id-match check at 676 runs.
	badConfirm, err := Encode(UDPTargetConfirm{FlowID: 0, TargetKind: 0x01, SelectedIP: []byte{1, 2, 3, 4}, DNSAnswerSetHash: fill(0xcc, 48), TTLSeconds: 60, ResolutionSource: UDPResolutionClientSuppliedIP})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFlowManagementFrame(AuroraFrame{FrameType: registry.FrameUDPTargetConfirm, FlowID: 0, Payload: badConfirm}); err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("UDPTargetConfirm propagation err = %v, want zero flow_id", err)
	}

	// r.Err on a truncated FLOW_CLOSE (662-664). FLOW_CLOSE is the only
	// management type whose per-type arm does not run a validator before the
	// shared r.Err check, so a truncated payload reaches 662 directly.
	if err := ValidateFlowManagementFrame(AuroraFrame{FrameType: registry.FrameFlowClose, FlowID: 13, Payload: nil}); err == nil {
		t.Fatal("truncated FLOW_CLOSE err = nil, want error")
	}

	// flow_id mismatch (676-678): a valid FlowOpen whose payload flow_id differs
	// from the frame flow_id.
	openPayload, err := Encode(validFlowOpenForCoverage())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFlowManagementFrame(AuroraFrame{FrameType: registry.FrameFlowOpen, FlowID: 99, Payload: openPayload}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("flow_id mismatch err = %v, want does-not-match", err)
	}
}

func TestValidateUDPTargetConfirmDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*UDPTargetConfirm)
		wantSub string
	}{
		{"zero flow_id", func(c *UDPTargetConfirm) { c.FlowID = 0 }, "zero flow_id"},
		{"IPv6 target wrong length", func(c *UDPTargetConfirm) { c.TargetKind = 0x02; c.SelectedIP = fill(0x06, 15) }, "IPv6 target must be 16 bytes"},
		{"unknown critical extension", func(c *UDPTargetConfirm) { c.Extensions = []Extension{badCriticalExtension()} }, "unknown critical extension"},
		{"valid confirm accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			confirm := validUDPTargetConfirmForCoverage()
			if tc.mutate != nil {
				tc.mutate(&confirm)
			}
			err := ValidateUDPTargetConfirm(confirm)
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

func TestValidateFlowCloseRejectsUnknownCriticalExtension(t *testing.T) {
	close := validFlowCloseForCoverage()
	close.Extensions = []Extension{badCriticalExtension()}
	if err := ValidateFlowClose(close); err == nil || !strings.Contains(err.Error(), "unknown critical extension") {
		t.Fatalf("ValidateFlowClose(bad ext) err = %v, want unknown critical extension", err)
	}
}

func TestNewUDPTargetConfirmFrameDecidesPerCondition(t *testing.T) {
	// ValidateUDPTargetConfirm error (736-738).
	bad := validUDPTargetConfirmForCoverage()
	bad.FlowID = 0
	if _, err := NewUDPTargetConfirmFrame(bad); err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("NewUDPTargetConfirmFrame(bad) err = %v, want zero flow_id", err)
	}

	// Encode error (742-744): a confirm that passes validation but whose FlowID
	// overflows the varint encoder.
	overflow := validUDPTargetConfirmForCoverage()
	overflow.FlowID = covMaxVarint
	if _, err := NewUDPTargetConfirmFrame(overflow); err == nil {
		t.Fatal("NewUDPTargetConfirmFrame(varint-overflow) err = nil, want encode error")
	}
}

func TestNewFlowOpenFrameDecidesPerCondition(t *testing.T) {
	// ValidateFlowOpen error (757-759).
	bad := validFlowOpenForCoverage()
	bad.FlowOpenVersion = 0
	if _, err := NewFlowOpenFrame(bad); err == nil || !strings.Contains(err.Error(), "unsupported flow_open_version") {
		t.Fatalf("NewFlowOpenFrame(bad) err = %v, want unsupported flow_open_version", err)
	}

	// Encode error (762-764): a flow open that passes validation but whose
	// FlowID overflows the varint encoder.
	overflow := validFlowOpenForCoverage()
	overflow.FlowID = covMaxVarint
	if _, err := NewFlowOpenFrame(overflow); err == nil {
		t.Fatal("NewFlowOpenFrame(varint-overflow) err = nil, want encode error")
	}
}

func TestNewFlowCloseFrameDecidesPerCondition(t *testing.T) {
	// ValidateFlowClose error (777-779).
	bad := validFlowCloseForCoverage()
	bad.FlowID = 0
	if _, err := NewFlowCloseFrame(bad); err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("NewFlowCloseFrame(bad) err = %v, want zero flow_id", err)
	}

	// Encode error (782-784): a close that passes validation but whose FlowID
	// overflows the varint encoder.
	overflow := validFlowCloseForCoverage()
	overflow.FlowID = covMaxVarint
	if _, err := NewFlowCloseFrame(overflow); err == nil {
		t.Fatal("NewFlowCloseFrame(varint-overflow) err = nil, want encode error")
	}
}

func TestCloneExtensionsDeepCopiesBodies(t *testing.T) {
	// cloneExtensions (805) non-empty path: the loop body (809-813) and the
	// return (814) are both uncovered. Verify the clone deep-copies each Body so
	// mutating the original does not affect the clone.
	original := []Extension{{ExtensionType: 0x01, Critical: false, Body: []byte("abc")}, {ExtensionType: 0x02, Critical: true, Body: []byte("de")}}
	cloned := cloneExtensions(original)
	if len(cloned) != len(original) {
		t.Fatalf("cloneExtensions len = %d, want %d", len(cloned), len(original))
	}
	original[0].Body[0] = 'Z'
	original[1].Body = nil
	if string(cloned[0].Body) != "abc" {
		t.Fatalf("cloneExtensions shallow-copied Body[0]: %q", cloned[0].Body)
	}
	if string(cloned[1].Body) != "de" {
		t.Fatalf("cloneExtensions shallow-copied Body[1]: %q", cloned[1].Body)
	}
	if cloned[0].Critical != false || cloned[1].Critical != true {
		t.Fatalf("cloneExtensions lost critical flags: %+v", cloned)
	}
}

func TestValidateRouteFrameRejectsTruncatedRouteForward(t *testing.T) {
	// r.Err on a truncated ROUTE_FORWARD (857-859). Encode a valid forward and
	// cut it mid-field so DecodeRouteForwardFrame's fixed pre-hash read fails.
	encoded, err := Encode(validRouteForwardForCoverage())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRouteFrame(AuroraFrame{FrameType: registry.FrameRouteForward, Payload: encoded[:6]}); err == nil {
		t.Fatal("ValidateRouteFrame(truncated) err = nil, want error")
	}
}

func TestValidateRouteForwardFrameDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RouteForwardFrame)
		wantSub string
	}{
		{"next relay hash wrong length", func(f *RouteForwardFrame) { f.NextRelayDescriptorHash = fill(0x21, 47) }, "next relay descriptor hash must be 48 bytes"},
		{"previous hop hash wrong length", func(f *RouteForwardFrame) { f.PreviousHopRelayDescriptorHash = fill(0x22, 47) }, "previous hop descriptor hash must be 48 bytes"},
		{"routing record id wrong length", func(f *RouteForwardFrame) { f.NextRelayRoutingRecordID = fill(0x23, 15) }, "routing record id must be 16 bytes"},
		{"IPv4 locator wrong length", func(f *RouteForwardFrame) { f.NextRelayLocator = []byte{1, 2, 3, 4, 5} }, "IPv4 locator must be 6 bytes"},
		{"IPv6 locator wrong length", func(f *RouteForwardFrame) {
			f.NextRelayLocatorType = registry.LocatorIPv6Port
			f.NextRelayLocator = fill(0x06, 17)
		}, "IPv6 locator must be 18 bytes"},
		{"opaque locator empty", func(f *RouteForwardFrame) { f.NextRelayLocatorType = registry.LocatorOpaque; f.NextRelayLocator = nil }, "locator is empty"},
		{"valid route forward accepted", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forward := validRouteForwardForCoverage()
			if tc.mutate != nil {
				tc.mutate(&forward)
			}
			err := ValidateRouteForwardFrame(forward)
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

func TestValidateAuthorityLocatorDecidesPerCondition(t *testing.T) {
	cases := []struct {
		name     string
		locator  []byte
		wantSub  string
		wantNone bool
	}{
		{"trailing bytes", append(routeAuthorityLocatorForTest(t, "example.com", 443), 0xff), "trailing", false},
		{"empty name", routeAuthorityLocatorForTest(t, "", 443), "name is empty", false},
		{"zero port", routeAuthorityLocatorForTest(t, "example.com", 0), "port is zero", false},
		{"valid authority", routeAuthorityLocatorForTest(t, "example.com", 443), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuthorityLocator(tc.locator)
			if tc.wantNone {
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
