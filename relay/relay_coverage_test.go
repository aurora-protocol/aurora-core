package relay

// Adversarial coverage for the residual count-0 branches in relay/relay.go.
// The gateway dispatch surface (HandleFailure / HandleCoverRequest / handle*
// / forwardVerbatim / failureOrDefault / findRequestClass / StaticOrigin) is
// already covered adversarially by relay_gateway_coverage_test.go, and the
// happy exit-flow paths (open/stream/datagram/close round-trips, UDP target
// confirm, rate-limit trip, BlindRSA + VOPRF verifier-service admission) are
// exercised end-to-end by relay_test.go. This file targets only the branches
// those tests leave cold, perturbing exactly one condition per case so the
// branch under test is the one that fires. Each rejection asserts exactly one
// error substring so the failure is attributable to the perturbed field alone.
//
// Uncovered blocks (measured count 0 before this file) and their disposition:
//   - RunGatewayActiveProbeHarness: empty-cases guard 205.
//   - gatewayProbeOrigin: ForwardRequest 266, ForwardSidecarRequest 271,
//     RecordSidecarFailure 276 (the active-probe harness only drives a
//     gateway-owned capsule slot, so these forwarding methods are never called
//     through it).
//   - HandleFrameBlock: FlowOpen err propagation 463, FlowClose err
//     propagation 483, default "unsupported exit frame type" 489.
//   - HandleFlowOpenFrame: non-FLOW_OPEN frame type 498, duplicate flow_id
//     508, OpenWithOptions error 523.
//   - handleDataFrame: DNS-message rate-limit error 530 and success 534,
//     data-for-closed-flow 547, STREAM_DATA byte rate-limit error 552, UDP
//     stream-fallback unavailable 558, STREAM_DATA for non-stream flow 561,
//     DATAGRAM_DATA unavailable 577.
//   - handleFlowCloseFrame: non-FLOW_CLOSE frame type 593,
//     ValidateFlowManagementFrame error 596.
//   - ensure: nil flows 626, zero TTL 629, zero rate limit 632.
//   - consumeRateLimit: zero WindowSeconds default 639.
//   - checkExitPolicy: malformed IP target 663.
//   - confirmFramesForOpen: NewUDPTargetConfirmFrame encode error 693.
//   - effectiveUDPConfirmTTLSeconds: zero TTL default 701.
//   - cloneProtocolExtensions: non-empty extension path 741/742/746.
//   - addrFromFlowTarget: IPv4 wrong length 752, IPv6 wrong length 756/757,
//     IPv6 valid 760, default 766.
//   - AllowsVerifierServiceAdmission: ValidateStructural error 847, non-VOPRF
//     proof 850, selectVOPRFVerifierService error 854, nil transport 857,
//     matches != 1 895.
//
// Dead by design (documented, not contrived):
//   - Gateway.HandleFailure 98-100 (classification.Action != CoverOrigin).
//     failure.Classify hardcodes Action: CoverOrigin for every Kind, so the
//     non-cover-origin branch is unreachable. Already documented in
//     relay_gateway_coverage_test.go; only the nil-Origin guard is exercised.
//   - HandleFlowOpenFrame confirmFramesForOpen error 512. After
//     ValidateFlowManagementFrame (501) the open is protocol-valid; for a UDP
//     IPv4/IPv6 target confirmFramesForOpen builds a UDPTargetConfirm whose
//     every field is protocol-valid (FlowID <= wire.MaxVarint because it came
//     from a decoded varint, SelectedIP 4/16 bytes, DNSAnswerSetHash 48 bytes,
//     TTLSeconds <= 86400 capped by effectiveUDPConfirmTTLSeconds, valid
//     ResolutionSource). NewUDPTargetConfirmFrame -> ValidateUDPTargetConfirm
//     passes and Encode writes only in-range varints/opaques, so no error
//     reaches 512 via the exported entry point. (The 693 return inside
//     confirmFramesForOpen is reachable via a direct in-package call with an
//     out-of-range FlowID that bypasses the decoded-frame constraint.)
//   - handleDataFrame default 587 "unsupported data frame type". handleDataFrame
//     is only called from HandleFrameBlock (476) which routes only
//     FrameStreamData/FrameDatagramData/FrameDNSMessage; the FrameDNSMessage
//     branch (530) returns before the line-550 switch, so that switch only sees
//     FrameStreamData/FrameDatagramData. The default needs a frame type routed
//     to handleDataFrame that is not one of those, which is impossible.
//   - handleFlowCloseFrame r.Err() 601 and trailing-bytes 604.
//     ValidateFlowManagementFrame (596) already fully decodes the FrameFlowClose
//     payload, checks r.Err(), and checks !r.EOF(); handleFlowCloseFrame
//     re-decodes the identical payload with a fresh reader, so r.Err() is
//     necessarily nil and r.EOF() necessarily true when 596 passed.
//   - AllowsProof ProofLabStaticToken 839 and default 841. AllowsProof calls
//     proof.ValidateStructural(now, false) (821); with allowLab=false that
//     rejects ProofLabStaticToken ("lab admission proof disabled") and with
//     allowPrivate=false rejects ProofOpaqueIssuer, and the default rejects
//     every unknown type. Only ProofVOPRFP384SHA384 and ProofBlindRSA2048 pass,
//     both of which have explicit cases in the AllowsProof switch (824-837), so
//     the LabStatic case (839) and the default (841) are unreachable.
//
// Not duplicated: the gateway dispatch, happy exit-flow, and verifier-service
// admission success paths are covered by relay_test.go and
// relay_gateway_coverage_test.go and are not re-asserted here except for
// anchors that prove the error-case inputs are otherwise valid.
//
// Coverage is re-measured per target to confirm the intended branch moved (no
// wrong-branch bugs). The new helpers relayCovValidFlowOpen and
// relayCovCloseFrame are each referenced by >=2 tests, so they are not U1000.
// No context.Context, no goroutines, no deprecated APIs.

import (
	"math"
	"strings"
	"testing"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

// relayCovValidFlowOpen returns a FlowOpen that passes protocol.ValidateFlowOpen
// (and therefore ValidateFlowManagementFrame) for the given flow/target kind,
// with a small in-range flow id and the fixed-length fields at their required
// sizes. Each error-case test clones it and perturbs exactly one field. For
// UDP+IPv4 it also passes flow.validateOpen (no UDP-domain / fake-IP conflict).
// Referenced by >=2 tests, so not U1000.
func relayCovValidFlowOpen(flowID uint64, flowKind, targetKind uint8, target []byte) protocol.FlowOpen {
	return protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         flowKind,
		TargetKind:       targetKind,
		TargetHost:       append([]byte(nil), target...),
		TargetPort:       443,
		UDPFQDNMode:      coreflow.UDPFQDNNoneIPAuthoritative,
		NameBindingID:    bytesOf(0x11, 16),
		DNSAnswerSetHash: bytesOf(0x22, 48),
		LocalBindingMode: coreflow.LocalBindingExplicitProxyAPI,
		PriorityClass:    coreflow.PriorityInteractive,
	}
}

// relayCovCloseFrame encodes close and wraps it as a FrameFlowClose with the
// given frame-level FlowID (which may differ from close.FlowID to drive the
// mismatch path). Referenced by >=2 tests, so not U1000.
func relayCovCloseFrame(t *testing.T, close protocol.FlowClose, frameFlowID uint64) protocol.AuroraFrame {
	t.Helper()
	payload, err := protocol.Encode(close)
	if err != nil {
		t.Fatalf("encode close: %v", err)
	}
	return protocol.AuroraFrame{FrameType: registry.FrameFlowClose, FlowID: frameFlowID, Payload: payload}
}

func TestRunGatewayActiveProbeHarnessRejectsEmpty(t *testing.T) {
	// An empty case slice hits the 205 guard before any origin is constructed.
	if _, err := RunGatewayActiveProbeHarness(nil); err == nil || !strings.Contains(err.Error(), "no gateway active-probe cases") {
		t.Fatalf("err = %v, want %q", err, "no gateway active-probe cases")
	}
}

func TestGatewayProbeOriginForwardingMethods(t *testing.T) {
	// The active-probe harness drives only a gateway-owned capsule slot, so
	// the probe origin's forwarding/sidecar/failure-log methods are exercised
	// here by direct calls. Each bumps its own counter and returns its status.
	o := &gatewayProbeOrigin{normal: Response{Status: 200, Body: []byte("cover")}}
	t.Run("forward request", func(t *testing.T) {
		resp := o.ForwardRequest([]byte("body"))
		if resp.Status != 204 || o.forwardedRequests != 1 {
			t.Fatalf("ForwardRequest = %+v count=%d, want status 204 count 1", resp, o.forwardedRequests)
		}
	})
	t.Run("forward sidecar request", func(t *testing.T) {
		resp := o.ForwardSidecarRequest([]byte("body"))
		if resp.Status != 206 || o.sidecarForwardedRequests != 1 {
			t.Fatalf("ForwardSidecarRequest = %+v count=%d, want status 206 count 1", resp, o.sidecarForwardedRequests)
		}
	})
	t.Run("record sidecar failure", func(t *testing.T) {
		o.RecordSidecarFailure(RedactedFailureLog{Code: "denied", Body: []byte("x")})
		if o.failureLogs != 1 {
			t.Fatalf("RecordSidecarFailure count=%d, want 1", o.failureLogs)
		}
	})
}

func TestHandleFrameBlockPropagatesFrameErrors(t *testing.T) {
	t.Run("flow open policy denial", func(t *testing.T) {
		// A structurally-valid FLOW_OPEN to a loopback domain passes
		// ValidateFrameBlock (455) then fails checkExitPolicy in
		// HandleFlowOpenFrame; the error propagates at 463.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		open := relayTCPFlowOpen(40, "localhost")
		_, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}, 100)
		if err == nil || !strings.Contains(err.Error(), "exit policy denied domain target") {
			t.Fatalf("err = %v, want %q", err, "exit policy denied domain target")
		}
	})
	t.Run("flow close unknown flow", func(t *testing.T) {
		// A structurally-valid FLOW_CLOSE for a flow that was never opened
		// passes ValidateFrameBlock, then MarkPeerClose fails inside
		// handleFlowCloseFrame and propagates at 483 (and 607).
		handler := NewExitFlowHandler(DefaultExitPolicy())
		close := protocol.FlowClose{FlowID: 999, CloseCode: protocol.CloseNormal}
		_, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			relayCovCloseFrame(t, close, 999),
		}}, 100)
		if err == nil || !strings.Contains(err.Error(), "unknown flow_id") {
			t.Fatalf("err = %v, want %q", err, "unknown flow_id")
		}
	})
	t.Run("unsupported exit frame type", func(t *testing.T) {
		// 0x8000 passes ValidateFrameType (reserved-high range returns nil) and
		// the per-frame validators (each only inspects its own types), so it
		// reaches the HandleFrameBlock default at 489.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		_, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{
			{FrameType: 0x8000, FlowID: 1, Payload: bytesOf(0xaa, 2)},
		}}, 100)
		if err == nil || !strings.Contains(err.Error(), "unsupported exit frame type 0x8000") {
			t.Fatalf("err = %v, want %q", err, "unsupported exit frame type 0x8000")
		}
	})
}

func TestHandleFlowOpenFrameDecidesPerCondition(t *testing.T) {
	t.Run("non flow open frame type", func(t *testing.T) {
		// A STREAM_DATA frame handed to HandleFlowOpenFrame hits the 498 guard
		// before any decode.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		_, err := handler.HandleFlowOpenFrame(protocol.AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 1, Payload: bytesOf(0xaa, 4)}, 100)
		if err == nil || !strings.Contains(err.Error(), "expected FLOW_OPEN frame") {
			t.Fatalf("err = %v, want %q", err, "expected FLOW_OPEN frame")
		}
	})
	t.Run("duplicate flow id", func(t *testing.T) {
		// Opening the same flow_id twice hits the 508 guard before the second
		// open mutates state.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		first := relayTCPFlowOpen(50, "example.com")
		if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, first), 100); err != nil {
			t.Fatalf("first open: %v", err)
		}
		_, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, first), 101)
		if err == nil || !strings.Contains(err.Error(), "duplicate flow_id 50") {
			t.Fatalf("err = %v, want %q", err, "duplicate flow_id 50")
		}
	})
	t.Run("open with options rejects udp domain without fqdn mode", func(t *testing.T) {
		// A UDP flow to a domain with a non-relay-resolved FQDN mode passes
		// protocol.ValidateFlowOpen (UDPFQDNMode in range) but fails
		// flow.validateOpen inside OpenWithOptions at 523.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		open := relayCovValidFlowOpen(60, coreflow.FlowKindUDPAssociation, coreflow.TargetKindDomainName, []byte("example.com"))
		_, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100)
		if err == nil || !strings.Contains(err.Error(), "UDP domain targets require relay-resolved FQDN mode") {
			t.Fatalf("err = %v, want %q", err, "UDP domain targets require relay-resolved FQDN mode")
		}
	})
	t.Run("valid open anchor", func(t *testing.T) {
		// Anchor: a TCP flow to a public domain opens cleanly, proving the
		// error-case inputs are otherwise valid.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		out, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, relayTCPFlowOpen(61, "example.com")), 100)
		if err != nil || len(out) != 0 {
			t.Fatalf("valid open: err=%v out=%d, want nil err empty out", err, len(out))
		}
	})
}

func TestHandleDataFrameDecidesPerCondition(t *testing.T) {
	t.Run("dns message rate limit error", func(t *testing.T) {
		// A DNS message frame with a payload exceeding MaxBytes fails
		// consumeRateLimit inside the DNS branch at 530.
		handler := &ExitFlowHandler{Policy: DefaultExitPolicy(), RateLimit: ExitRateLimit{WindowSeconds: 60, MaxFlowOpens: 10, MaxBytes: 4}}
		handler.ensure()
		frame := protocol.AuroraFrame{FrameType: registry.FrameDNSMessage, FlowID: 70, Payload: bytesOf(0xaa, 16)}
		_, err := handler.handleDataFrame(frame, 100)
		if err == nil || !strings.Contains(err.Error(), "byte rate limit exceeded") {
			t.Fatalf("err = %v, want %q", err, "byte rate limit exceeded")
		}
	})
	t.Run("dns message success", func(t *testing.T) {
		// Anchor: a DNS message frame under the default rate limit produces a
		// DNS event, proving the error-case input is otherwise valid.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		frame := protocol.AuroraFrame{FrameType: registry.FrameDNSMessage, FlowID: 71, Payload: bytesOf(0xbb, 8)}
		event, err := handler.handleDataFrame(frame, 100)
		if err != nil || event.Kind != ExitEventDNSMessage || event.FlowID != 71 {
			t.Fatalf("dns event = %+v err=%v, want DNSMessage flow 71 nil err", event, err)
		}
	})
	t.Run("stream data for closed flow", func(t *testing.T) {
		// After a peer close, STREAM_DATA for the flow hits the 547 guard
		// before the rate-limit/datagram logic.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		open := relayTCPFlowOpen(72, "example.com")
		if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
			t.Fatal(err)
		}
		if err := handler.flows.MarkPeerClose(protocol.FlowClose{FlowID: 72, CloseCode: protocol.CloseNormal}, coreflow.CloseOptions{NowUnix: 100, DrainSeconds: 30}); err != nil {
			t.Fatal(err)
		}
		_, err := handler.handleDataFrame(protocol.AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 72, Payload: bytesOf(0xaa, 4)}, 100)
		if err == nil || !strings.Contains(err.Error(), "data for closed flow_id 72") {
			t.Fatalf("err = %v, want %q", err, "data for closed flow_id 72")
		}
	})
	t.Run("stream data byte rate limit error", func(t *testing.T) {
		// A STREAM_DATA frame whose payload exceeds MaxBytes fails
		// consumeRateLimit at 552 before the flow-kind switch.
		handler := &ExitFlowHandler{Policy: DefaultExitPolicy(), RateLimit: ExitRateLimit{WindowSeconds: 60, MaxFlowOpens: 10, MaxBytes: 4}}
		handler.ensure()
		open := relayTCPFlowOpen(73, "example.com")
		if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
			t.Fatal(err)
		}
		_, err := handler.handleDataFrame(protocol.AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 73, Payload: bytesOf(0xaa, 8)}, 100)
		if err == nil || !strings.Contains(err.Error(), "byte rate limit exceeded") {
			t.Fatalf("err = %v, want %q", err, "byte rate limit exceeded")
		}
	})
	t.Run("udp stream fallback unavailable", func(t *testing.T) {
		// STREAM_DATA on an expired UDP flow: consumeRateLimit passes, then
		// AcceptDatagramWithOptions returns false (expired) at 558.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		open := relayUDPFlowOpen(74, []byte{93, 184, 216, 34})
		if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
			t.Fatal(err)
		}
		_, err := handler.handleDataFrame(protocol.AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 74, Payload: bytesOf(0xaa, 4)}, 500)
		if err == nil || !strings.Contains(err.Error(), "UDP stream-fallback data for unavailable flow_id 74") {
			t.Fatalf("err = %v, want %q", err, "UDP stream-fallback data for unavailable flow_id 74")
		}
	})
	t.Run("stream data for non stream flow", func(t *testing.T) {
		// STREAM_DATA on a DNS-exchange flow: not UDP (555 false), not TCP
		// (561 true), so the 561 guard fires.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		open := relayCovValidFlowOpen(75, coreflow.FlowKindDNSExchange, coreflow.TargetKindDomainName, []byte("example.com"))
		if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
			t.Fatal(err)
		}
		_, err := handler.handleDataFrame(protocol.AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 75, Payload: bytesOf(0xaa, 4)}, 100)
		if err == nil || !strings.Contains(err.Error(), "STREAM_DATA for non-stream flow_id 75") {
			t.Fatalf("err = %v, want %q", err, "STREAM_DATA for non-stream flow_id 75")
		}
	})
	t.Run("datagram data unavailable", func(t *testing.T) {
		// DATAGRAM_DATA on an expired UDP flow: consumeRateLimit passes, then
		// AcceptDatagramWithOptions returns false (expired) at 577.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		open := relayUDPFlowOpen(76, []byte{93, 184, 216, 35})
		if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
			t.Fatal(err)
		}
		_, err := handler.handleDataFrame(protocol.AuroraFrame{FrameType: registry.FrameDatagramData, FlowID: 76, Payload: bytesOf(0xaa, 4)}, 500)
		if err == nil || !strings.Contains(err.Error(), "DATAGRAM_DATA for unavailable flow_id 76") {
			t.Fatalf("err = %v, want %q", err, "DATAGRAM_DATA for unavailable flow_id 76")
		}
	})
}

func TestHandleFlowCloseFrameDecidesPerCondition(t *testing.T) {
	t.Run("non flow close frame type", func(t *testing.T) {
		// A direct call with a non-FLOW_CLOSE frame hits the 593 guard.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		_, err := handler.handleFlowCloseFrame(protocol.AuroraFrame{FrameType: registry.FrameStreamData, FlowID: 1, Payload: bytesOf(0xaa, 4)}, 100)
		if err == nil || !strings.Contains(err.Error(), "expected FLOW_CLOSE frame") {
			t.Fatalf("err = %v, want %q", err, "expected FLOW_CLOSE frame")
		}
	})
	t.Run("validate flow management frame mismatch", func(t *testing.T) {
		// A FLOW_CLOSE whose payload flow_id differs from the frame flow_id
		// fails ValidateFlowManagementFrame at 596.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		close := protocol.FlowClose{FlowID: 5, CloseCode: protocol.CloseNormal}
		_, err := handler.handleFlowCloseFrame(relayCovCloseFrame(t, close, 1), 100)
		if err == nil || !strings.Contains(err.Error(), "frame flow_id 1 does not match payload flow_id 5") {
			t.Fatalf("err = %v, want %q", err, "frame flow_id 1 does not match payload flow_id 5")
		}
	})
	t.Run("mark peer close unknown flow", func(t *testing.T) {
		// A valid FLOW_CLOSE for a flow that was never opened passes 596/601/
		// 604 and fails MarkPeerClose at 607.
		handler := NewExitFlowHandler(DefaultExitPolicy())
		close := protocol.FlowClose{FlowID: 999, CloseCode: protocol.CloseNormal}
		_, err := handler.handleFlowCloseFrame(relayCovCloseFrame(t, close, 999), 100)
		if err == nil || !strings.Contains(err.Error(), "unknown flow_id 999") {
			t.Fatalf("err = %v, want %q", err, "unknown flow_id 999")
		}
	})
}

func TestExitFlowHandlerEnsureDefaultsEachGuard(t *testing.T) {
	t.Run("nil flows initialized", func(t *testing.T) {
		// flows nil but TTL + RateLimit preset so only the 626 guard fires.
		h := &ExitFlowHandler{Policy: DefaultExitPolicy(), UDPConfirmTTLSeconds: 300, RateLimit: DefaultExitRateLimit()}
		h.ensure()
		if h.flows == nil {
			t.Fatal("ensure did not initialize flows")
		}
	})
	t.Run("zero ttl defaulted", func(t *testing.T) {
		// flows preset, RateLimit preset, TTL zero so only the 629 guard fires.
		h := &ExitFlowHandler{Policy: DefaultExitPolicy(), flows: coreflow.NewManager(), RateLimit: DefaultExitRateLimit()}
		h.ensure()
		if h.UDPConfirmTTLSeconds != 300 {
			t.Fatalf("UDPConfirmTTLSeconds = %d, want 300", h.UDPConfirmTTLSeconds)
		}
	})
	t.Run("zero rate limit defaulted", func(t *testing.T) {
		// flows preset, TTL preset, RateLimit all-zero so only the 632 guard
		// fires.
		h := &ExitFlowHandler{Policy: DefaultExitPolicy(), flows: coreflow.NewManager(), UDPConfirmTTLSeconds: 300}
		h.ensure()
		if h.RateLimit != DefaultExitRateLimit() {
			t.Fatalf("RateLimit = %+v, want default", h.RateLimit)
		}
	})
}

func TestConsumeRateLimitDefaultsZeroWindowSeconds(t *testing.T) {
	// RateLimit.WindowSeconds == 0 with the other fields non-zero so ensure
	// does not reset it; consumeRateLimit then defaults WindowSeconds at 639.
	h := &ExitFlowHandler{Policy: DefaultExitPolicy(), UDPConfirmTTLSeconds: 300, RateLimit: ExitRateLimit{MaxFlowOpens: 10, MaxBytes: 1024}}
	h.ensure()
	if h.RateLimit.WindowSeconds != 0 {
		t.Fatalf("precondition: WindowSeconds = %d, want 0", h.RateLimit.WindowSeconds)
	}
	// A single flow-open within the limit must succeed (the zero WindowSeconds
	// is defaulted, not treated as "always reset").
	if err := h.consumeRateLimit(100, 1, 0); err != nil {
		t.Fatalf("consumeRateLimit with zero WindowSeconds: %v", err)
	}
}

func TestCheckExitPolicyAndAddrFromFlowTarget(t *testing.T) {
	handler := NewExitFlowHandler(DefaultExitPolicy())
	t.Run("malformed ip target", func(t *testing.T) {
		// Direct call: a 5-byte IPv4 target host fails addrFromFlowTarget at
		// 663. (HandleFlowOpenFrame cannot reach this: ValidateFlowOpen
		// enforces the 4-byte length first.)
		err := handler.checkExitPolicy(protocol.FlowOpen{TargetKind: coreflow.TargetKindIPv4, TargetHost: bytesOf(0x01, 5)})
		if err == nil || !strings.Contains(err.Error(), "malformed IP target") {
			t.Fatalf("err = %v, want %q", err, "malformed IP target")
		}
	})
	t.Run("addr ipv4 wrong length", func(t *testing.T) {
		if _, ok := addrFromFlowTarget(coreflow.TargetKindIPv4, bytesOf(0x01, 3)); ok {
			t.Fatal("addrFromFlowTarget(IPv4, 3 bytes) = ok, want false")
		}
	})
	t.Run("addr ipv6 wrong length", func(t *testing.T) {
		if _, ok := addrFromFlowTarget(coreflow.TargetKindIPv6, bytesOf(0x01, 15)); ok {
			t.Fatal("addrFromFlowTarget(IPv6, 15 bytes) = ok, want false")
		}
	})
	t.Run("addr ipv6 valid", func(t *testing.T) {
		addr, ok := addrFromFlowTarget(coreflow.TargetKindIPv6, bytesOf(0x01, 16))
		if !ok || !addr.Is6() {
			t.Fatalf("addrFromFlowTarget(IPv6, 16 bytes) = %v ok=%v, want ok IPv6", addr, ok)
		}
	})
	t.Run("addr unknown kind", func(t *testing.T) {
		if _, ok := addrFromFlowTarget(0x09, nil); ok {
			t.Fatal("addrFromFlowTarget(0x09, nil) = ok, want false")
		}
	})
}

func TestConfirmFramesForOpenAndTTLDefaults(t *testing.T) {
	t.Run("effective ttl defaults to 300", func(t *testing.T) {
		// A handler that never ran ensure exposes a zero TTL; the function
		// defaults it to 300 at 701.
		h := &ExitFlowHandler{Policy: DefaultExitPolicy()}
		if got := h.effectiveUDPConfirmTTLSeconds(); got != 300 {
			t.Fatalf("effectiveUDPConfirmTTLSeconds = %d, want 300", got)
		}
	})
	t.Run("confirm frames for open encode error", func(t *testing.T) {
		// Direct call: a UDP IPv4 open with an out-of-range flow id passes
		// ValidateUDPTargetConfirm (FlowID != 0) but fails Encode at 693 via
		// WriteVarint. This also drives the 701 TTL default (ensure is not
		// called by confirmFramesForOpen).
		h := &ExitFlowHandler{Policy: DefaultExitPolicy()}
		open := relayCovValidFlowOpen(math.MaxUint64, coreflow.FlowKindUDPAssociation, coreflow.TargetKindIPv4, []byte{93, 184, 216, 34})
		_, err := h.confirmFramesForOpen(open)
		if err == nil || !strings.Contains(err.Error(), "varint out of range") {
			t.Fatalf("err = %v, want %q", err, "varint out of range")
		}
	})
}

func TestCloneProtocolExtensionsViaFlowClose(t *testing.T) {
	// A FLOW_CLOSE carrying a non-critical extension, routed through
	// handleFlowCloseFrame for an open flow, returns successfully and clones
	// the extension list via cloneProtocolExtensions (741/742/746).
	handler := NewExitFlowHandler(DefaultExitPolicy())
	open := relayTCPFlowOpen(80, "example.com")
	if _, err := handler.HandleFlowOpenFrame(flowOpenFrame(t, open), 100); err != nil {
		t.Fatal(err)
	}
	close := protocol.FlowClose{
		FlowID:     80,
		CloseCode:  protocol.CloseNormal,
		Extensions: []protocol.Extension{{ExtensionType: 1, Critical: false, Body: []byte("ext")}},
	}
	event, err := handler.handleFlowCloseFrame(relayCovCloseFrame(t, close, 80), 100)
	if err != nil {
		t.Fatalf("close with extension: %v", err)
	}
	if len(event.Close.Extensions) != 1 || string(event.Close.Extensions[0].Body) != "ext" {
		t.Fatalf("cloned extensions = %+v, want one ext", event.Close.Extensions)
	}
}

func TestAdmissionPolicyAllowsVerifierServiceAdmissionDecidesPerCondition(t *testing.T) {
	t.Run("structural validation error", func(t *testing.T) {
		// An expired VOPRF proof fails ValidateStructural at 847 before the
		// proof-type or service checks.
		proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
		proof.ExpiryUnix = 20
		err := (AdmissionPolicy{NowUnix: 20}).AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{AdmissionProof: proof})
		if err == nil || !strings.Contains(err.Error(), "admission proof expired") {
			t.Fatalf("err = %v, want %q", err, "admission proof expired")
		}
	})
	t.Run("non voprf proof", func(t *testing.T) {
		// A Blind RSA proof passes ValidateStructural but is rejected at 850.
		proof := relayAdmissionProof(registry.ProofBlindRSA2048)
		err := (AdmissionPolicy{NowUnix: 20}).AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{AdmissionProof: proof})
		if err == nil || !strings.Contains(err.Error(), "verifier service admission requires VOPRF proof") {
			t.Fatalf("err = %v, want %q", err, "verifier service admission requires VOPRF proof")
		}
	})
	t.Run("no matching verifier service", func(t *testing.T) {
		// A valid VOPRF proof with no verifier services yields zero matches,
		// failing selectVOPRFVerifierService at 895 and propagating at 854.
		proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
		err := (AdmissionPolicy{NowUnix: 20, RequestAuth: map[uint64]bool{7: true}}).AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{AdmissionProof: proof})
		if err == nil || !strings.Contains(err.Error(), "exactly one authorized issuer verifier service") {
			t.Fatalf("err = %v, want %q", err, "exactly one authorized issuer verifier service")
		}
	})
	t.Run("two matching verifier services", func(t *testing.T) {
		// Two services both allowlisting the proof's bucket yield two matches,
		// also failing the matches != 1 guard at 895.
		proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
		s1, _ := relayVerifierService(t, proof.RelayBucketID)
		s2, _ := relayVerifierService(t, proof.RelayBucketID)
		err := (AdmissionPolicy{NowUnix: 20, VerifierServices: []protocol.IssuerVerifierServiceRecord{s1, s2}, RequestAuth: map[uint64]bool{7: true}}).AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{AdmissionProof: proof})
		if err == nil || !strings.Contains(err.Error(), "exactly one authorized issuer verifier service") {
			t.Fatalf("err = %v, want %q", err, "exactly one authorized issuer verifier service")
		}
	})
	t.Run("nil transport with one match", func(t *testing.T) {
		// Exactly one matching service but no transport: selectVOPRFVerifier
		// succeeds (854 ok), then the 857 nil-transport guard fires.
		proof := relayAdmissionProof(registry.ProofVOPRFP384SHA384)
		service, _ := relayVerifierService(t, proof.RelayBucketID)
		err := (AdmissionPolicy{
			NowUnix:          20,
			VerifierServices: []protocol.IssuerVerifierServiceRecord{service},
			RequestAuth:      map[uint64]bool{7: true},
		}).AllowsVerifierServiceAdmission(VerifierServiceAdmissionInput{AdmissionProof: proof})
		if err == nil || !strings.Contains(err.Error(), "VOPRF proof requires verifier service transport") {
			t.Fatalf("err = %v, want %q", err, "VOPRF proof requires verifier service transport")
		}
	})
}
