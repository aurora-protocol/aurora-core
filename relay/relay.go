package relay

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/failure"
	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/ops"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type FailureKind = failure.Kind

const (
	FailureBadAccessHint        = failure.BadAccessHint
	FailureReplayedHint         = failure.ReplayedAccessHint
	FailureBadAEADTag           = failure.BadAEADTag
	FailureWrongSuite           = failure.WrongSuite
	FailureMalformedFlowOpen    = failure.MalformedFlowOpen
	FailureMalformedKeyUpdate   = failure.MalformedKeyUpdate
	FailureMalformedHybridShare = failure.MalformedHybridShare
	FailureInvalidCoverSlot     = failure.InvalidCoverSlot
	FailureUnsupportedMethod    = failure.UnsupportedMethod
	FailureVerifierUnavailable  = failure.VerifierUnavailable
)

type Response struct {
	Status    int
	Body      []byte
	CloseCode uint16
}

type Origin interface {
	NormalResponse() Response
}

type ForwardingOrigin interface {
	Origin
	ForwardRequest([]byte) Response
}

type SidecarOrigin interface {
	Origin
	ForwardSidecarRequest([]byte) Response
	RecordSidecarFailure(RedactedFailureLog)
}

type RedactedFailureLog struct {
	Code string
	Body []byte
}

type GatewayProbeReport struct {
	Passed                   bool
	CanonicalResponse        Response
	Cases                    []GatewayProbeFinding
	NormalResponses          int
	ForwardedRequests        int
	SidecarForwardedRequests int
	FailureLogs              int
}

type GatewayProbeFinding struct {
	Name     string
	Kind     FailureKind
	Response Response
	Passed   bool
}

type StaticOrigin struct {
	Status int
	Body   []byte
}

func (o StaticOrigin) NormalResponse() Response {
	status := o.Status
	if status == 0 {
		status = 200
	}
	return Response{Status: status, Body: append([]byte(nil), o.Body...)}
}

type Gateway struct {
	Origin Origin
}

func (g Gateway) HandleFailure(kind FailureKind) Response {
	classification := failure.Classify(kind)
	if classification.Action != failure.CoverOrigin {
		return Response{Status: 404, Body: []byte("not found")}
	}
	if g.Origin == nil {
		return Response{Status: 404, Body: []byte("not found")}
	}
	return g.Origin.NormalResponse()
}

type CoverRequestKind uint8

const (
	CoverRequestOrdinary CoverRequestKind = iota
	CoverRequestPrelude
	CoverRequestCapsule
)

type CoverRequest struct {
	Template protocol.CoverTemplate
	ClassID  uint64
	Kind     CoverRequestKind
	Body     []byte
	Failure  FailureKind
}

func (g Gateway) HandleCoverRequest(req CoverRequest) Response {
	class, ok := findRequestClass(req.Template, req.ClassID)
	if !ok {
		return g.HandleFailure(FailureInvalidCoverSlot)
	}
	switch class.ClassType {
	case registry.RequestOriginPassThrough:
		return g.forwardVerbatim(req.Body)
	case registry.RequestGatewayOwnedSlot:
		return g.handleGatewayOwned(class, req)
	case registry.RequestSidecarOriginSlot:
		return g.handleSidecarOrigin(class, req)
	default:
		return g.HandleFailure(FailureInvalidCoverSlot)
	}
}

func (g Gateway) handleGatewayOwned(class protocol.RequestClass, req CoverRequest) Response {
	switch req.Kind {
	case CoverRequestOrdinary:
		return g.HandleFailure(FailureInvalidCoverSlot)
	case CoverRequestPrelude:
		if !class.MayCarryPrelude {
			return g.HandleFailure(FailureInvalidCoverSlot)
		}
	case CoverRequestCapsule:
		if !class.MayCarryCapsule {
			return g.HandleFailure(FailureInvalidCoverSlot)
		}
	}
	if req.Failure != 0 {
		return g.HandleFailure(req.Failure)
	}
	return g.HandleFailure(FailureInvalidCoverSlot)
}

func (g Gateway) handleSidecarOrigin(class protocol.RequestClass, req CoverRequest) Response {
	sidecar, ok := g.Origin.(SidecarOrigin)
	if !ok {
		return g.HandleFailure(FailureInvalidCoverSlot)
	}
	switch req.Kind {
	case CoverRequestOrdinary:
		return sidecar.ForwardSidecarRequest(append([]byte(nil), req.Body...))
	case CoverRequestPrelude:
		if !class.MayCarryPrelude {
			return g.HandleFailure(FailureInvalidCoverSlot)
		}
	case CoverRequestCapsule:
		if !class.MayCarryCapsule {
			return g.HandleFailure(FailureInvalidCoverSlot)
		}
	}
	kind := req.failureOrDefault()
	sidecar.RecordSidecarFailure(RedactedFailureLog{Code: failure.Classify(kind).LogKey})
	return g.HandleFailure(kind)
}

func (g Gateway) forwardVerbatim(body []byte) Response {
	if fwd, ok := g.Origin.(ForwardingOrigin); ok {
		return fwd.ForwardRequest(append([]byte(nil), body...))
	}
	return g.HandleFailure(FailureInvalidCoverSlot)
}

func (r CoverRequest) failureOrDefault() FailureKind {
	if r.Failure != 0 {
		return r.Failure
	}
	return FailureInvalidCoverSlot
}

func findRequestClass(t protocol.CoverTemplate, classID uint64) (protocol.RequestClass, bool) {
	for _, class := range t.RequestClasses {
		if class.ClassID == classID {
			return class, true
		}
	}
	return protocol.RequestClass{}, false
}

func RunGatewayActiveProbeHarness(cases []failure.ProbeCase) (GatewayProbeReport, error) {
	if len(cases) == 0 {
		return GatewayProbeReport{}, fmt.Errorf("relay: no gateway active-probe cases")
	}
	origin := &gatewayProbeOrigin{normal: Response{Status: 200, Body: []byte("<html>cover</html>")}}
	gateway := Gateway{Origin: origin}
	template := gatewayProbeTemplate()
	canonical := Response{Status: origin.normal.Status, Body: append([]byte(nil), origin.normal.Body...), CloseCode: origin.normal.CloseCode}
	report := GatewayProbeReport{
		Passed:            true,
		CanonicalResponse: canonical,
		Cases:             make([]GatewayProbeFinding, 0, len(cases)),
	}
	for _, tc := range cases {
		beforeNormal := origin.normalResponses
		beforeForwarded := origin.forwardedRequests
		beforeSidecar := origin.sidecarForwardedRequests
		beforeLogs := origin.failureLogs
		resp := gateway.HandleCoverRequest(CoverRequest{
			Template: template,
			ClassID:  1,
			Kind:     CoverRequestCapsule,
			Body:     []byte("opaque active-probe body"),
			Failure:  tc.Kind,
		})
		normalDelta := origin.normalResponses - beforeNormal
		forwardedDelta := origin.forwardedRequests - beforeForwarded
		sidecarDelta := origin.sidecarForwardedRequests - beforeSidecar
		logDelta := origin.failureLogs - beforeLogs
		passed := normalDelta == 1 &&
			forwardedDelta == 0 &&
			sidecarDelta == 0 &&
			logDelta == 0 &&
			sameGatewayResponse(resp, canonical)
		report.Passed = report.Passed && passed
		report.Cases = append(report.Cases, GatewayProbeFinding{
			Name:     tc.Name,
			Kind:     tc.Kind,
			Response: resp,
			Passed:   passed,
		})
	}
	report.NormalResponses = origin.normalResponses
	report.ForwardedRequests = origin.forwardedRequests
	report.SidecarForwardedRequests = origin.sidecarForwardedRequests
	report.FailureLogs = origin.failureLogs
	return report, nil
}

type gatewayProbeOrigin struct {
	normal                   Response
	normalResponses          int
	forwardedRequests        int
	sidecarForwardedRequests int
	failureLogs              int
}

func (o *gatewayProbeOrigin) NormalResponse() Response {
	o.normalResponses++
	return Response{Status: o.normal.Status, Body: append([]byte(nil), o.normal.Body...), CloseCode: o.normal.CloseCode}
}

func (o *gatewayProbeOrigin) ForwardRequest(_ []byte) Response {
	o.forwardedRequests++
	return Response{Status: 204}
}

func (o *gatewayProbeOrigin) ForwardSidecarRequest(_ []byte) Response {
	o.sidecarForwardedRequests++
	return Response{Status: 206}
}

func (o *gatewayProbeOrigin) RecordSidecarFailure(_ RedactedFailureLog) {
	o.failureLogs++
}

func gatewayProbeTemplate() protocol.CoverTemplate {
	return protocol.CoverTemplate{RequestClasses: []protocol.RequestClass{{
		ClassID:         1,
		ClassType:       registry.RequestGatewayOwnedSlot,
		MayCarryPrelude: true,
		MayCarryCapsule: true,
	}}}
}

func sameGatewayResponse(a, b Response) bool {
	return a.Status == b.Status && a.CloseCode == b.CloseCode && bytes.Equal(a.Body, b.Body)
}

type Session struct {
	preludeVerified bool
	selectedSuite   uint64
	admission       []byte
}

func NewSession() *Session {
	return &Session{}
}

func (s *Session) MarkPreludeVerified(selectedSuite uint64) error {
	switch selectedSuite {
	case registry.SuiteHybrid768AESGCM, registry.SuiteHybrid768P256AESGCM, registry.SuiteHybrid1024AESGCM,
		registry.SuiteHybrid768ChaCha20, registry.SuiteHybrid768P256ChaCha20, registry.SuiteHybrid1024ChaCha20:
	default:
		return fmt.Errorf("relay: unsupported production suite 0x%x", selectedSuite)
	}
	s.preludeVerified = true
	s.selectedSuite = selectedSuite
	return nil
}

func (s *Session) ReceiveAdmission(admission []byte) error {
	if !s.preludeVerified {
		return fmt.Errorf("relay: admission before prelude verification")
	}
	s.admission = append([]byte(nil), admission...)
	return nil
}

type ExitPolicy struct {
	AllowPrivate bool
}

func DefaultExitPolicy() ExitPolicy {
	return ExitPolicy{}
}

func (p ExitPolicy) AllowIP(ipString string) bool {
	addr, err := netip.ParseAddr(ipString)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if p.AllowPrivate {
		return true
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedExitPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedExitPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

type ExitFlowHandler struct {
	Policy               ExitPolicy
	UDPConfirmTTLSeconds uint32

	flows *coreflow.Manager
}

const maxUDPConfirmTTLSeconds uint32 = 86400

type ExitEventKind uint8

const (
	ExitEventFlowOpened ExitEventKind = iota + 1
	ExitEventStreamData
	ExitEventDatagramData
	ExitEventDNSMessage
	ExitEventFlowClosed
)

type ExitFrameResult struct {
	OutboundFrames []protocol.AuroraFrame
	Events         []ExitFrameEvent
}

type ExitFrameEvent struct {
	Kind      ExitEventKind
	FlowID    uint64
	FrameType uint64
	Flow      coreflow.FlowState
	Data      []byte
	Close     protocol.FlowClose
}

func NewExitFlowHandler(policy ExitPolicy) *ExitFlowHandler {
	return &ExitFlowHandler{
		Policy:               policy,
		UDPConfirmTTLSeconds: 300,
		flows:                coreflow.NewManager(),
	}
}

func (h *ExitFlowHandler) HandleFrameBlock(block protocol.FrameBlock, now uint64) (ExitFrameResult, error) {
	h.ensure()
	if err := protocol.ValidateFrameBlock(block); err != nil {
		return ExitFrameResult{}, err
	}
	var result ExitFrameResult
	for _, frame := range block.Frames {
		switch frame.FrameType {
		case registry.FrameFlowOpen:
			out, err := h.HandleFlowOpenFrame(frame, now)
			if err != nil {
				return ExitFrameResult{}, err
			}
			result.OutboundFrames = appendAuroraFrames(result.OutboundFrames, out)
			state, _ := h.FlowState(frame.FlowID)
			result.Events = append(result.Events, ExitFrameEvent{
				Kind:      ExitEventFlowOpened,
				FlowID:    frame.FlowID,
				FrameType: frame.FrameType,
				Flow:      cloneFlowState(state),
			})
		case registry.FrameStreamData, registry.FrameDatagramData, registry.FrameDNSMessage:
			event, err := h.handleDataFrame(frame, now)
			if err != nil {
				return ExitFrameResult{}, err
			}
			result.Events = append(result.Events, event)
		case registry.FrameFlowClose:
			event, err := h.handleFlowCloseFrame(frame, now)
			if err != nil {
				return ExitFrameResult{}, err
			}
			result.Events = append(result.Events, event)
		case registry.FramePadding:
			continue
		default:
			return ExitFrameResult{}, fmt.Errorf("relay: unsupported exit frame type 0x%x", frame.FrameType)
		}
	}
	return result, nil
}

func (h *ExitFlowHandler) HandleFlowOpenFrame(frame protocol.AuroraFrame, now uint64) ([]protocol.AuroraFrame, error) {
	h.ensure()
	if frame.FrameType != registry.FrameFlowOpen {
		return nil, fmt.Errorf("relay: expected FLOW_OPEN frame, got 0x%x", frame.FrameType)
	}
	if err := protocol.ValidateFlowManagementFrame(frame); err != nil {
		return nil, err
	}
	open := protocol.DecodeFlowOpen(wire.NewReader(frame.Payload))
	if err := h.checkExitPolicy(open); err != nil {
		return nil, err
	}
	out, err := h.confirmFramesForOpen(open)
	if err != nil {
		return nil, err
	}
	ttl := h.effectiveUDPConfirmTTLSeconds()
	if err := h.flows.OpenWithOptions(open, coreflow.FlowOptions{
		NowUnix:            now,
		TTLSeconds:         uint64(ttl),
		IdleTimeoutSeconds: 30,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *ExitFlowHandler) handleDataFrame(frame protocol.AuroraFrame, now uint64) (ExitFrameEvent, error) {
	if frame.FrameType == registry.FrameDNSMessage {
		state, _ := h.FlowState(frame.FlowID)
		return ExitFrameEvent{
			Kind:      ExitEventDNSMessage,
			FlowID:    frame.FlowID,
			FrameType: frame.FrameType,
			Flow:      cloneFlowState(state),
			Data:      append([]byte(nil), frame.Payload...),
		}, nil
	}
	state, ok := h.flows.DemuxInbound(frame.FlowID)
	if !ok {
		return ExitFrameEvent{}, fmt.Errorf("relay: data for unknown flow_id %d", frame.FlowID)
	}
	if state.LocalClosed || state.PeerClosed {
		return ExitFrameEvent{}, fmt.Errorf("relay: data for closed flow_id %d", frame.FlowID)
	}
	switch frame.FrameType {
	case registry.FrameStreamData:
		if state.Kind == coreflow.FlowKindUDPAssociation {
			var accepted bool
			state, accepted = h.flows.AcceptDatagramWithOptions(frame.FlowID, coreflow.DatagramOptions{NowUnix: now})
			if !accepted {
				return ExitFrameEvent{}, fmt.Errorf("relay: UDP stream-fallback data for unavailable flow_id %d", frame.FlowID)
			}
		} else if state.Kind != coreflow.FlowKindTCPStream {
			return ExitFrameEvent{}, fmt.Errorf("relay: STREAM_DATA for non-stream flow_id %d", frame.FlowID)
		}
		return ExitFrameEvent{
			Kind:      ExitEventStreamData,
			FlowID:    frame.FlowID,
			FrameType: frame.FrameType,
			Flow:      cloneFlowState(state),
			Data:      append([]byte(nil), frame.Payload...),
		}, nil
	case registry.FrameDatagramData:
		var accepted bool
		state, accepted = h.flows.AcceptDatagramWithOptions(frame.FlowID, coreflow.DatagramOptions{NowUnix: now})
		if !accepted {
			return ExitFrameEvent{}, fmt.Errorf("relay: DATAGRAM_DATA for unavailable flow_id %d", frame.FlowID)
		}
		return ExitFrameEvent{
			Kind:      ExitEventDatagramData,
			FlowID:    frame.FlowID,
			FrameType: frame.FrameType,
			Flow:      cloneFlowState(state),
			Data:      append([]byte(nil), frame.Payload...),
		}, nil
	default:
		return ExitFrameEvent{}, fmt.Errorf("relay: unsupported data frame type 0x%x", frame.FrameType)
	}
}

func (h *ExitFlowHandler) handleFlowCloseFrame(frame protocol.AuroraFrame, now uint64) (ExitFrameEvent, error) {
	if frame.FrameType != registry.FrameFlowClose {
		return ExitFrameEvent{}, fmt.Errorf("relay: expected FLOW_CLOSE frame, got 0x%x", frame.FrameType)
	}
	if err := protocol.ValidateFlowManagementFrame(frame); err != nil {
		return ExitFrameEvent{}, err
	}
	r := wire.NewReader(frame.Payload)
	close := protocol.DecodeFlowClose(r)
	if r.Err() != nil {
		return ExitFrameEvent{}, r.Err()
	}
	if !r.EOF() {
		return ExitFrameEvent{}, fmt.Errorf("relay: trailing FLOW_CLOSE payload bytes")
	}
	if err := h.flows.MarkPeerClose(close, coreflow.CloseOptions{NowUnix: now, DrainSeconds: 30}); err != nil {
		return ExitFrameEvent{}, err
	}
	state, _ := h.FlowState(frame.FlowID)
	return ExitFrameEvent{
		Kind:      ExitEventFlowClosed,
		FlowID:    frame.FlowID,
		FrameType: frame.FrameType,
		Flow:      cloneFlowState(state),
		Close:     cloneFlowClose(close),
	}, nil
}

func (h *ExitFlowHandler) FlowState(flowID uint64) (coreflow.FlowState, bool) {
	h.ensure()
	return h.flows.DemuxInbound(flowID)
}

func (h *ExitFlowHandler) ensure() {
	if h.flows == nil {
		h.flows = coreflow.NewManager()
	}
	if h.UDPConfirmTTLSeconds == 0 {
		h.UDPConfirmTTLSeconds = 300
	}
}

func (h *ExitFlowHandler) checkExitPolicy(open protocol.FlowOpen) error {
	switch open.TargetKind {
	case coreflow.TargetKindIPv4, coreflow.TargetKindIPv6:
		addr, ok := addrFromFlowTarget(open.TargetKind, open.TargetHost)
		if !ok {
			return fmt.Errorf("relay: malformed IP target")
		}
		if !h.Policy.AllowIP(addr.String()) {
			return fmt.Errorf("relay: exit policy denied target")
		}
	}
	return nil
}

func (h *ExitFlowHandler) confirmFramesForOpen(open protocol.FlowOpen) ([]protocol.AuroraFrame, error) {
	if open.FlowKind != coreflow.FlowKindUDPAssociation {
		return nil, nil
	}
	if open.TargetKind != coreflow.TargetKindIPv4 && open.TargetKind != coreflow.TargetKindIPv6 {
		return nil, nil
	}
	frame, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           open.FlowID,
		TargetKind:       open.TargetKind,
		SelectedIP:       append([]byte(nil), open.TargetHost...),
		SelectedPort:     open.TargetPort,
		DNSAnswerSetHash: append([]byte(nil), open.DNSAnswerSetHash...),
		TTLSeconds:       h.effectiveUDPConfirmTTLSeconds(),
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		return nil, err
	}
	return []protocol.AuroraFrame{frame}, nil
}

func (h *ExitFlowHandler) effectiveUDPConfirmTTLSeconds() uint32 {
	ttl := h.UDPConfirmTTLSeconds
	if ttl == 0 {
		ttl = 300
	}
	if ttl > maxUDPConfirmTTLSeconds {
		return maxUDPConfirmTTLSeconds
	}
	return ttl
}

func appendAuroraFrames(out []protocol.AuroraFrame, frames []protocol.AuroraFrame) []protocol.AuroraFrame {
	for _, frame := range frames {
		out = append(out, cloneAuroraFrame(frame))
	}
	return out
}

func cloneAuroraFrame(frame protocol.AuroraFrame) protocol.AuroraFrame {
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame
}

func cloneFlowState(state coreflow.FlowState) coreflow.FlowState {
	state.TargetHost = append([]byte(nil), state.TargetHost...)
	state.NameBindingID = append([]byte(nil), state.NameBindingID...)
	state.DNSAnswerSetHash = append([]byte(nil), state.DNSAnswerSetHash...)
	state.ConfirmedHost = append([]byte(nil), state.ConfirmedHost...)
	state.ConfirmedDNSAnswerSetHash = append([]byte(nil), state.ConfirmedDNSAnswerSetHash...)
	return state
}

func cloneFlowClose(close protocol.FlowClose) protocol.FlowClose {
	close.Reason = append([]byte(nil), close.Reason...)
	close.Extensions = cloneProtocolExtensions(close.Extensions)
	return close
}

func cloneProtocolExtensions(in []protocol.Extension) []protocol.Extension {
	if len(in) == 0 {
		return nil
	}
	out := make([]protocol.Extension, len(in))
	for i, ext := range in {
		out[i] = ext
		out[i].Body = append([]byte(nil), ext.Body...)
	}
	return out
}

func addrFromFlowTarget(kind uint8, host []byte) (netip.Addr, bool) {
	switch kind {
	case coreflow.TargetKindIPv4:
		if len(host) != 4 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte{host[0], host[1], host[2], host[3]}), true
	case coreflow.TargetKindIPv6:
		if len(host) != 16 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte{
			host[0], host[1], host[2], host[3],
			host[4], host[5], host[6], host[7],
			host[8], host[9], host[10], host[11],
			host[12], host[13], host[14], host[15],
		}).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

type AdmissionPolicy struct {
	VerifierServices []protocol.IssuerVerifierServiceRecord
	BlindRSAVerifier BlindRSAVerifier
	VOPRFTransport   ops.IssuerVerifierTransport
	RequestAuth      map[uint64]bool
	NowUnix          uint64
}

type BlindRSAVerifier interface {
	VerifyBlindRSA2048(protocol.AdmissionProof) error
}

type MetadataBlindRSAVerifier struct {
	IssuerMetadata []protocol.IssuerMetadata
	NowUnix        uint64
}

func (v MetadataBlindRSAVerifier) VerifyBlindRSA2048(proof protocol.AdmissionProof) error {
	matches := 0
	for _, metadata := range v.IssuerMetadata {
		if err := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, v.NowUnix); err == nil {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("relay: Blind RSA issuer metadata lookup returned %d matches", matches)
	}
	return nil
}

type VerifierServiceAdmissionInput struct {
	AdmissionProof            protocol.AdmissionProof
	ReplayProof               protocol.ReplayProof
	IssuerMetadataHash        []byte
	RelayDescriptorHash       []byte
	RouteInstanceID           uint64
	HopIndex                  uint8
	ReplayEpochValidUntilUnix uint64
	HandshakeBindingContext   []byte
	AdmissionContextHash      []byte
	ChallengeDigest           []byte
	AuthenticatorInputHash    []byte
	RequestNonce              []byte
	RequestTimeUnix           uint64
	TokenSpentCache           admission.ReplayCache
	BootstrapDedupCache       admission.ReplayCache
}

func (p AdmissionPolicy) AllowsProof(proof protocol.AdmissionProof) error {
	if err := proof.ValidateStructural(p.NowUnix, false); err != nil {
		return err
	}
	switch proof.ProofType {
	case registry.ProofBlindRSA2048:
		if p.BlindRSAVerifier == nil {
			return fmt.Errorf("relay: Blind RSA proof requires local verifier")
		}
		return p.BlindRSAVerifier.VerifyBlindRSA2048(proof)
	case registry.ProofVOPRFP384SHA384:
		return fmt.Errorf("relay: VOPRF proof requires verifier-service replay context")
	case registry.ProofLabStaticToken:
		return fmt.Errorf("relay: lab admission proof disabled")
	default:
		return fmt.Errorf("relay: unsupported admission proof type 0x%x", proof.ProofType)
	}
}

func (p AdmissionPolicy) AllowsVerifierServiceAdmission(in VerifierServiceAdmissionInput) error {
	if err := in.AdmissionProof.ValidateStructural(p.NowUnix, false); err != nil {
		return err
	}
	if in.AdmissionProof.ProofType != registry.ProofVOPRFP384SHA384 {
		return fmt.Errorf("relay: verifier service admission requires VOPRF proof")
	}
	service, err := p.selectVOPRFVerifierService(in.AdmissionProof)
	if err != nil {
		return err
	}
	if p.VOPRFTransport == nil {
		return failure.NewError(failure.VerifierUnavailable, "relay: VOPRF proof requires verifier service transport")
	}
	return ops.VerifyIssuerVerifierService(ops.IssuerVerifierServiceVerificationInput{
		Request: ops.IssuerVerifierRequestInput{
			Service:                   service,
			AdmissionProof:            in.AdmissionProof,
			ReplayProof:               in.ReplayProof,
			IssuerMetadataHash:        append([]byte(nil), in.IssuerMetadataHash...),
			RelayDescriptorHash:       append([]byte(nil), in.RelayDescriptorHash...),
			RouteInstanceID:           in.RouteInstanceID,
			HopIndex:                  in.HopIndex,
			ReplayEpochValidUntilUnix: in.ReplayEpochValidUntilUnix,
			HandshakeBindingContext:   append([]byte(nil), in.HandshakeBindingContext...),
			AdmissionContextHash:      append([]byte(nil), in.AdmissionContextHash...),
			ChallengeDigest:           append([]byte(nil), in.ChallengeDigest...),
			AuthenticatorInputHash:    append([]byte(nil), in.AuthenticatorInputHash...),
			TokenSpentCache:           in.TokenSpentCache,
			BootstrapDedupCache:       in.BootstrapDedupCache,
			RequestNonce:              append([]byte(nil), in.RequestNonce...),
			RequestTimeUnix:           in.RequestTimeUnix,
			NowUnix:                   p.NowUnix,
			RequestAuthImplemented:    p.RequestAuth[service.RequestAuthPolicyID],
		},
		Transport: p.VOPRFTransport,
	})
}

func (p AdmissionPolicy) selectVOPRFVerifierService(proof protocol.AdmissionProof) (protocol.IssuerVerifierServiceRecord, error) {
	matches := 0
	var matched protocol.IssuerVerifierServiceRecord
	for _, service := range p.VerifierServices {
		if err := service.Allows(proof.ProofType, proof.RelayBucketID, p.NowUnix, p.RequestAuth[service.RequestAuthPolicyID]); err == nil {
			matches++
			matched = service
		}
	}
	if matches != 1 {
		return protocol.IssuerVerifierServiceRecord{}, fmt.Errorf("relay: VOPRF proof requires exactly one authorized issuer verifier service")
	}
	return matched, nil
}
