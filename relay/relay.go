package relay

import (
	"fmt"
	"net/netip"

	"github.com/aurora-protocol/aurora-core/failure"
	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type FailureKind = failure.Kind

const (
	FailureBadAccessHint       = failure.BadAccessHint
	FailureReplayedHint        = failure.ReplayedAccessHint
	FailureBadAEADTag          = failure.BadAEADTag
	FailureWrongSuite          = failure.WrongSuite
	FailureMalformedFlowOpen   = failure.MalformedFlowOpen
	FailureMalformedKeyUpdate  = failure.MalformedKeyUpdate
	FailureInvalidCoverSlot    = failure.InvalidCoverSlot
	FailureUnsupportedMethod   = failure.UnsupportedMethod
	FailureVerifierUnavailable = failure.VerifierUnavailable
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
		return g.HandleFailure(req.failureOrDefault())
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

func NewExitFlowHandler(policy ExitPolicy) *ExitFlowHandler {
	return &ExitFlowHandler{
		Policy:               policy,
		UDPConfirmTTLSeconds: 300,
		flows:                coreflow.NewManager(),
	}
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
	VOPRFVerifier    VOPRFVerifier
	RequestAuth      map[uint64]bool
	NowUnix          uint64
}

type BlindRSAVerifier interface {
	VerifyBlindRSA2048(protocol.AdmissionProof) error
}

type VOPRFVerifier interface {
	VerifyVOPRF(protocol.AdmissionProof, protocol.IssuerVerifierServiceRecord) error
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
		matches := 0
		var matched protocol.IssuerVerifierServiceRecord
		for _, service := range p.VerifierServices {
			if err := service.Allows(proof.ProofType, proof.RelayBucketID, p.NowUnix, p.RequestAuth[service.RequestAuthPolicyID]); err == nil {
				matches++
				matched = service
			}
		}
		if matches != 1 {
			return fmt.Errorf("relay: VOPRF proof requires exactly one authorized issuer verifier service")
		}
		if p.VOPRFVerifier == nil {
			return fmt.Errorf("relay: VOPRF proof requires verifier client")
		}
		return p.VOPRFVerifier.VerifyVOPRF(proof, matched)
	case registry.ProofLabStaticToken:
		return fmt.Errorf("relay: lab admission proof disabled")
	default:
		return fmt.Errorf("relay: unsupported admission proof type 0x%x", proof.ProofType)
	}
}
