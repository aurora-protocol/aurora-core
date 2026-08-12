package client

import (
	"fmt"
	"net"
	"strings"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/transport"
)

type Engine struct {
	Profile policy.Profile
}

type Plan struct {
	RouteModeID          uint64
	MethodID             uint64
	PersonalityID        uint64
	ShapeID              uint64
	UDPMode              transport.UDPMode
	PerformanceDowngrade bool
}

func (e Engine) Plan(caps transport.Capabilities) (Plan, error) {
	profile := e.Profile
	if profile.ID == 0 {
		profile = policy.SmartProfile("normal")
	}
	carrierPlan, err := transport.SelectCarrierPlan(profile, caps)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		RouteModeID:          profile.DefaultRoute,
		MethodID:             carrierPlan.Carrier.MethodID,
		PersonalityID:        profile.DefaultPersonality,
		ShapeID:              profile.DefaultShape,
		UDPMode:              carrierPlan.UDPMode,
		PerformanceDowngrade: carrierPlan.PerformanceDowngrade,
	}, nil
}

type LocalProxy struct {
	flows       *flow.Manager
	dns         *flow.DNSForwarder
	tcpSchedule *flow.Scheduler
}

type LocalProxyOptions struct {
	MaxBufferedTCPBytes int
}

type UDPSendOptions struct {
	NowUnix               uint64
	SentAtUnix            uint64
	UDPMode               transport.UDPMode
	MaxRealtimeAgeSeconds uint64
}

func NewLocalProxy() *LocalProxy {
	return NewLocalProxyWithOptions(LocalProxyOptions{})
}

func NewLocalProxyWithOptions(opts LocalProxyOptions) *LocalProxy {
	return &LocalProxy{
		flows:       flow.NewManager(),
		dns:         flow.NewDNSForwarder(flow.DNSForwarderOptions{}),
		tcpSchedule: flow.NewScheduler(flow.SchedulerOptions{MaxBufferedBytes: opts.MaxBufferedTCPBytes}),
	}
}

func (p *LocalProxy) OpenTCP(flowID uint64, host string, port uint16) error {
	return p.OpenTCPWithPriority(flowID, host, port, flow.PriorityInteractive)
}

func (p *LocalProxy) OpenTCPWithPriority(flowID uint64, host string, port uint16, priority uint8) error {
	_, err := p.OpenTCPFrameWithPriority(flowID, host, port, priority)
	return err
}

func (p *LocalProxy) OpenTCPFrame(flowID uint64, host string, port uint16) (protocol.AuroraFrame, error) {
	return p.OpenTCPFrameWithPriority(flowID, host, port, flow.PriorityInteractive)
}

func (p *LocalProxy) OpenTCPFrameWithPriority(flowID uint64, host string, port uint16, priority uint8) (protocol.AuroraFrame, error) {
	return p.openTCPFrame(flowID, host, port, priority, flow.LocalBindingExplicitProxyAPI)
}

// OpenTUNTCPFrame creates a TCP flow for a locally captured packet-tunnel connection.
func (p *LocalProxy) OpenTUNTCPFrame(flowID uint64, host string, port uint16) (protocol.AuroraFrame, error) {
	return p.openTCPFrame(flowID, host, port, flow.PriorityInteractive, flow.LocalBindingTUNPacketFlow)
}

// OpenTCPFromFakeIPFrame restores a TCP target from a local synthetic DNS answer.
func (p *LocalProxy) OpenTCPFromFakeIPFrame(flowID uint64, fakeIP string, port uint16) (flow.SyntheticAnswer, protocol.AuroraFrame, error) {
	open, answer, err := p.dns.OpenMappedFakeIPTCPFlow(flowID, fakeIP, port)
	if err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	frame, err := protocol.NewFlowOpenFrame(open)
	if err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	if err := p.flows.Open(open); err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	return answer, frame, nil
}

func (p *LocalProxy) openTCPFrame(flowID uint64, host string, port uint16, priority, localBindingMode uint8) (protocol.AuroraFrame, error) {
	targetKind, targetHost, err := localTarget(host)
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         flow.FlowKindTCPStream,
		TargetKind:       targetKind,
		TargetHost:       targetHost,
		TargetPort:       port,
		UDPFQDNMode:      flow.UDPFQDNNoneIPAuthoritative,
		NameBindingID:    make([]byte, 16),
		DNSAnswerSetHash: make([]byte, 48),
		LocalBindingMode: localBindingMode,
		PriorityClass:    priority,
	}
	frame, err := protocol.NewFlowOpenFrame(open)
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	if err := p.flows.Open(open); err != nil {
		return protocol.AuroraFrame{}, err
	}
	return frame, nil
}

func (p *LocalProxy) OpenUDPExplicit(flowID uint64, host string, port uint16, now uint64) error {
	_, err := p.OpenUDPExplicitFrame(flowID, host, port, now)
	return err
}

func (p *LocalProxy) OpenUDPExplicitFrame(flowID uint64, host string, port uint16, now uint64) (protocol.AuroraFrame, error) {
	return p.openUDPFrame(flowID, host, port, now, flow.LocalBindingExplicitProxyAPI)
}

// OpenTUNUDPFrame creates a UDP flow for a locally captured packet-tunnel datagram.
func (p *LocalProxy) OpenTUNUDPFrame(flowID uint64, host string, port uint16, now uint64) (protocol.AuroraFrame, error) {
	return p.openUDPFrame(flowID, host, port, now, flow.LocalBindingTUNPacketFlow)
}

func (p *LocalProxy) openUDPFrame(flowID uint64, host string, port uint16, now uint64, localBindingMode uint8) (protocol.AuroraFrame, error) {
	targetKind, targetHost, err := localTarget(host)
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	udpFQDNMode := uint8(flow.UDPFQDNNoneIPAuthoritative)
	var originalDomainHint []byte
	if targetKind == flow.TargetKindDomainName {
		udpFQDNMode = flow.UDPFQDNRelayResolvedFlowBound
		originalDomainHint = append([]byte(nil), targetHost...)
	}
	open := protocol.FlowOpen{
		FlowOpenVersion:    registry.Version20,
		FlowID:             flowID,
		FlowKind:           flow.FlowKindUDPAssociation,
		TargetKind:         targetKind,
		TargetHost:         targetHost,
		TargetPort:         port,
		UDPFQDNMode:        udpFQDNMode,
		NameBindingID:      make([]byte, 16),
		DNSAnswerSetHash:   make([]byte, 48),
		LocalBindingMode:   localBindingMode,
		PriorityClass:      flow.PriorityRealtime,
		OriginalDomainHint: originalDomainHint,
	}
	frame, err := protocol.NewFlowOpenFrame(open)
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	if err := p.flows.OpenWithOptions(open, flow.FlowOptions{NowUnix: now, TTLSeconds: 300, IdleTimeoutSeconds: 30}); err != nil {
		return protocol.AuroraFrame{}, err
	}
	return frame, nil
}

func localTarget(host string) (uint8, []byte, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return 0, nil, fmt.Errorf("client: empty target host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return flow.TargetKindIPv4, append([]byte(nil), v4...), nil
		}
		if v16 := ip.To16(); v16 != nil {
			return flow.TargetKindIPv6, append([]byte(nil), v16...), nil
		}
	}
	domain := strings.TrimSuffix(strings.ToLower(host), ".")
	if domain == "" || strings.ContainsAny(domain, "/\x00") {
		return 0, nil, fmt.Errorf("client: invalid domain target")
	}
	return flow.TargetKindDomainName, []byte(domain), nil
}

func (p *LocalProxy) HasFlow(flowID uint64) bool {
	_, ok := p.flows.DemuxInbound(flowID)
	return ok
}

func (p *LocalProxy) FlowState(flowID uint64) (flow.FlowState, bool) {
	return p.flows.DemuxInbound(flowID)
}

func (p *LocalProxy) ResolveFakeDNS(host string, answers []string, now uint64) (flow.SyntheticAnswer, error) {
	return p.dns.ResolveFakeA(host, answers, now)
}

func (p *LocalProxy) AnswerLocalDNSQuery(flowID uint64, query []byte, answers []string, now uint64) (flow.LocalDNSResult, error) {
	return p.dns.AnswerLocalAQuery(flowID, query, answers, now)
}

func (p *LocalProxy) OpenUDPWithFakeDNS(flowID uint64, host string, answers []string, port uint16, now uint64) (flow.SyntheticAnswer, error) {
	answer, _, err := p.OpenUDPWithFakeDNSFrame(flowID, host, answers, port, now)
	return answer, err
}

func (p *LocalProxy) OpenUDPWithFakeDNSFrame(flowID uint64, host string, answers []string, port uint16, now uint64) (flow.SyntheticAnswer, protocol.AuroraFrame, error) {
	open, answer, err := p.dns.OpenFakeIPUDPFlow(flowID, host, answers, port, now)
	if err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	frame, err := protocol.NewFlowOpenFrame(open)
	if err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	if err := p.flows.OpenWithOptions(open, flow.FlowOptions{NowUnix: now, TTLSeconds: 300, IdleTimeoutSeconds: 30}); err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	return answer, frame, nil
}

func (p *LocalProxy) OpenUDPFromFakeIP(flowID uint64, fakeIP string, port uint16, now uint64) (flow.SyntheticAnswer, error) {
	answer, _, err := p.OpenUDPFromFakeIPFrame(flowID, fakeIP, port, now)
	return answer, err
}

func (p *LocalProxy) OpenUDPFromFakeIPFrame(flowID uint64, fakeIP string, port uint16, now uint64) (flow.SyntheticAnswer, protocol.AuroraFrame, error) {
	open, answer, err := p.dns.OpenMappedFakeIPUDPFlow(flowID, fakeIP, port, now)
	if err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	frame, err := protocol.NewFlowOpenFrame(open)
	if err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	if err := p.flows.OpenWithOptions(open, flow.FlowOptions{NowUnix: now, TTLSeconds: 300, IdleTimeoutSeconds: 30}); err != nil {
		return flow.SyntheticAnswer{}, protocol.AuroraFrame{}, err
	}
	return answer, frame, nil
}

func (p *LocalProxy) SendTCP(flowID uint64, data []byte, flags uint64) (protocol.AuroraFrame, error) {
	state, ok := p.flows.DemuxInbound(flowID)
	if !ok {
		return protocol.AuroraFrame{}, fmt.Errorf("client: unknown TCP flow %d", flowID)
	}
	if state.Kind != flow.FlowKindTCPStream {
		return protocol.AuroraFrame{}, fmt.Errorf("client: flow %d is not TCP", flowID)
	}
	if state.LocalClosed {
		return protocol.AuroraFrame{}, fmt.Errorf("client: TCP flow %d is closed for local writes", flowID)
	}
	return protocol.NewStreamDataFrame(flowID, data, flags)
}

func (p *LocalProxy) EnqueueTCP(flowID uint64, data []byte, flags uint64) error {
	state, ok := p.flows.DemuxInbound(flowID)
	if !ok {
		return fmt.Errorf("client: unknown TCP flow %d", flowID)
	}
	if state.Kind != flow.FlowKindTCPStream {
		return fmt.Errorf("client: flow %d is not TCP", flowID)
	}
	if state.LocalClosed {
		return fmt.Errorf("client: TCP flow %d is closed for local writes", flowID)
	}
	if p.tcpSchedule == nil {
		p.tcpSchedule = flow.NewScheduler(flow.SchedulerOptions{})
	}
	return p.tcpSchedule.Enqueue(flow.StreamChunk{
		FlowID:        flowID,
		PriorityClass: state.PriorityClass,
		Data:          data,
		Flags:         flags,
	})
}

func (p *LocalProxy) NextTCPFrame() (protocol.AuroraFrame, bool, error) {
	if p.tcpSchedule == nil {
		return protocol.AuroraFrame{}, false, nil
	}
	chunk, ok := p.tcpSchedule.Next()
	if !ok {
		return protocol.AuroraFrame{}, false, nil
	}
	frame, err := protocol.NewStreamDataFrame(chunk.FlowID, chunk.Data, chunk.Flags)
	if err != nil {
		return protocol.AuroraFrame{}, false, err
	}
	return frame, true, nil
}

func (p *LocalProxy) SendUDP(flowID uint64, data []byte, now uint64) (protocol.AuroraFrame, error) {
	return p.SendUDPWithMode(flowID, data, now, transport.UDPNativeDatagram)
}

func (p *LocalProxy) SendUDPWithMode(flowID uint64, data []byte, now uint64, udpMode transport.UDPMode) (protocol.AuroraFrame, error) {
	return p.SendUDPWithOptions(flowID, data, UDPSendOptions{NowUnix: now, UDPMode: udpMode})
}

func (p *LocalProxy) SendUDPWithOptions(flowID uint64, data []byte, opts UDPSendOptions) (protocol.AuroraFrame, error) {
	switch opts.UDPMode {
	case transport.UDPNativeDatagram, transport.UDPOverStreamFallback:
	default:
		return protocol.AuroraFrame{}, fmt.Errorf("client: UDP mode %d is unsupported", opts.UDPMode)
	}
	state, ok := p.flows.AcceptDatagramWithOptions(flowID, flow.DatagramOptions{
		NowUnix:               opts.NowUnix,
		SentAtUnix:            opts.SentAtUnix,
		MaxRealtimeAgeSeconds: opts.MaxRealtimeAgeSeconds,
	})
	if !ok {
		return protocol.AuroraFrame{}, fmt.Errorf("client: UDP flow %d is unavailable", flowID)
	}
	if state.Kind != flow.FlowKindUDPAssociation {
		return protocol.AuroraFrame{}, fmt.Errorf("client: flow %d is not UDP", flowID)
	}
	if opts.UDPMode == transport.UDPNativeDatagram {
		return protocol.NewDatagramDataFrame(flowID, data, 0)
	}
	return protocol.NewStreamDataFrame(flowID, data, 0)
}

func (p *LocalProxy) CloseFrame(flowID uint64, finalSequenceHint uint64, reason []byte) (protocol.AuroraFrame, error) {
	if _, ok := p.flows.DemuxInbound(flowID); !ok {
		return protocol.AuroraFrame{}, fmt.Errorf("client: unknown flow %d", flowID)
	}
	frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
		FlowID:                   flowID,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
		FinalSequenceHint:        finalSequenceHint,
		Reason:                   append([]byte(nil), reason...),
	})
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	if err := p.Close(flowID); err != nil {
		return protocol.AuroraFrame{}, err
	}
	return frame, nil
}

func (p *LocalProxy) GracefulCloseFrame(flowID uint64, finalSequenceHint uint64, reason []byte, now uint64, drainSeconds uint64) (protocol.AuroraFrame, error) {
	if _, ok := p.flows.DemuxInbound(flowID); !ok {
		return protocol.AuroraFrame{}, fmt.Errorf("client: unknown flow %d", flowID)
	}
	close := protocol.FlowClose{
		FlowID:                   flowID,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
		FinalSequenceHint:        finalSequenceHint,
		Reason:                   append([]byte(nil), reason...),
	}
	frame, err := protocol.NewFlowCloseFrame(close)
	if err != nil {
		return protocol.AuroraFrame{}, err
	}
	if err := p.flows.MarkLocalClose(close, flow.CloseOptions{NowUnix: now, DrainSeconds: drainSeconds}); err != nil {
		return protocol.AuroraFrame{}, err
	}
	return frame, nil
}

func (p *LocalProxy) ReceiveFlowClose(close protocol.FlowClose, now uint64, drainSeconds uint64) error {
	return p.flows.MarkPeerClose(close, flow.CloseOptions{NowUnix: now, DrainSeconds: drainSeconds})
}

func (p *LocalProxy) ReceiveFlowCloseFrame(frame protocol.AuroraFrame, now uint64, drainSeconds uint64) error {
	return p.flows.MarkPeerCloseFrame(frame, flow.CloseOptions{NowUnix: now, DrainSeconds: drainSeconds})
}

func (p *LocalProxy) ReceiveUDPTargetConfirmFrame(frame protocol.AuroraFrame) error {
	return p.flows.ConfirmUDPFrame(frame)
}

func (p *LocalProxy) ReceiveUDPTargetConfirmFrameAt(frame protocol.AuroraFrame, now uint64) error {
	return p.flows.ConfirmUDPFrameWithOptions(frame, flow.UDPConfirmOptions{NowUnix: now})
}

func (p *LocalProxy) PurgeClosed(now uint64) {
	p.flows.PurgeClosed(now)
}

func (p *LocalProxy) Close(flowID uint64) error {
	return p.flows.Close(protocol.FlowClose{FlowID: flowID})
}
