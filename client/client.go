package client

import (
	"fmt"
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
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return fmt.Errorf("client: empty TCP host")
	}
	return p.flows.Open(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         flow.FlowKindTCPStream,
		TargetKind:       flow.TargetKindDomainName,
		TargetHost:       []byte(host),
		TargetPort:       port,
		UDPFQDNMode:      flow.UDPFQDNNoneIPAuthoritative,
		NameBindingID:    make([]byte, 16),
		DNSAnswerSetHash: make([]byte, 48),
		LocalBindingMode: flow.LocalBindingExplicitProxyAPI,
		PriorityClass:    priority,
	})
}

func (p *LocalProxy) HasFlow(flowID uint64) bool {
	_, ok := p.flows.DemuxInbound(flowID)
	return ok
}

func (p *LocalProxy) FlowState(flowID uint64) (flow.FlowState, bool) {
	return p.flows.DemuxInbound(flowID)
}

func (p *LocalProxy) OpenUDPWithFakeDNS(flowID uint64, host string, answers []string, port uint16, now uint64) (flow.SyntheticAnswer, error) {
	open, answer, err := p.dns.OpenFakeIPUDPFlow(flowID, host, answers, port, now)
	if err != nil {
		return flow.SyntheticAnswer{}, err
	}
	if err := p.flows.OpenWithOptions(open, flow.FlowOptions{NowUnix: now, TTLSeconds: 300, IdleTimeoutSeconds: 30}); err != nil {
		return flow.SyntheticAnswer{}, err
	}
	return answer, nil
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
	state, ok := p.flows.AcceptDatagram(flowID, now)
	if !ok {
		return protocol.AuroraFrame{}, fmt.Errorf("client: UDP flow %d is unavailable", flowID)
	}
	if state.Kind != flow.FlowKindUDPAssociation {
		return protocol.AuroraFrame{}, fmt.Errorf("client: flow %d is not UDP", flowID)
	}
	return protocol.NewDatagramDataFrame(flowID, data, 0)
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

func (p *LocalProxy) PurgeClosed(now uint64) {
	p.flows.PurgeClosed(now)
}

func (p *LocalProxy) Close(flowID uint64) error {
	return p.flows.Close(protocol.FlowClose{FlowID: flowID})
}
