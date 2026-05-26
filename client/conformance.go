package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
)

type ProxyFlowConformanceCase struct {
	Name   string
	Passed bool
	Detail string
}

type ProxyFlowConformanceReport struct {
	Passed   bool
	Cases    []ProxyFlowConformanceCase
	Findings []string
}

func RunProxyFlowConformance() (ProxyFlowConformanceReport, error) {
	report := ProxyFlowConformanceReport{Passed: true}
	addTCPFlowConformance(&report)
	addUDPModeConformance(&report)
	addUDPTargetConfirmConformance(&report)
	addUDPFQDNFakeIPConformance(&report)
	addRealtimeStaleDropConformance(&report)
	addDNSForwarderConformance(&report)
	return report, nil
}

func (r *ProxyFlowConformanceReport) addCase(name string, passed bool, detail string) {
	r.Cases = append(r.Cases, ProxyFlowConformanceCase{
		Name:   name,
		Passed: passed,
		Detail: detail,
	})
	if !passed {
		r.Passed = false
		r.Findings = append(r.Findings, name+" failed")
	}
}

func addTCPFlowConformance(report *ProxyFlowConformanceReport) {
	p := NewLocalProxyWithOptions(LocalProxyOptions{MaxBufferedTCPBytes: 8})
	bulkOpen, bulkErr := p.OpenTCPFrameWithPriority(31, "bulk.example", 443, flow.PriorityBulk)
	interactiveOpen, interactiveErr := p.OpenTCPFrameWithPriority(32, "interactive.example", 443, flow.PriorityInteractive)
	enqueueBulkErr := p.EnqueueTCP(31, []byte("bulk"), 0)
	enqueueInteractiveErr := p.EnqueueTCP(32, []byte("work"), 0x01)
	firstFrame, firstOK, firstErr := p.NextTCPFrame()

	backpressure := NewLocalProxyWithOptions(LocalProxyOptions{MaxBufferedTCPBytes: 3})
	_ = backpressure.OpenTCPWithPriority(33, "pressure.example", 443, flow.PriorityBulk)
	backpressureErr := backpressure.EnqueueTCP(33, []byte("over"), 0)

	closeFrame, closeErr := p.GracefulCloseFrame(32, 9, []byte("done"), 100, 5)
	_, sendAfterCloseErr := p.SendTCP(32, []byte("blocked"), 0)
	peerClose := protocol.FlowClose{FlowID: 32, CloseCode: protocol.CloseNormal, FinalSequenceHintPresent: true, FinalSequenceHint: 10}
	receiveCloseErr := p.ReceiveFlowClose(peerClose, 101, 5)
	_, stillOpen := p.FlowState(32)

	passed := bulkErr == nil &&
		interactiveErr == nil &&
		bulkOpen.FrameType == registry.FrameFlowOpen &&
		interactiveOpen.FrameType == registry.FrameFlowOpen &&
		enqueueBulkErr == nil &&
		enqueueInteractiveErr == nil &&
		firstErr == nil &&
		firstOK &&
		firstFrame.FrameType == registry.FrameStreamData &&
		firstFrame.FlowID == 32 &&
		firstFrame.Flags == 0x01 &&
		backpressureErr != nil &&
		closeErr == nil &&
		closeFrame.FrameType == registry.FrameFlowClose &&
		sendAfterCloseErr != nil &&
		receiveCloseErr == nil &&
		!stillOpen
	report.addCase(
		"tcp_open_scheduler_backpressure_close",
		passed,
		"FLOW_OPEN, priority scheduling, backpressure, half-close, and full-close semantics",
	)
}

func addUDPModeConformance(report *ProxyFlowConformanceReport) {
	p := NewLocalProxy()
	openFrame, openErr := p.OpenUDPExplicitFrame(41, "203.0.113.41", 443, 100)
	nativeFrame, nativeErr := p.SendUDPWithMode(41, []byte{0xaa}, 101, transport.UDPNativeDatagram)
	streamFrame, streamErr := p.SendUDPWithMode(41, []byte{0xbb}, 102, transport.UDPOverStreamFallback)
	passed := openErr == nil &&
		openFrame.FrameType == registry.FrameFlowOpen &&
		nativeErr == nil &&
		nativeFrame.FrameType == registry.FrameDatagramData &&
		streamErr == nil &&
		streamFrame.FrameType == registry.FrameStreamData
	report.addCase(
		"udp_native_and_stream_fallback",
		passed,
		"UDP uses DATAGRAM_DATA for native carriers and STREAM_DATA fallback for stream-only carriers",
	)
}

func addUDPTargetConfirmConformance(report *ProxyFlowConformanceReport) {
	p := NewLocalProxy()
	_, openErr := p.OpenUDPExplicitFrame(42, "203.0.113.42", 443, 100)
	confirmFrame, confirmFrameErr := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           42,
		TargetKind:       flow.TargetKindIPv4,
		SelectedIP:       []byte{203, 0, 113, 42},
		SelectedPort:     443,
		DNSAnswerSetHash: bytes.Repeat([]byte{0x00}, 48),
		TTLSeconds:       10,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	confirmErr := p.ReceiveUDPTargetConfirmFrameAt(confirmFrame, 105)
	state, stateOK := p.FlowState(42)
	_, expiredErr := p.SendUDPWithMode(42, []byte{0xcc}, 116, transport.UDPNativeDatagram)

	_, idleOpenErr := p.OpenUDPExplicitFrame(43, "203.0.113.43", 443, 200)
	_, idleErr := p.SendUDPWithMode(43, []byte{0xdd}, 231, transport.UDPNativeDatagram)

	passed := openErr == nil &&
		confirmFrameErr == nil &&
		confirmErr == nil &&
		stateOK &&
		bytes.Equal(state.ConfirmedHost, []byte{203, 0, 113, 42}) &&
		state.TTLSeconds == 15 &&
		expiredErr != nil &&
		idleOpenErr == nil &&
		idleErr != nil
	report.addCase(
		"udp_target_confirm_demux_ttl_idle",
		passed,
		"UDP_TARGET_CONFIRM is flow_id-authoritative and enforces target, TTL, and idle expiry",
	)
}

func addUDPFQDNFakeIPConformance(report *ProxyFlowConformanceReport) {
	p := NewLocalProxy()
	explicitFrame, explicitErr := p.OpenUDPExplicitFrame(51, "Example.COM", 443, 100)
	explicitOpen, explicitDecodeErr := decodeConformanceFlowOpen(explicitFrame)
	answer, fakeFrame, fakeErr := p.OpenUDPWithFakeDNSFrame(52, "Example.COM", []string{"93.184.216.34"}, 443, 100)
	fakeOpen, fakeDecodeErr := decodeConformanceFlowOpen(fakeFrame)

	m := flow.NewManager()
	implicitDomainErr := m.Open(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           53,
		FlowKind:         flow.FlowKindUDPAssociation,
		TargetKind:       flow.TargetKindDomainName,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		UDPFQDNMode:      flow.UDPFQDNClientResolvedNameBinding,
		NameBindingID:    bytes.Repeat([]byte{0x11}, 16),
		DNSAnswerSetHash: bytes.Repeat([]byte{0x22}, 48),
		LocalBindingMode: flow.LocalBindingExplicitProxyAPI,
		PriorityClass:    flow.PriorityRealtime,
	})

	passed := explicitErr == nil &&
		explicitDecodeErr == nil &&
		explicitOpen.TargetKind == flow.TargetKindDomainName &&
		explicitOpen.UDPFQDNMode == flow.UDPFQDNRelayResolvedFlowBound &&
		bytes.Equal(explicitOpen.OriginalDomainHint, []byte("example.com")) &&
		fakeErr == nil &&
		fakeDecodeErr == nil &&
		answer.FakeIP != "" &&
		fakeOpen.TargetKind == flow.TargetKindIPv4 &&
		net.IP(fakeOpen.TargetHost).String() == "93.184.216.34" &&
		fakeOpen.UDPFQDNMode == flow.UDPFQDNClientResolvedNameBinding &&
		fakeOpen.LocalBindingMode == flow.LocalBindingTransparentFakeIP &&
		len(fakeOpen.OriginalDomainHint) == 0 &&
		len(fakeOpen.NameBindingID) == 16 &&
		len(fakeOpen.DNSAnswerSetHash) == 48 &&
		implicitDomainErr != nil
	report.addCase(
		"udp_fqdn_policy_and_fake_ip",
		passed,
		"FQDN UDP requires explicit relay-resolved mode while transparent fake-IP targets real IP answers without raw domain hints",
	)
}

func addRealtimeStaleDropConformance(report *ProxyFlowConformanceReport) {
	p := NewLocalProxy()
	_, openErr := p.OpenUDPExplicitFrame(61, "203.0.113.61", 443, 100)
	_, staleErr := p.SendUDPWithOptions(61, []byte{0xee}, UDPSendOptions{
		NowUnix:               110,
		SentAtUnix:            100,
		UDPMode:               transport.UDPNativeDatagram,
		MaxRealtimeAgeSeconds: 5,
	})
	state, stateOK := p.FlowState(61)
	passed := openErr == nil &&
		staleErr != nil &&
		stateOK &&
		state.LastActivityUnix == 100
	report.addCase(
		"realtime_stale_drop",
		passed,
		"stale realtime UDP packets are dropped without removing or refreshing live flow state",
	)
}

func addDNSForwarderConformance(report *ProxyFlowConformanceReport) {
	p := NewLocalProxy()
	query := conformanceDNSAQuery(0x1234, "example.com")
	result, err := p.AnswerLocalDNSQuery(71, query, []string{"93.184.216.34"}, 100)
	_, _, fakeErr := p.OpenUDPFromFakeIPFrame(72, result.Answer.FakeIP, 443, 101)

	blockedQuery := conformanceDNSAQuery(0x1235, "blocked.example")
	p.dns.AddNegative("blocked.example", 100, 30)
	blocked, blockedErr := p.AnswerLocalDNSQuery(73, blockedQuery, []string{"203.0.113.73"}, 110)

	passed := err == nil &&
		len(result.Response) > len(query) &&
		result.Frame.FrameType == registry.FrameDNSMessage &&
		result.Frame.FlowID == 71 &&
		bytes.Equal(result.Frame.Payload, query) &&
		result.Answer.Domain == "example.com" &&
		result.Answer.FakeIP != "" &&
		fakeErr == nil &&
		blockedErr == nil &&
		len(blocked.Response) == len(blockedQuery) &&
		blocked.Frame.FrameType == 0 &&
		blocked.Answer.FakeIP == "" &&
		dnsRCode(blocked.Response) == 3
	report.addCase(
		"dns_forwarder_privacy_negative_cache",
		passed,
		"local DNS returns fake-IP answers through DNS frames and negative-cache NXDOMAIN without opening an Aurora frame",
	)
}

func decodeConformanceFlowOpen(frame protocol.AuroraFrame) (protocol.FlowOpen, error) {
	if frame.FrameType != registry.FrameFlowOpen {
		return protocol.FlowOpen{}, fmt.Errorf("client: expected FLOW_OPEN frame, got 0x%x", frame.FrameType)
	}
	if err := protocol.ValidateFlowManagementFrame(frame); err != nil {
		return protocol.FlowOpen{}, err
	}
	r := wire.NewReader(frame.Payload)
	open := protocol.DecodeFlowOpen(r)
	if r.Err() != nil {
		return protocol.FlowOpen{}, r.Err()
	}
	if !r.EOF() {
		return protocol.FlowOpen{}, fmt.Errorf("client: trailing FLOW_OPEN bytes")
	}
	return open, nil
}

func conformanceDNSAQuery(id uint16, domain string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range bytes.Split([]byte(domain), []byte(".")) {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00)
	query = binary.BigEndian.AppendUint16(query, 1)
	query = binary.BigEndian.AppendUint16(query, 1)
	return query
}

func dnsRCode(message []byte) uint16 {
	if len(message) < 4 {
		return 0xffff
	}
	return binary.BigEndian.Uint16(message[2:4]) & 0x000f
}

func FormatProxyFlowConformanceReport(report ProxyFlowConformanceReport) string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "flow_check passed=%t cases=%d failures=%d\n", report.Passed, len(report.Cases), len(report.Findings))
	for _, c := range report.Cases {
		fmt.Fprintf(&out, "flow_case %s passed=%t detail=%q\n", c.Name, c.Passed, c.Detail)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&out, "flow_finding %s\n", finding)
	}
	return out.String()
}
