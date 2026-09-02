package client

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/policy"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestEnginePlansAdversarialSplit2H2Baseline(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyAdversarialDPI)
	engine := Engine{Profile: profile}
	plan, err := engine.Plan(transport.Capabilities{SupportsH2: true, SupportsH1WS: true, CoverTemplateOK: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RouteModeID != registry.RouteSplit2 || plan.MethodID != registry.MethodWebH2Stream || plan.PersonalityID != registry.PersonalityProxyFlow {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.UDPMode != transport.UDPOverStreamFallback || !plan.PerformanceDowngrade {
		t.Fatalf("H2 UDP fallback downgrade not exposed: %+v", plan)
	}
}

func TestEngineRejectsRawDirectFallbackUnderAdversarialProfile(t *testing.T) {
	profile, _ := policy.ProfileByID(registry.PolicyAdversarialDPI)
	engine := Engine{Profile: profile}
	if _, err := engine.Plan(transport.Capabilities{CoverTemplateOK: true, SupportsH3: true, SupportsH3Dgram: true}); err == nil {
		t.Fatalf("expected no carrier rather than raw/direct fallback")
	}
}

func TestLocalProxyFlowTracksOpenAndClose(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(1, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	if !p.HasFlow(1) {
		t.Fatalf("flow was not tracked")
	}
	if err := p.Close(1); err != nil {
		t.Fatal(err)
	}
	if p.HasFlow(1) {
		t.Fatalf("flow was not closed")
	}
}

func TestLocalProxyHTTPConnectOpensExplicitTCPFlow(t *testing.T) {
	p := NewLocalProxy()
	response, err := p.OpenHTTPConnectRequest(50, []byte("CONNECT Example.COM:443 HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")) {
		t.Fatalf("unexpected HTTP CONNECT response: %q", response)
	}
	state, ok := p.FlowState(50)
	if !ok {
		t.Fatalf("HTTP CONNECT did not open a flow")
	}
	if state.Kind != flow.FlowKindTCPStream || state.TargetKind != flow.TargetKindDomainName || string(state.TargetHost) != "example.com" || state.TargetPort != 443 {
		t.Fatalf("unexpected HTTP CONNECT flow: %+v", state)
	}
	if state.LocalBindingMode != flow.LocalBindingExplicitProxyAPI || state.PriorityClass != flow.PriorityInteractive {
		t.Fatalf("HTTP CONNECT flow used wrong local binding: %+v", state)
	}
}

func TestLocalProxyHTTPConnectRejectsNonConnect(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenHTTPConnectRequest(51, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err == nil {
		t.Fatalf("non-CONNECT request opened a local TCP flow")
	}
	if p.HasFlow(51) {
		t.Fatalf("rejected HTTP request left a flow behind")
	}
}

func TestLocalProxyHTTPConnectUsesRequestTargetOverHostHeader(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenHTTPConnectRequest(55, []byte("CONNECT Good.EXAMPLE:443 HTTP/1.1\r\nHost: bad.example:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	state, ok := p.FlowState(55)
	if !ok {
		t.Fatalf("HTTP CONNECT did not open a flow")
	}
	if string(state.TargetHost) != "good.example" || state.TargetPort != 443 {
		t.Fatalf("HTTP CONNECT trusted mismatched Host header: %+v", state)
	}
}

func TestSOCKS5GreetingSelectsNoAuth(t *testing.T) {
	response, err := HandleSOCKS5Greeting([]byte{0x05, 0x02, 0x02, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte{0x05, 0x00}) {
		t.Fatalf("unexpected SOCKS5 greeting response: %x", response)
	}
}

func TestSOCKS5GreetingRejectsAuthOnly(t *testing.T) {
	if _, err := HandleSOCKS5Greeting([]byte{0x05, 0x01, 0x02}); err == nil {
		t.Fatalf("auth-only SOCKS5 greeting was accepted")
	}
}

func TestLocalProxySOCKS5ConnectOpensDomainTCPFlow(t *testing.T) {
	p := NewLocalProxy()
	request := append([]byte{0x05, 0x01, 0x00, 0x03, 0x0b}, []byte("Example.COM")...)
	request = append(request, 0x01, 0xbb)
	response, err := p.OpenSOCKS5ConnectRequest(52, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("unexpected SOCKS5 CONNECT response: %x", response)
	}
	state, ok := p.FlowState(52)
	if !ok {
		t.Fatalf("SOCKS5 CONNECT did not open a flow")
	}
	if state.Kind != flow.FlowKindTCPStream || state.TargetKind != flow.TargetKindDomainName || string(state.TargetHost) != "example.com" || state.TargetPort != 443 {
		t.Fatalf("unexpected SOCKS5 CONNECT flow: %+v", state)
	}
}

func TestSOCKS5UDPAssociateReturnsBindEndpoint(t *testing.T) {
	response, err := HandleSOCKS5UDPAssociateRequest([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, "127.0.0.1", 1081)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x39}
	if !bytes.Equal(response, want) {
		t.Fatalf("unexpected SOCKS5 UDP ASSOCIATE response: %x", response)
	}
}

func TestLocalProxySOCKS5UDPDatagramOpensRelayResolvedFlow(t *testing.T) {
	p := NewLocalProxy()
	packet := append([]byte{0x00, 0x00, 0x00, 0x03, 0x0b}, []byte("Example.COM")...)
	packet = append(packet, 0x01, 0xbb)
	packet = append(packet, []byte("payload")...)
	frame, err := p.HandleSOCKS5UDPDatagram(53, packet, 100, transport.UDPOverStreamFallback)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameStreamData || frame.FlowID != 53 || !bytes.Equal(frame.Payload, []byte("payload")) {
		t.Fatalf("unexpected SOCKS5 UDP frame: %+v", frame)
	}
	state, ok := p.FlowState(53)
	if !ok {
		t.Fatalf("SOCKS5 UDP datagram did not open a flow")
	}
	if state.Kind != flow.FlowKindUDPAssociation || state.TargetKind != flow.TargetKindDomainName || string(state.TargetHost) != "example.com" || state.TargetPort != 443 {
		t.Fatalf("unexpected SOCKS5 UDP flow: %+v", state)
	}
	if state.UDPFQDNMode != flow.UDPFQDNRelayResolvedFlowBound || state.LocalBindingMode != flow.LocalBindingExplicitProxyAPI || state.PriorityClass != flow.PriorityRealtime {
		t.Fatalf("SOCKS5 UDP flow used wrong binding semantics: %+v", state)
	}
}

func TestLocalProxySOCKS5UDPDatagramFramesPrependsFlowOpenForFirstDatagram(t *testing.T) {
	p := NewLocalProxy()
	packet := append([]byte{0x00, 0x00, 0x00, 0x03, 0x0b}, []byte("Example.COM")...)
	packet = append(packet, 0x01, 0xbb)
	packet = append(packet, []byte("payload")...)

	frames, err := p.HandleSOCKS5UDPDatagramFrames(61, packet, 100, transport.UDPOverStreamFallback)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("first SOCKS5 UDP datagram should emit FLOW_OPEN and data, got %d frames", len(frames))
	}
	if frames[0].FrameType != registry.FrameFlowOpen || frames[0].FlowID != 61 {
		t.Fatalf("first SOCKS5 UDP frame was not FLOW_OPEN: %+v", frames[0])
	}
	open := protocol.DecodeFlowOpen(wire.NewReader(frames[0].Payload))
	if open.FlowID != 61 || open.FlowKind != flow.FlowKindUDPAssociation || open.TargetKind != flow.TargetKindDomainName || string(open.TargetHost) != "example.com" {
		t.Fatalf("unexpected SOCKS5 UDP FLOW_OPEN payload: %+v", open)
	}
	if open.UDPFQDNMode != flow.UDPFQDNRelayResolvedFlowBound || open.LocalBindingMode != flow.LocalBindingExplicitProxyAPI || string(open.OriginalDomainHint) != "example.com" {
		t.Fatalf("SOCKS5 UDP FLOW_OPEN used wrong explicit FQDN semantics: %+v", open)
	}
	if frames[1].FrameType != registry.FrameStreamData || frames[1].FlowID != 61 || !bytes.Equal(frames[1].Payload, []byte("payload")) {
		t.Fatalf("second SOCKS5 UDP frame was not stream fallback data: %+v", frames[1])
	}

	nextPacket := append([]byte{0x00, 0x00, 0x00, 0x03, 0x0b}, []byte("Example.COM")...)
	nextPacket = append(nextPacket, 0x01, 0xbb)
	nextPacket = append(nextPacket, []byte("again")...)
	frames, err = p.HandleSOCKS5UDPDatagramFrames(61, nextPacket, 101, transport.UDPOverStreamFallback)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].FrameType != registry.FrameStreamData || !bytes.Equal(frames[0].Payload, []byte("again")) {
		t.Fatalf("established SOCKS5 UDP flow should only emit data frame: %+v", frames)
	}
}

func TestLocalProxyOpensTransparentUDPFromFakeIPMap(t *testing.T) {
	p := NewLocalProxy()
	answer, err := p.ResolveFakeDNS("Example.COM.", []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := p.OpenUDPFromFakeIP(57, answer.FakeIP, 443, 101)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Domain != "example.com" || mapped.FakeIP != answer.FakeIP {
		t.Fatalf("unexpected mapped fake-IP answer: %+v", mapped)
	}
	state, ok := p.FlowState(57)
	if !ok {
		t.Fatalf("mapped fake-IP UDP flow was not opened")
	}
	if state.Kind != flow.FlowKindUDPAssociation || state.TargetKind != flow.TargetKindIPv4 || !bytes.Equal(state.TargetHost, []byte{93, 184, 216, 34}) {
		t.Fatalf("mapped fake-IP UDP flow did not target the real IP answer: %+v", state)
	}
	if state.UDPFQDNMode != flow.UDPFQDNClientResolvedNameBinding || state.LocalBindingMode != flow.LocalBindingTransparentFakeIP {
		t.Fatalf("mapped fake-IP UDP flow used wrong binding semantics: %+v", state)
	}
	if !bytes.Equal(state.NameBindingID, answer.NameBindingID) || !bytes.Equal(state.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("mapped fake-IP UDP flow leaked or lost DNS binding: %+v", state)
	}
}

func TestLocalProxyOpenUDPFromFakeIPFrameReturnsFlowOpen(t *testing.T) {
	p := NewLocalProxy()
	answer, err := p.ResolveFakeDNS("Example.COM.", []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	mapped, frame, err := p.OpenUDPFromFakeIPFrame(62, answer.FakeIP, 443, 101)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Domain != "example.com" || mapped.FakeIP != answer.FakeIP {
		t.Fatalf("unexpected mapped fake-IP answer: %+v", mapped)
	}
	if frame.FrameType != registry.FrameFlowOpen || frame.FlowID != 62 {
		t.Fatalf("unexpected mapped fake-IP FLOW_OPEN frame: %+v", frame)
	}
	open := protocol.DecodeFlowOpen(wire.NewReader(frame.Payload))
	if open.FlowID != 62 || open.FlowKind != flow.FlowKindUDPAssociation || open.TargetKind != flow.TargetKindIPv4 || !bytes.Equal(open.TargetHost, []byte{93, 184, 216, 34}) {
		t.Fatalf("unexpected mapped fake-IP FLOW_OPEN payload: %+v", open)
	}
	if open.UDPFQDNMode != flow.UDPFQDNClientResolvedNameBinding || open.LocalBindingMode != flow.LocalBindingTransparentFakeIP || len(open.OriginalDomainHint) != 0 {
		t.Fatalf("mapped fake-IP FLOW_OPEN leaked domain semantics: %+v", open)
	}
	if !bytes.Equal(open.NameBindingID, answer.NameBindingID) || !bytes.Equal(open.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("mapped fake-IP FLOW_OPEN lost DNS binding metadata")
	}
}

func TestLocalProxyAnswersLocalDNSQueryThroughForwarder(t *testing.T) {
	p := NewLocalProxy()
	query := clientDNSQuestion(0x2222, "Example.COM", 1)

	result, err := p.AnswerLocalDNSQuery(58, query, []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Frame.FrameType != registry.FrameDNSMessage || result.Frame.FlowID != 58 || !bytes.Equal(result.Frame.Payload, query) {
		t.Fatalf("local DNS query was not forwarded as DNS frame: %+v", result.Frame)
	}
	if result.Answer.Domain != "example.com" || result.Answer.FakeIP == "" || result.Answer.FakeIP == "93.184.216.34" {
		t.Fatalf("local DNS query did not synthesize fake-IP answer: %+v", result.Answer)
	}
	if binary.BigEndian.Uint16(result.Response[0:2]) != 0x2222 || binary.BigEndian.Uint16(result.Response[6:8]) != 1 {
		t.Fatalf("local DNS response did not preserve id and answer count: %x", result.Response[:12])
	}
}

func TestLocalProxySOCKS5UDPDatagramRejectsFragments(t *testing.T) {
	p := NewLocalProxy()
	packet := append([]byte{0x00, 0x00, 0x01, 0x03, 0x0b}, []byte("example.com")...)
	packet = append(packet, 0x01, 0xbb, 'x')
	if _, err := p.HandleSOCKS5UDPDatagram(54, packet, 100, transport.UDPNativeDatagram); err == nil {
		t.Fatalf("fragmented SOCKS5 UDP datagram was accepted")
	}
	if p.HasFlow(54) {
		t.Fatalf("rejected SOCKS5 UDP datagram left a flow behind")
	}
}

func TestLocalProxyOpensUDPWithFakeDNSWithoutDomainLeak(t *testing.T) {
	p := NewLocalProxy()
	answer, err := p.OpenUDPWithFakeDNS(2, "Example.COM.", []string{"93.184.216.34"}, 443, 100)
	if err != nil {
		t.Fatal(err)
	}
	state, ok := p.FlowState(2)
	if !ok {
		t.Fatalf("UDP flow was not tracked")
	}
	if state.Kind != flow.FlowKindUDPAssociation || state.TargetKind != flow.TargetKindIPv4 {
		t.Fatalf("unexpected UDP fake-IP flow state: %+v", state)
	}
	if state.UDPFQDNMode != flow.UDPFQDNClientResolvedNameBinding || state.LocalBindingMode != flow.LocalBindingTransparentFakeIP {
		t.Fatalf("UDP fake-IP flow used wrong binding mode: %+v", state)
	}
	if bytes.Contains(state.TargetHost, []byte("example.com")) {
		t.Fatalf("raw domain leaked into UDP target host")
	}
	if !bytes.Equal(state.NameBindingID, answer.NameBindingID) || !bytes.Equal(state.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("flow state does not match DNS synthetic answer")
	}
}

func TestLocalProxyOpenTCPFrameTracksFlowAndReturnsFlowOpen(t *testing.T) {
	p := NewLocalProxy()
	frame, err := p.OpenTCPFrame(59, "Example.COM", 443)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameFlowOpen || frame.FlowID != 59 {
		t.Fatalf("unexpected TCP FLOW_OPEN frame: %+v", frame)
	}
	open := protocol.DecodeFlowOpen(wire.NewReader(frame.Payload))
	if open.FlowID != 59 || open.FlowKind != flow.FlowKindTCPStream || open.TargetKind != flow.TargetKindDomainName || string(open.TargetHost) != "example.com" || open.TargetPort != 443 {
		t.Fatalf("unexpected TCP FLOW_OPEN payload: %+v", open)
	}
	if open.LocalBindingMode != flow.LocalBindingExplicitProxyAPI || open.PriorityClass != flow.PriorityInteractive {
		t.Fatalf("TCP FLOW_OPEN used wrong local binding: %+v", open)
	}
	state, ok := p.FlowState(59)
	if !ok {
		t.Fatalf("TCP frame open did not track flow")
	}
	if state.Kind != open.FlowKind || state.TargetKind != open.TargetKind || !bytes.Equal(state.TargetHost, open.TargetHost) {
		t.Fatalf("tracked TCP flow does not match frame payload: state=%+v open=%+v", state, open)
	}
}

func TestLocalProxyOpenUDPWithFakeDNSFrameReturnsIPAuthoritativeFlowOpen(t *testing.T) {
	p := NewLocalProxy()
	answer, frame, err := p.OpenUDPWithFakeDNSFrame(60, "Example.COM.", []string{"93.184.216.34"}, 443, 100)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameFlowOpen || frame.FlowID != 60 {
		t.Fatalf("unexpected UDP FLOW_OPEN frame: %+v", frame)
	}
	open := protocol.DecodeFlowOpen(wire.NewReader(frame.Payload))
	if open.FlowID != 60 || open.FlowKind != flow.FlowKindUDPAssociation || open.TargetKind != flow.TargetKindIPv4 || !bytes.Equal(open.TargetHost, []byte{93, 184, 216, 34}) {
		t.Fatalf("unexpected UDP FLOW_OPEN payload: %+v", open)
	}
	if open.UDPFQDNMode != flow.UDPFQDNClientResolvedNameBinding || open.LocalBindingMode != flow.LocalBindingTransparentFakeIP {
		t.Fatalf("UDP FLOW_OPEN used wrong fake-IP binding: %+v", open)
	}
	if len(open.OriginalDomainHint) != 0 || bytes.Contains(open.TargetHost, []byte("example.com")) {
		t.Fatalf("UDP FLOW_OPEN leaked raw domain: %+v", open)
	}
	if !bytes.Equal(open.NameBindingID, answer.NameBindingID) || !bytes.Equal(open.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("UDP FLOW_OPEN did not carry DNS binding metadata")
	}
	if _, ok := p.FlowState(60); !ok {
		t.Fatalf("UDP frame open did not track flow")
	}
}

func TestLocalProxyOpenUDPExplicitFrameReturnsRelayResolvedFlowOpen(t *testing.T) {
	p := NewLocalProxy()
	frame, err := p.OpenUDPExplicitFrame(63, "Example.COM.", 443, 100)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameFlowOpen || frame.FlowID != 63 {
		t.Fatalf("unexpected explicit UDP FLOW_OPEN frame: %+v", frame)
	}
	open := protocol.DecodeFlowOpen(wire.NewReader(frame.Payload))
	if open.FlowID != 63 || open.FlowKind != flow.FlowKindUDPAssociation || open.TargetKind != flow.TargetKindDomainName || string(open.TargetHost) != "example.com" {
		t.Fatalf("unexpected explicit UDP FLOW_OPEN payload: %+v", open)
	}
	if open.UDPFQDNMode != flow.UDPFQDNRelayResolvedFlowBound || open.LocalBindingMode != flow.LocalBindingExplicitProxyAPI || string(open.OriginalDomainHint) != "example.com" {
		t.Fatalf("explicit UDP FLOW_OPEN used wrong FQDN semantics: %+v", open)
	}
	state, ok := p.FlowState(63)
	if !ok {
		t.Fatalf("explicit UDP frame open did not track flow")
	}
	if state.Kind != open.FlowKind || state.TargetKind != open.TargetKind || !bytes.Equal(state.TargetHost, open.TargetHost) {
		t.Fatalf("tracked explicit UDP flow does not match frame payload: state=%+v open=%+v", state, open)
	}
}

func TestLocalProxyOpenUDPExplicitTracksFlowWithoutReturningFrame(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenUDPExplicit(64, "Example.COM.", 443, 100); err != nil {
		t.Fatal(err)
	}
	state, ok := p.FlowState(64)
	if !ok {
		t.Fatal("explicit UDP open did not track flow")
	}
	if state.Kind != flow.FlowKindUDPAssociation || state.TargetKind != flow.TargetKindDomainName || string(state.TargetHost) != "example.com" {
		t.Fatalf("tracked explicit UDP flow = %+v", state)
	}
	if err := p.OpenUDPExplicit(65, "bad/host", 443, 100); err == nil {
		t.Fatal("explicit UDP open accepted an invalid target host")
	}
	if _, ok := p.FlowState(65); ok {
		t.Fatal("failed explicit UDP open tracked flow")
	}
}

func TestLocalProxyBuildsTCPStreamDataFrameForLiveTCPFlow(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(3, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	frame, err := p.SendTCP(3, []byte("GET / HTTP/2\r\n\r\n"), 0x01)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameStreamData || frame.FlowID != 3 || frame.Flags != 0x01 || !bytes.Equal(frame.Payload, []byte("GET / HTTP/2\r\n\r\n")) {
		t.Fatalf("unexpected TCP stream frame: %+v", frame)
	}
	if err := protocol.ValidateFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
		t.Fatalf("stream frame did not validate: %v", err)
	}
}

func TestLocalProxySchedulesTCPFramesByPriority(t *testing.T) {
	p := NewLocalProxyWithOptions(LocalProxyOptions{MaxBufferedTCPBytes: 1024})
	if err := p.OpenTCPWithPriority(31, "bulk.example", 443, flow.PriorityBulk); err != nil {
		t.Fatal(err)
	}
	if err := p.OpenTCPWithPriority(32, "interactive.example", 443, flow.PriorityInteractive); err != nil {
		t.Fatal(err)
	}
	if err := p.EnqueueTCP(31, []byte("bulk"), 0); err != nil {
		t.Fatal(err)
	}
	if err := p.EnqueueTCP(32, []byte("interactive"), 0x01); err != nil {
		t.Fatal(err)
	}
	frame, ok, err := p.NextTCPFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || frame.FlowID != 32 || frame.FrameType != registry.FrameStreamData || frame.Flags != 0x01 || !bytes.Equal(frame.Payload, []byte("interactive")) {
		t.Fatalf("interactive stream data was not scheduled first: ok=%v frame=%+v", ok, frame)
	}
}

func TestLocalProxyAppliesTCPBackpressureAndReleasesCapacity(t *testing.T) {
	p := NewLocalProxyWithOptions(LocalProxyOptions{MaxBufferedTCPBytes: 4})
	if err := p.OpenTCP(33, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	if err := p.EnqueueTCP(33, []byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	if err := p.EnqueueTCP(33, []byte("de"), 0); err == nil {
		t.Fatalf("TCP scheduler accepted data past buffer limit")
	}
	if _, ok, err := p.NextTCPFrame(); err != nil || !ok {
		t.Fatalf("scheduler did not release a frame: ok=%v err=%v", ok, err)
	}
	if err := p.EnqueueTCP(33, []byte("de"), 0); err != nil {
		t.Fatalf("scheduler did not release capacity after dequeue: %v", err)
	}
}

func TestLocalProxyBuildsUDPDatagramFrameForLiveUDPFlow(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenUDPWithFakeDNS(4, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	frame, err := p.SendUDP(4, []byte("payload"), 101)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameDatagramData || frame.FlowID != 4 || !bytes.Equal(frame.Payload, []byte("payload")) {
		t.Fatalf("unexpected UDP datagram frame: %+v", frame)
	}
}

func TestLocalProxyReceiveUDPTargetConfirmFrameRejectsMismatchBeforeMutation(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenUDPWithFakeDNS(44, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           44,
		TargetKind:       flow.TargetKindIPv4,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: flow.DNSAnswerSetHash([]string{"93.184.216.34"}),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame.FlowID = 45
	if err := p.ReceiveUDPTargetConfirmFrame(frame); err == nil {
		t.Fatalf("mismatched UDP target confirm frame was accepted")
	}
	state, ok := p.FlowState(44)
	if !ok {
		t.Fatalf("flow should remain tracked after rejected frame")
	}
	if len(state.ConfirmedHost) != 0 || state.ConfirmedPort != 0 {
		t.Fatalf("mismatched target confirm mutated local flow state: %+v", state)
	}
}

func TestLocalProxyReceiveUDPTargetConfirmFrameAppliesTTL(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenUDPWithFakeDNS(47, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           47,
		TargetKind:       flow.TargetKindIPv4,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: flow.DNSAnswerSetHash([]string{"93.184.216.34"}),
		TTLSeconds:       5,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ReceiveUDPTargetConfirmFrameAt(frame, 110); err != nil {
		t.Fatal(err)
	}
	state, ok := p.FlowState(47)
	if !ok {
		t.Fatalf("confirmed local UDP flow was removed")
	}
	if state.ConfirmedTTLSeconds != 5 || state.ConfirmedAtUnix != 110 || state.TTLSeconds != 15 {
		t.Fatalf("local UDP confirm TTL was not applied: %+v", state)
	}
	if _, err := p.SendUDP(47, []byte("fresh"), 114); err != nil {
		t.Fatalf("fresh UDP datagram before confirmed TTL was rejected: %v", err)
	}
	if _, err := p.SendUDP(47, []byte("late"), 116); err == nil {
		t.Fatalf("UDP datagram after confirmed target TTL was accepted")
	}
}

func TestLocalProxyBuildsUDPStreamFrameForFallbackCarrier(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenUDPWithFakeDNS(41, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	frame, err := p.SendUDPWithMode(41, []byte("payload"), 101, transport.UDPOverStreamFallback)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameStreamData || frame.FlowID != 41 || !bytes.Equal(frame.Payload, []byte("payload")) {
		t.Fatalf("unexpected UDP stream fallback frame: %+v", frame)
	}
}

func TestLocalProxyDropsStaleRealtimeUDPInStreamFallback(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenUDPWithFakeDNS(43, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	_, err := p.SendUDPWithOptions(43, []byte("late"), UDPSendOptions{
		NowUnix:               110,
		SentAtUnix:            100,
		UDPMode:               transport.UDPOverStreamFallback,
		MaxRealtimeAgeSeconds: 5,
	})
	if err == nil {
		t.Fatalf("stale realtime UDP fallback datagram was accepted")
	}
	state, ok := p.FlowState(43)
	if !ok {
		t.Fatalf("stale UDP datagram should not remove an otherwise live flow")
	}
	if state.LastActivityUnix != 100 {
		t.Fatalf("stale UDP datagram refreshed flow activity to %d", state.LastActivityUnix)
	}
	frame, err := p.SendUDPWithOptions(43, []byte("fresh"), UDPSendOptions{
		NowUnix:               111,
		SentAtUnix:            109,
		UDPMode:               transport.UDPOverStreamFallback,
		MaxRealtimeAgeSeconds: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameStreamData || !bytes.Equal(frame.Payload, []byte("fresh")) {
		t.Fatalf("fresh fallback datagram was not framed as stream data: %+v", frame)
	}
}

func TestLocalProxyRejectsUnsupportedUDPModeWithoutRefreshingFlow(t *testing.T) {
	p := NewLocalProxy()
	if _, err := p.OpenUDPWithFakeDNS(42, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SendUDPWithMode(42, []byte("payload"), 101, transport.UDPUnsupported); err == nil {
		t.Fatalf("unsupported UDP mode was accepted")
	}
	state, ok := p.FlowState(42)
	if !ok {
		t.Fatalf("flow was unexpectedly removed")
	}
	if state.LastActivityUnix != 100 {
		t.Fatalf("unsupported UDP mode refreshed flow activity to %d", state.LastActivityUnix)
	}
}

func TestLocalProxyRejectsDataForWrongOrExpiredFlow(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(5, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SendUDP(5, []byte("wrong kind"), 100); err == nil {
		t.Fatalf("TCP flow accepted UDP datagram")
	}
	if _, err := p.OpenUDPWithFakeDNS(6, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SendTCP(6, []byte("wrong kind"), 0); err == nil {
		t.Fatalf("UDP flow accepted TCP stream data")
	}
	if _, err := p.SendUDP(6, []byte("late"), 500); err == nil {
		t.Fatalf("expired UDP flow accepted datagram")
	}
}

func TestLocalProxyCloseFrameReleasesFlowAndReturnsFlowClose(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(7, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	frame, err := p.CloseFrame(7, 42, []byte("done"))
	if err != nil {
		t.Fatal(err)
	}
	if p.HasFlow(7) {
		t.Fatalf("flow remained tracked after CloseFrame")
	}
	if frame.FrameType != registry.FrameFlowClose || frame.FlowID != 7 {
		t.Fatalf("unexpected close frame: %+v", frame)
	}
	close := protocol.DecodeFlowClose(wire.NewReader(frame.Payload))
	if close.FlowID != 7 || close.CloseCode != protocol.CloseNormal || !close.FinalSequenceHintPresent || close.FinalSequenceHint != 42 || !bytes.Equal(close.Reason, []byte("done")) {
		t.Fatalf("unexpected close payload: %+v", close)
	}
}

func TestLocalProxyGracefulCloseKeepsHalfClosedStateAndCompletesOnPeerClose(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(40, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	frame, err := p.GracefulCloseFrame(40, 42, []byte("done"), 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameFlowClose || frame.FlowID != 40 {
		t.Fatalf("unexpected close frame: %+v", frame)
	}
	state, ok := p.FlowState(40)
	if !ok {
		t.Fatalf("gracefully closed flow was released before peer close")
	}
	if !state.LocalClosed || state.PeerClosed || state.FinalSequenceHint != 42 || state.DrainUntilUnix != 105 {
		t.Fatalf("unexpected graceful close state: %+v", state)
	}
	if _, err := p.SendTCP(40, []byte("late"), 0); err == nil {
		t.Fatalf("local TCP write succeeded after local close")
	}
	if err := p.ReceiveFlowClose(protocol.FlowClose{FlowID: 40, CloseCode: protocol.CloseNormal}, 101, 5); err != nil {
		t.Fatal(err)
	}
	if p.HasFlow(40) {
		t.Fatalf("flow remained tracked after both sides closed")
	}
}

func TestLocalProxyPurgeClosedReleasesHalfClosedFlowAtDrainDeadline(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(45, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GracefulCloseFrame(45, 0, nil, 100, 5); err != nil {
		t.Fatal(err)
	}

	p.PurgeClosed(104)
	if !p.HasFlow(45) {
		t.Fatal("half-closed flow was purged before its drain deadline")
	}
	p.PurgeClosed(105)
	if p.HasFlow(45) {
		t.Fatal("half-closed flow remained tracked at its drain deadline")
	}
}

func TestLocalProxyReceiveFlowCloseFrameRejectsMismatchBeforeMutation(t *testing.T) {
	p := NewLocalProxy()
	if err := p.OpenTCP(46, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 46, CloseCode: protocol.CloseNormal})
	if err != nil {
		t.Fatal(err)
	}
	frame.FlowID = 47
	if err := p.ReceiveFlowCloseFrame(frame, 101, 5); err == nil {
		t.Fatalf("mismatched FLOW_CLOSE frame was accepted")
	}
	state, ok := p.FlowState(46)
	if !ok {
		t.Fatalf("flow should remain tracked after rejected frame")
	}
	if state.PeerClosed || state.LocalClosed || state.DrainUntilUnix != 0 {
		t.Fatalf("mismatched close frame mutated local flow state: %+v", state)
	}
}

func clientDNSQuestion(id uint16, domain string, qtype uint16) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100)
	binary.BigEndian.PutUint16(out[4:6], 1)
	for _, label := range bytes.Split([]byte(domain), []byte(".")) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, 1)
	return out
}
