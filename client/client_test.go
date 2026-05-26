package client

import (
	"bytes"
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
