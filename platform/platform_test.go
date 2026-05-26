package platform

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestAdaptersAreThinPacketIoOnly(t *testing.T) {
	for _, adapter := range []Adapter{NewMockAdapter("linux"), NewMockAdapter("apple"), NewMockAdapter("android"), NewMockAdapter("windows")} {
		if adapter.HasCryptoState() {
			t.Fatalf("%s adapter contains crypto state", adapter.Name())
		}
		if err := adapter.Start(SessionConfig{SessionID: "s1"}); err != nil {
			t.Fatal(err)
		}
		if err := adapter.SubmitPacket([]byte{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		pkt, ok := adapter.ReadPacket()
		if !ok || string(pkt) != string([]byte{1, 2, 3}) {
			t.Fatalf("%s adapter failed packet loopback", adapter.Name())
		}
	}
}

func TestNetworkChangeIsForwardedAsEvent(t *testing.T) {
	a := NewMockAdapter("apple")
	_ = a.Start(SessionConfig{SessionID: "s1"})
	a.NotifyNetworkChange(PathInfo{Interface: "wifi", Expensive: false})
	events := a.Events()
	if len(events) != 1 || events[0].Type != EventNetworkChange {
		t.Fatalf("network change not forwarded: %+v", events)
	}
}

func TestPlatformProfilesMatchRequiredLocalInterfaces(t *testing.T) {
	cases := []struct {
		kind              Kind
		wantPacket        string
		wantLocalProxy    bool
		wantLocalModes    []string
		wantNoEntitlement bool
	}{
		{KindLinux, PacketTUN, true, []string{LocalSOCKS5, LocalHTTPConnect, LocalDNSForwarder}, false},
		{KindWindows, PacketWintun, true, []string{LocalSOCKS5, LocalHTTPConnect, LocalDNSForwarder}, false},
		{KindApple, PacketNetworkExtension, true, []string{LocalSOCKS5, LocalHTTPConnect, LocalDNSForwarder}, false},
		{KindAndroid, PacketVpnService, true, []string{LocalSOCKS5, LocalHTTPConnect, LocalDNSForwarder}, false},
		{KindFreeBSD, PacketTUN, true, []string{LocalSOCKS5, LocalHTTPConnect, LocalDNSForwarder}, false},
		{KindOpenWrt, PacketTUN, true, []string{LocalSOCKS5, LocalHTTPConnect, LocalDNSForwarder}, false},
		{KindCI, PacketNone, true, []string{LocalSOCKS5, LocalHTTPConnect}, true},
	}
	for _, tc := range cases {
		profile := ProfileFor(tc.kind)
		if profile.PacketMode != tc.wantPacket {
			t.Fatalf("%s packet mode = %s, want %s", tc.kind, profile.PacketMode, tc.wantPacket)
		}
		if profile.SupportsLocalProxy != tc.wantLocalProxy {
			t.Fatalf("%s local proxy = %v, want %v", tc.kind, profile.SupportsLocalProxy, tc.wantLocalProxy)
		}
		if !profile.HasNoKernelLocalInterface() {
			t.Fatalf("%s profile has no no-kernel local interface", tc.kind)
		}
		assertLocalModes(t, profile, tc.wantLocalModes)
		if profile.NoEntitlementOnly != tc.wantNoEntitlement {
			t.Fatalf("%s no-entitlement = %v, want %v", tc.kind, profile.NoEntitlementOnly, tc.wantNoEntitlement)
		}
		if profile.ContainsCryptoState {
			t.Fatalf("%s profile contains crypto state", tc.kind)
		}
	}
}

func assertLocalModes(t *testing.T, profile Profile, want []string) {
	t.Helper()
	if len(profile.LocalModes) != len(want) {
		t.Fatalf("%s local modes = %v, want %v", profile.Kind, profile.LocalModes, want)
	}
	for _, mode := range want {
		if !profile.SupportsLocalMode(mode) {
			t.Fatalf("%s does not support local mode %s; modes=%v", profile.Kind, mode, profile.LocalModes)
		}
	}
}

func TestThinAdapterForwardsCoreABIWithoutCryptoState(t *testing.T) {
	sink := &recordingCoreSink{}
	adapter := NewThinAdapter(ProfileFor(KindCI), sink)
	if adapter.HasCryptoState() {
		t.Fatalf("thin adapter reported crypto state")
	}
	if err := adapter.OpenSession([]byte("cfg")); err != nil {
		t.Fatal(err)
	}
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           1,
		FlowKind:         flow.FlowKindTCPStream,
		TargetKind:       flow.TargetKindDomainName,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		NameBindingID:    bytes.Repeat([]byte{1}, 16),
		DNSAnswerSetHash: bytes.Repeat([]byte{2}, 48),
	}
	if err := adapter.SubmitTCPFlow(open); err != nil {
		t.Fatal(err)
	}
	open.TargetHost[0] = 'x'
	if err := adapter.SubmitUDPDatagram(2, []byte{9, 8, 7}); err != nil {
		t.Fatal(err)
	}
	dns := []byte{0x12, 0x34, 0x01, 0x00}
	if err := adapter.SubmitDNSMessage(3, dns); err != nil {
		t.Fatal(err)
	}
	dns[0] = 0
	adapter.NotifyNetworkChange(PathInfo{Interface: "wifi"})
	if sink.openSessions != 1 || sink.tcpFlows != 1 || sink.udpDatagrams != 1 || sink.dnsMessages != 1 || sink.networkChanges != 1 {
		t.Fatalf("adapter did not forward ABI calls: %+v", sink)
	}
	if !bytes.Equal(sink.lastTCPFlow.TargetHost, []byte("example.com")) {
		t.Fatalf("TCP flow target host was not copied before forwarding: %q", sink.lastTCPFlow.TargetHost)
	}
	if !bytes.Equal(sink.lastDNSMessage, []byte{0x12, 0x34, 0x01, 0x00}) {
		t.Fatalf("DNS message was not copied before forwarding: %x", sink.lastDNSMessage)
	}
}

func TestAdapterBlueprintsCoverP8Platforms(t *testing.T) {
	report, err := VerifyAdapterBlueprints(AdapterBlueprints())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("platform adapter conformance failed: %+v", report)
	}
	if len(report.Platforms) != 7 || len(report.Failures) != 0 {
		t.Fatalf("unexpected platform report shape: %+v", report)
	}
	wantPackets := map[Kind]string{
		KindLinux:   PacketTUN,
		KindWindows: PacketWintun,
		KindApple:   PacketNetworkExtension,
		KindAndroid: PacketVpnService,
		KindFreeBSD: PacketTUN,
		KindOpenWrt: PacketTUN,
		KindCI:      PacketNone,
	}
	for _, platform := range report.Platforms {
		if platform.PacketMode != wantPackets[platform.Kind] {
			t.Fatalf("%s packet mode = %s, want %s", platform.Kind, platform.PacketMode, wantPackets[platform.Kind])
		}
		if !platform.LocalProxyFallback || !platform.NoCryptoState || !platform.BoundaryComplete {
			t.Fatalf("%s does not satisfy P8 adapter boundary: %+v", platform.Kind, platform)
		}
		delete(wantPackets, platform.Kind)
	}
	if len(wantPackets) != 0 {
		t.Fatalf("missing platform adapter blueprints: %+v", wantPackets)
	}
}

func TestAdapterBlueprintVerificationRejectsMissingProxyFallback(t *testing.T) {
	blueprints := AdapterBlueprints()
	blueprints[0].LocalModes = nil
	report, err := VerifyAdapterBlueprints(blueprints)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("platform adapter conformance accepted missing proxy fallback: %+v", report)
	}
	if len(report.Failures) != 1 || report.Failures[0].Field != "local_proxy_fallback" {
		t.Fatalf("unexpected platform adapter failure report: %+v", report.Failures)
	}
}

type recordingCoreSink struct {
	openSessions   int
	tcpFlows       int
	udpDatagrams   int
	dnsMessages    int
	networkChanges int
	lastTCPFlow    protocol.FlowOpen
	lastDNSMessage []byte
}

func (s *recordingCoreSink) OpenSession(configBlob []byte) error {
	if len(configBlob) == 0 {
		return nil
	}
	s.openSessions++
	return nil
}

func (s *recordingCoreSink) CloseSession(string) error {
	return nil
}

func (s *recordingCoreSink) SubmitTCPFlow(open protocol.FlowOpen) error {
	s.tcpFlows++
	s.lastTCPFlow = open
	return nil
}

func (s *recordingCoreSink) SubmitUDPDatagram(uint64, []byte) error {
	s.udpDatagrams++
	return nil
}

func (s *recordingCoreSink) SubmitDNSMessage(_ uint64, message []byte) error {
	s.dnsMessages++
	s.lastDNSMessage = append([]byte(nil), message...)
	return nil
}

func (s *recordingCoreSink) ReadPacketOrFrame() ([]byte, bool) {
	return nil, false
}

func (s *recordingCoreSink) NotifyNetworkChange(PathInfo) {
	s.networkChanges++
}

func (s *recordingCoreSink) ExportRedactedDiagnostics() []byte {
	return nil
}
