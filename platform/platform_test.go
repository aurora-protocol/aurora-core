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
		wantNoEntitlement bool
	}{
		{KindLinux, PacketTUN, true, false},
		{KindWindows, PacketWintun, true, false},
		{KindApple, PacketNetworkExtension, false, false},
		{KindAndroid, PacketVpnService, true, false},
		{KindFreeBSD, PacketTUN, true, false},
		{KindCI, PacketNone, true, true},
	}
	for _, tc := range cases {
		profile := ProfileFor(tc.kind)
		if profile.PacketMode != tc.wantPacket {
			t.Fatalf("%s packet mode = %s, want %s", tc.kind, profile.PacketMode, tc.wantPacket)
		}
		if profile.SupportsLocalProxy != tc.wantLocalProxy {
			t.Fatalf("%s local proxy = %v, want %v", tc.kind, profile.SupportsLocalProxy, tc.wantLocalProxy)
		}
		if profile.NoEntitlementOnly != tc.wantNoEntitlement {
			t.Fatalf("%s no-entitlement = %v, want %v", tc.kind, profile.NoEntitlementOnly, tc.wantNoEntitlement)
		}
		if profile.ContainsCryptoState {
			t.Fatalf("%s profile contains crypto state", tc.kind)
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
	if !bytes.Equal(sink.lastDNSMessage, []byte{0x12, 0x34, 0x01, 0x00}) {
		t.Fatalf("DNS message was not copied before forwarding: %x", sink.lastDNSMessage)
	}
}

type recordingCoreSink struct {
	openSessions   int
	tcpFlows       int
	udpDatagrams   int
	dnsMessages    int
	networkChanges int
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

func (s *recordingCoreSink) SubmitTCPFlow(protocol.FlowOpen) error {
	s.tcpFlows++
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
