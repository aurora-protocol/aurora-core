package flow

import (
	"bytes"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func fb(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestUDPFlowDemuxIsFlowIDAuthoritative(t *testing.T) {
	m := NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           10,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 7},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
	}
	if err := m.Open(open); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmUDP(protocol.UDPTargetConfirm{
		FlowID:           10,
		TargetKind:       TargetKindIPv4,
		SelectedIP:       []byte{203, 0, 113, 7},
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0xbb, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	}); err != nil {
		t.Fatal(err)
	}
	local, ok := m.DemuxInbound(10)
	if !ok || local.FlowID != 10 || string(local.NameBindingID) != string(fb(0xaa, 16)) {
		t.Fatalf("demux did not use flow_id authoritative state")
	}
	if !bytes.Equal(local.ConfirmedDNSAnswerSetHash, fb(0xbb, 48)) || local.ConfirmedTTLSeconds != 60 || local.ConfirmedResolutionSource != protocol.UDPResolutionClientSuppliedIP {
		t.Fatalf("UDP target confirm metadata was not recorded: %+v", local)
	}
	if _, ok := m.DemuxInbound(11); ok {
		t.Fatalf("unknown flow_id should not demux")
	}
}

func TestUDPConfirmRejectsIPAuthoritativeTargetMismatch(t *testing.T) {
	m := NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           18,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 18},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
	}
	if err := m.Open(open); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmUDP(protocol.UDPTargetConfirm{
		FlowID:           18,
		TargetKind:       TargetKindIPv4,
		SelectedIP:       []byte{198, 51, 100, 18},
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0xbb, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	}); err == nil {
		t.Fatalf("IP-authoritative UDP confirm with mismatched target was accepted")
	}
	state, ok := m.DemuxInbound(18)
	if !ok {
		t.Fatalf("flow should remain tracked after rejected confirm")
	}
	if len(state.ConfirmedHost) != 0 {
		t.Fatalf("rejected target confirm mutated flow state: %+v", state)
	}
}

func TestUDPConfirmRejectsInvalidSelectedTargetBeforeMutation(t *testing.T) {
	m := NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           14,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 7},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
	}
	if err := m.Open(open); err != nil {
		t.Fatal(err)
	}
	err := m.ConfirmUDP(protocol.UDPTargetConfirm{
		FlowID:           14,
		TargetKind:       TargetKindDomainName,
		SelectedIP:       []byte("example.com"),
		SelectedPort:     443,
		DNSAnswerSetHash: fb(0xcc, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionRelayRecursiveDNS,
	})
	if err == nil {
		t.Fatalf("invalid UDP target confirm accepted")
	}
	state, ok := m.DemuxInbound(14)
	if !ok {
		t.Fatalf("flow should remain tracked after rejected confirm")
	}
	if len(state.ConfirmedHost) != 0 || len(state.ConfirmedDNSAnswerSetHash) != 0 {
		t.Fatalf("rejected confirm mutated flow state: %+v", state)
	}
}

func TestTransparentUDPRejectsRelayResolvedByDefault(t *testing.T) {
	m := NewManager()
	err := m.Open(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           11,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindDomainName,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNRelayResolvedFlowBound,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
	})
	if err == nil {
		t.Fatalf("expected transparent fake-IP relay-resolved UDP to be rejected by default")
	}
}

func TestUDPFQDNTargetRequiresExplicitRelayResolvedMode(t *testing.T) {
	m := NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           18,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindDomainName,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingExplicitProxyAPI,
		PriorityClass:    PriorityRealtime,
	}
	if err := m.Open(open); err == nil {
		t.Fatalf("UDP domain target accepted without relay-resolved mode")
	}
	open.UDPFQDNMode = UDPFQDNRelayResolvedFlowBound
	if err := m.Open(open); err != nil {
		t.Fatalf("explicit relay-resolved UDP domain target rejected: %v", err)
	}
}

func TestTransparentUDPRejectsRawOriginalDomainHint(t *testing.T) {
	m := NewManager()
	err := m.Open(protocol.FlowOpen{
		FlowOpenVersion:    registry.Version20,
		FlowID:             19,
		FlowKind:           FlowKindUDPAssociation,
		TargetKind:         TargetKindIPv4,
		TargetHost:         []byte{93, 184, 216, 34},
		TargetPort:         443,
		UDPFQDNMode:        UDPFQDNClientResolvedNameBinding,
		NameBindingID:      fb(0xaa, 16),
		OriginalDomainHint: []byte("example.com"),
		DNSAnswerSetHash:   fb(0xbb, 48),
		LocalBindingMode:   LocalBindingTransparentFakeIP,
		PriorityClass:      PriorityRealtime,
	})
	if err == nil {
		t.Fatalf("transparent UDP flow accepted raw original domain hint")
	}
}

func TestFakeIPAllocatorIsStableAndPrivate(t *testing.T) {
	a := NewFakeIPAllocator("198.18.0.0/15")
	ip1, id1, err := a.Assign("Example.COM", []string{"93.184.216.34"})
	if err != nil {
		t.Fatal(err)
	}
	ip2, id2, err := a.Assign("example.com.", []string{"93.184.216.34"})
	if err != nil {
		t.Fatal(err)
	}
	if ip1 != ip2 || !bytes.Equal(id1, id2) {
		t.Fatalf("fake IP assignment not stable: %s/%x vs %s/%x", ip1, id1, ip2, id2)
	}
}

func TestFakeIPAllocatorAvoidsHashCollisionsAndPreservesReverseLookup(t *testing.T) {
	a := NewFakeIPAllocator("198.18.0.0/15")
	ip1, _, err := a.Assign("collision-457.example", []string{"93.184.216.34"})
	if err != nil {
		t.Fatal(err)
	}
	ip2, _, err := a.Assign("collision-539.example", []string{"198.51.100.9"})
	if err != nil {
		t.Fatal(err)
	}
	if ip1 == ip2 {
		t.Fatalf("colliding names received the same fake IP: %s", ip1)
	}
	answers, ok := a.AnswersForFakeIP(ip1)
	if !ok || len(answers) != 1 || answers[0] != "93.184.216.34" {
		t.Fatalf("reverse lookup for first fake IP failed: %v %v", answers, ok)
	}
	answers[0] = "0.0.0.0"
	answers, ok = a.AnswersForFakeIP(ip1)
	if !ok || answers[0] != "93.184.216.34" {
		t.Fatalf("reverse lookup exposed mutable state: %v %v", answers, ok)
	}
	if answers, ok := a.AnswersForFakeIP(ip2); !ok || len(answers) != 1 || answers[0] != "198.51.100.9" {
		t.Fatalf("reverse lookup for second fake IP failed: %v %v", answers, ok)
	}
}

func TestFlowTTLAndIdleTimeoutDropStaleDatagrams(t *testing.T) {
	m := NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           12,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 9},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
		PriorityClass:    PriorityRealtime,
	}
	if err := m.OpenWithOptions(open, FlowOptions{NowUnix: 100, TTLSeconds: 20, IdleTimeoutSeconds: 5}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.AcceptDatagram(12, 104); !ok {
		t.Fatalf("active datagram flow was dropped")
	}
	if _, ok := m.AcceptDatagram(12, 110); ok {
		t.Fatalf("idle UDP datagram was accepted after timeout")
	}
	if _, ok := m.DemuxInbound(12); ok {
		t.Fatalf("expired flow remained in manager")
	}
}

func TestFlowTTLIsHardCapEvenWhenActive(t *testing.T) {
	m := NewManager()
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           13,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 10},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
		PriorityClass:    PriorityRealtime,
	}
	if err := m.OpenWithOptions(open, FlowOptions{NowUnix: 100, TTLSeconds: 7, IdleTimeoutSeconds: 100}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.AcceptDatagram(13, 106); !ok {
		t.Fatalf("flow expired before TTL")
	}
	if _, ok := m.AcceptDatagram(13, 108); ok {
		t.Fatalf("datagram accepted after flow TTL")
	}
}

func TestFlowCloseTracksHalfCloseUntilBothSidesClose(t *testing.T) {
	m := NewManager()
	if err := m.Open(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           15,
		FlowKind:         FlowKindTCPStream,
		TargetKind:       TargetKindDomainName,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingExplicitProxyAPI,
		PriorityClass:    PriorityInteractive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkLocalClose(protocol.FlowClose{FlowID: 15, CloseCode: protocol.CloseNormal, FinalSequenceHintPresent: true, FinalSequenceHint: 42}, CloseOptions{NowUnix: 100, DrainSeconds: 5}); err != nil {
		t.Fatal(err)
	}
	state, ok := m.DemuxInbound(15)
	if !ok {
		t.Fatalf("half-closed flow was released before peer close")
	}
	if !state.LocalClosed || state.PeerClosed || state.FinalSequenceHint != 42 || state.DrainUntilUnix != 105 {
		t.Fatalf("local half-close state mismatch: %+v", state)
	}
	if err := m.MarkPeerClose(protocol.FlowClose{FlowID: 15, CloseCode: protocol.CloseNormal}, CloseOptions{NowUnix: 101, DrainSeconds: 5}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.DemuxInbound(15); ok {
		t.Fatalf("fully closed flow remained tracked")
	}
}

func TestFlowClosePurgeReleasesHalfClosedAfterDrain(t *testing.T) {
	m := NewManager()
	if err := m.Open(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           16,
		FlowKind:         FlowKindTCPStream,
		TargetKind:       TargetKindDomainName,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingExplicitProxyAPI,
		PriorityClass:    PriorityInteractive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkPeerClose(protocol.FlowClose{FlowID: 16, CloseCode: protocol.CloseNormal}, CloseOptions{NowUnix: 200, DrainSeconds: 3}); err != nil {
		t.Fatal(err)
	}
	state, ok := m.DemuxInbound(16)
	if !ok {
		t.Fatalf("peer half-close was released before drain expiry")
	}
	if state.LocalClosed || !state.PeerClosed || state.DrainUntilUnix != 203 {
		t.Fatalf("peer half-close state mismatch: %+v", state)
	}
	m.PurgeClosed(202)
	if _, ok := m.DemuxInbound(16); !ok {
		t.Fatalf("half-closed flow was purged before drain expiry")
	}
	m.PurgeClosed(203)
	if _, ok := m.DemuxInbound(16); ok {
		t.Fatalf("half-closed flow survived drain expiry")
	}
}

func TestClosedUDPFlowRejectsDatagrams(t *testing.T) {
	m := NewManager()
	if err := m.Open(protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           17,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       TargetKindIPv4,
		TargetHost:       []byte{203, 0, 113, 17},
		TargetPort:       443,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    fb(0xaa, 16),
		DNSAnswerSetHash: fb(0xbb, 48),
		LocalBindingMode: LocalBindingTransparentFakeIP,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkLocalClose(protocol.FlowClose{FlowID: 17, CloseCode: protocol.CloseNormal}, CloseOptions{NowUnix: 300, DrainSeconds: 5}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.AcceptDatagram(17, 301); ok {
		t.Fatalf("datagram accepted after local FLOW_CLOSE")
	}
}
