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
	if err := m.ConfirmUDP(protocol.UDPTargetConfirm{FlowID: 10, SelectedKind: TargetKindIPv4, SelectedHost: []byte{198, 51, 100, 9}, SelectedPort: 443}); err != nil {
		t.Fatal(err)
	}
	local, ok := m.DemuxInbound(10)
	if !ok || local.FlowID != 10 || string(local.NameBindingID) != string(fb(0xaa, 16)) {
		t.Fatalf("demux did not use flow_id authoritative state")
	}
	if _, ok := m.DemuxInbound(11); ok {
		t.Fatalf("unknown flow_id should not demux")
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
