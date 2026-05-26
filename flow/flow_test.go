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
