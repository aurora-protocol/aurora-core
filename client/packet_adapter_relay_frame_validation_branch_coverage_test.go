package client

// Coverage for handleRelayFrameLocked (packet_adapter.go:979),
// validateLocalPacketLocked (:1255), and enqueueLocalPacketLocked (:1243)
// branches the end-to-end flows do not reach: padding frames, unsupported
// frame types, UDP target confirmations for unknown or non-UDP flows,
// malformed confirmations, and local-packet validation/backpressure guards.
// In-package (package client) because the locked helpers are unexported and
// require a.mu; follows the direct-call pattern of
// packet_adapter_backpressure_drop_test.go. No real network.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
)

func newPacketAdapterForRelayFrames(t *testing.T, options PacketAdapterOptions) *PacketAdapter {
	t.Helper()
	application, _ := packetAdapterApplications(t)
	t.Cleanup(func() { application.Close() })
	if options.MaxFlows == 0 {
		options.MaxFlows = 8
	}
	if options.MaxPacketBytes == 0 {
		options.MaxPacketBytes = 1500
	}
	if options.Random == nil {
		options.Random = bytes.NewReader(make([]byte, 64))
	}
	adapter, err := NewPacketAdapter(application, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adapter.Close)
	return adapter
}

func TestPacketAdapterDropsPaddingRelayFrames(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{})
	now := time.Unix(1_700_000_000, 0)
	local, err := adapter.HandleFrameBlocks(context.Background(), []protocol.FrameBlock{{Frames: []protocol.AuroraFrame{{FrameType: registry.FramePadding}}}}, now)
	if err != nil {
		t.Fatalf("padding relay frame ended the session: %v", err)
	}
	if len(local) != 0 {
		t.Fatalf("padding relay frame returned %d local packets, want none", len(local))
	}
}

func TestPacketAdapterRejectsUnsupportedRelayFrameType(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{})
	now := time.Unix(1_700_000_000, 0)
	// FrameKeyUpdate is a registered frame type the adapter does not handle on
	// the relay path; it must fail loudly instead of being silently dropped.
	adapter.mu.Lock()
	_, err := adapter.handleRelayFrameLocked(protocol.AuroraFrame{FrameType: registry.FrameKeyUpdate}, now)
	adapter.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "unsupported relay frame") {
		t.Fatalf("unsupported relay frame error = %v", err)
	}
}

func TestPacketAdapterDropsUDPTargetConfirmForUnknownFlow(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{})
	now := time.Unix(1_700_000_000, 0)
	confirm, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           999,
		TargetKind:       flow.TargetKindIPv4,
		SelectedIP:       []byte{203, 0, 113, 9},
		SelectedPort:     5353,
		DNSAnswerSetHash: make([]byte, 48),
		TTLSeconds:       60,
		ResolutionSource: protocol.UDPResolutionClientSuppliedIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	local, err := adapter.handleRelayFrameLocked(confirm, now)
	adapter.mu.Unlock()
	if err != nil {
		t.Fatalf("UDP target confirm for a retired flow ended the session: %v", err)
	}
	if len(local) != 0 {
		t.Fatalf("UDP target confirm for a retired flow returned %d local packets", len(local))
	}
}

func TestPacketAdapterRejectsUDPTargetConfirmForTCPFlow(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{UDPMode: transport.UDPOverStreamFallback})
	now := time.Unix(1_700_000_000, 0)
	syn := packetAdapterTCPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, 100, 0, tcpFlagSYN, nil)
	if err := adapter.Ingress(context.Background(), syn, now); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	var flowID uint64
	for id := range adapter.flowsByID {
		flowID = id
	}
	if flowID == 0 {
		adapter.mu.Unlock()
		t.Fatal("TCP SYN did not allocate a flow")
	}
	_, err := adapter.handleRelayFrameLocked(protocol.AuroraFrame{FrameType: registry.FrameUDPTargetConfirm, FlowID: flowID}, now)
	adapter.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "non-UDP flow") {
		t.Fatalf("UDP target confirm for a TCP flow error = %v, want non-UDP rejection", err)
	}
}

func TestPacketAdapterRejectsMalformedUDPTargetConfirm(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{UDPMode: transport.UDPOverStreamFallback})
	now := time.Unix(1_700_000_000, 0)
	udp := packetAdapterUDPv4(t, [4]byte{10, 0, 0, 2}, [4]byte{93, 184, 216, 34}, 50000, 443, []byte("ping"))
	if err := adapter.Ingress(context.Background(), udp, now); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	var flowID uint64
	for id := range adapter.flowsByID {
		flowID = id
	}
	if flowID == 0 {
		adapter.mu.Unlock()
		t.Fatal("UDP datagram did not allocate an association")
	}
	_, err := adapter.handleRelayFrameLocked(protocol.AuroraFrame{FrameType: registry.FrameUDPTargetConfirm, FlowID: flowID, Payload: []byte{0xff}}, now)
	adapter.mu.Unlock()
	if err == nil {
		t.Fatal("malformed UDP target confirm payload was accepted")
	}
}

func TestPacketAdapterValidateLocalPacketRejectsEmpty(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{})
	adapter.mu.Lock()
	err := adapter.validateLocalPacketLocked(nil)
	adapter.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "local packet is empty") {
		t.Fatalf("empty local packet error = %v", err)
	}
}

func TestPacketAdapterValidateLocalPacketRejectsOversized(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{MaxPacketBytes: 128})
	packet := bytes.Repeat([]byte{0x5a}, 129)
	adapter.mu.Lock()
	err := adapter.validateLocalPacketLocked(packet)
	adapter.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "exceeds configured limit") {
		t.Fatalf("oversized local packet error = %v", err)
	}
	if !allPacketAdapterBytesZero(packet) {
		t.Fatal("oversized local packet was not zeroed")
	}
}

func TestPacketAdapterEnqueueLocalPacketValidatesBeforeQueueing(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{})
	adapter.mu.Lock()
	err := adapter.enqueueLocalPacketLocked(nil)
	queued := len(adapter.localPackets)
	adapter.mu.Unlock()
	if err == nil {
		t.Fatal("empty local packet was enqueued")
	}
	if queued != 0 {
		t.Fatalf("invalid local packet left %d queued packets", queued)
	}
}

func TestPacketAdapterEnqueueLocalPacketBackpressureZeroesPacket(t *testing.T) {
	adapter := newPacketAdapterForRelayFrames(t, PacketAdapterOptions{MaxLocalPackets: 1})
	adapter.mu.Lock()
	if err := adapter.enqueueLocalPacketLocked([]byte{0x01}); err != nil {
		adapter.mu.Unlock()
		t.Fatalf("first local packet enqueue: %v", err)
	}
	packet := bytes.Repeat([]byte{0x6b}, 32)
	err := adapter.enqueueLocalPacketLocked(packet)
	queued := len(adapter.localPackets)
	adapter.mu.Unlock()
	if !errors.Is(err, session.ErrBackpressure) {
		t.Fatalf("full local packet buffer error = %v, want backpressure", err)
	}
	if queued != 1 {
		t.Fatalf("backpressured local packet left %d queued packets, want 1", queued)
	}
	if !allPacketAdapterBytesZero(packet) {
		t.Fatal("backpressured local packet was not zeroed")
	}
}
