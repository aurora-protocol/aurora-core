package relay

// Regression tests: per-flow egress failures (an unreachable target, a
// policy-denied destination, data racing a relay-side close) are ordinary
// network conditions for an authenticated tunnel. They must close the affected
// flow towards the client instead of failing HandleFrameBlock, because the
// first-hop carrier terminates the whole session on the first handler error.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	coreflow "github.com/aurora-protocol/aurora-core/flow"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

func relayTCPIPFlowOpen(flowID uint64, target [4]byte) protocol.FlowOpen {
	open := relayTCPFlowOpen(flowID, "example.com")
	open.TargetKind = coreflow.TargetKindIPv4
	open.TargetHost = append([]byte(nil), target[:]...)
	return open
}

func decodeFlowCloseForTest(t *testing.T, frame protocol.AuroraFrame) protocol.FlowClose {
	t.Helper()
	if frame.FrameType != registry.FrameFlowClose {
		t.Fatalf("frame type = 0x%x, want FLOW_CLOSE", frame.FrameType)
	}
	r := wire.NewReader(frame.Payload)
	close := protocol.DecodeFlowClose(r)
	if r.Err() != nil || !r.EOF() {
		t.Fatalf("malformed FLOW_CLOSE payload: %v", r.Err())
	}
	return close
}

func receiveSinkBlock(t *testing.T, sink *channelFrameSink) protocol.FrameBlock {
	t.Helper()
	select {
	case block := <-sink.blocks:
		return block
	case <-time.After(5 * time.Second):
		t.Fatal("no frame block was queued")
	}
	return protocol.FrameBlock{}
}

func expectNoSinkBlock(t *testing.T, sink *channelFrameSink) {
	t.Helper()
	select {
	case block := <-sink.blocks:
		t.Fatalf("unexpected queued block %#v", block)
	case <-time.After(50 * time.Millisecond):
	}
}

func newSocketExitSession(t *testing.T, dialer *recordingContextDialer, policy ExitPolicy) (*ExitSession, *channelFrameSink) {
	t.Helper()
	sink := &channelFrameSink{blocks: make(chan protocol.FrameBlock, 16)}
	egress, err := NewSocketEgress(context.Background(), SocketEgressOptions{
		Sink:     sink,
		Policy:   policy,
		Dialer:   dialer,
		Resolver: &recordingIPResolver{},
		Limits:   validSocketEgressLimits(4),
	})
	if err != nil {
		t.Fatalf("NewSocketEgress failed: %v", err)
	}
	exitSession, err := NewExitSession(egress, sink, ExitSessionOptions{Policy: policy})
	if err != nil {
		t.Fatalf("NewExitSession failed: %v", err)
	}
	t.Cleanup(func() {
		_ = exitSession.Close()
		dialer.closePeers()
	})
	return exitSession, sink
}

func TestExitSessionClosesFlowWhenDialFails(t *testing.T) {
	dialer := &recordingContextDialer{err: errors.New("connection refused")}
	exitSession, sink := newSocketExitSession(t, dialer, ExitPolicy{AllowPrivate: true})

	open := relayTCPIPFlowOpen(61, [4]byte{93, 184, 216, 34})
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}); err != nil {
		t.Fatalf("HandleFrameBlock(FLOW_OPEN to unreachable target) = %v, want nil (close the flow, keep the session)", err)
	}
	block := receiveSinkBlock(t, sink)
	if len(block.Frames) != 1 {
		t.Fatalf("queued frames = %d, want one FLOW_CLOSE", len(block.Frames))
	}
	close := decodeFlowCloseForTest(t, block.Frames[0])
	if close.FlowID != 61 || close.CloseCode != protocol.CloseTargetUnreachable {
		t.Fatalf("FLOW_CLOSE = %+v, want flow 61 target-unreachable", close)
	}

	// Data the client sent before it saw the close must be dropped, not fatal.
	data, err := protocol.NewStreamDataFrame(61, []byte("in flight"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}); err != nil {
		t.Fatalf("HandleFrameBlock(in-flight data for refused flow) = %v, want nil", err)
	}
	expectNoSinkBlock(t, sink)

	// The session keeps serving new flows.
	dialer.err = nil
	next := relayTCPIPFlowOpen(62, [4]byte{93, 184, 216, 34})
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, next)}}); err != nil {
		t.Fatalf("HandleFrameBlock(next FLOW_OPEN) = %v, want nil", err)
	}
}

func TestExitSessionClosesFlowWhenPolicyDeniesTarget(t *testing.T) {
	dialer := &recordingContextDialer{}
	exitSession, sink := newSocketExitSession(t, dialer, DefaultExitPolicy())

	open := relayTCPIPFlowOpen(63, [4]byte{10, 0, 0, 1})
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}); err != nil {
		t.Fatalf("HandleFrameBlock(FLOW_OPEN to private target) = %v, want nil (close the flow, keep the session)", err)
	}
	if len(dialer.calls) != 0 {
		t.Fatalf("policy-denied target was dialed: %+v", dialer.calls)
	}
	block := receiveSinkBlock(t, sink)
	if len(block.Frames) != 1 {
		t.Fatalf("queued frames = %d, want one FLOW_CLOSE", len(block.Frames))
	}
	close := decodeFlowCloseForTest(t, block.Frames[0])
	if close.FlowID != 63 || close.CloseCode != protocol.ClosePolicyDenied {
		t.Fatalf("FLOW_CLOSE = %+v, want flow 63 policy-denied", close)
	}
	if _, ok := exitSession.validator.FlowState(63); ok {
		t.Fatal("refused flow was left open in the validator")
	}
}

func TestExitSessionDropsDataRacingRelaySideClose(t *testing.T) {
	dialer := &recordingContextDialer{}
	exitSession, sink := newSocketExitSession(t, dialer, ExitPolicy{AllowPrivate: true})

	open := relayTCPIPFlowOpen(64, [4]byte{93, 184, 216, 34})
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}); err != nil {
		t.Fatalf("HandleFrameBlock(FLOW_OPEN) = %v", err)
	}
	if len(dialer.peers) != 1 {
		t.Fatalf("dials = %d, want 1", len(dialer.peers))
	}
	// The destination closes first; the relay tells the client.
	_ = dialer.peers[0].Close()
	block := receiveSinkBlock(t, sink)
	if len(block.Frames) != 1 {
		t.Fatalf("queued frames = %d, want one FLOW_CLOSE", len(block.Frames))
	}
	// net.Pipe fails SetReadDeadline once the peer is closed, so the pump may
	// report the close as a reset instead of EOF depending on scheduling.
	if close := decodeFlowCloseForTest(t, block.Frames[0]); close.FlowID != 64 || (close.CloseCode != protocol.CloseNormal && close.CloseCode != protocol.CloseResetByPeer) {
		t.Fatalf("FLOW_CLOSE = %+v, want flow 64 normal or reset", close)
	}

	// Client data that was already in flight must be dropped, not fatal.
	data, err := protocol.NewStreamDataFrame(64, []byte("late"), 0)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}); err != nil {
			t.Fatalf("HandleFrameBlock(data after relay-side close) = %v, want nil", err)
		}
		state, ok := exitSession.validator.FlowState(64)
		if !ok || state.LocalClosed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("validator never learned about the relay-side close")
		}
		time.Sleep(time.Millisecond)
	}
	expectNoSinkBlock(t, sink)

	// The client's own FLOW_CLOSE for that flow (possibly after the drain
	// purge) is not a protocol violation either.
	closeFrame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 64, CloseCode: protocol.CloseNormal})
	if err != nil {
		t.Fatal(err)
	}
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{closeFrame}}); err != nil {
		t.Fatalf("HandleFrameBlock(client FLOW_CLOSE after relay-side close) = %v, want nil", err)
	}
	if _, ok := exitSession.validator.FlowState(64); ok {
		t.Fatal("flow closed by both sides was left in the validator")
	}
}

func TestExitFlowHandlerPurgesLocallyClosedFlows(t *testing.T) {
	handler := NewExitFlowHandler(ExitPolicy{AllowPrivate: true})
	open := relayTCPIPFlowOpen(65, [4]byte{93, 184, 216, 34})
	if _, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}, 100); err != nil {
		t.Fatal(err)
	}
	handler.markLocalClose(65, protocol.CloseResetByPeer, 100)
	state, ok := handler.FlowState(65)
	if !ok || !state.LocalClosed {
		t.Fatalf("flow state after local close = %+v ok=%t, want local-closed", state, ok)
	}
	// Data for a draining flow is dropped without an error.
	data, err := protocol.NewStreamDataFrame(65, []byte("late"), 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}, 101)
	if err != nil || len(result.Events) != 0 {
		t.Fatalf("draining-flow data result = %+v err=%v, want no events and nil", result, err)
	}
	// Once the drain elapses the flow is purged so the validator does not grow
	// by one record per connection for the session lifetime.
	if _, err := handler.HandleFrameBlock(protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}, 100+exitCloseDrainSeconds); err != nil {
		t.Fatal(err)
	}
	if _, ok := handler.FlowState(65); ok {
		t.Fatal("locally closed flow was not purged after its drain")
	}
}

// halfCloseSocketConn is a TCP-like connection: a FLOW_CLOSE from the client
// shuts down the write half while the exit keeps reading the response.
type halfCloseSocketConn struct {
	net.Conn
}

func (c *halfCloseSocketConn) CloseWrite() error { return nil }

func TestExitSessionClosesFlowWhenEgressStillHoldsTheFlowID(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	dialer := &recordingContextDialer{useConn: true, conn: &halfCloseSocketConn{Conn: local}}
	exitSession, sink := newSocketExitSession(t, dialer, ExitPolicy{AllowPrivate: true})

	open := relayTCPIPFlowOpen(70, [4]byte{93, 184, 216, 34})
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}); err != nil {
		t.Fatalf("HandleFrameBlock(FLOW_OPEN) = %v", err)
	}

	// The client half-closes. The exit shuts down the write half but keeps the
	// socket to deliver the rest of the response, so the flow ID stays reserved
	// in the egress for as long as the destination keeps sending.
	closeFrame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 70, CloseCode: protocol.CloseNormal})
	if err != nil {
		t.Fatal(err)
	}
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{closeFrame}}); err != nil {
		t.Fatalf("HandleFrameBlock(client FLOW_CLOSE) = %v", err)
	}
	// The validator only keeps a peer-closed flow for its drain window.
	exitSession.validator.flows.PurgeClosed(uint64(time.Now().Unix()) + exitCloseDrainSeconds)
	if _, ok := exitSession.validator.FlowState(70); ok {
		t.Fatal("peer-closed flow was not purged after its drain")
	}

	// Reusing that flow ID is not a protocol violation for the validator, but
	// the egress still holds the socket: close the new flow, keep the session.
	if err := exitSession.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{flowOpenFrame(t, open)}}); err != nil {
		t.Fatalf("HandleFrameBlock(FLOW_OPEN reusing a draining flow ID) = %v, want nil (close the flow, keep the session)", err)
	}
	block := receiveSinkBlock(t, sink)
	if len(block.Frames) != 1 {
		t.Fatalf("queued frames = %d, want one FLOW_CLOSE", len(block.Frames))
	}
	if close := decodeFlowCloseForTest(t, block.Frames[0]); close.FlowID != 70 || close.CloseCode != protocol.CloseResourceLimit {
		t.Fatalf("FLOW_CLOSE = %+v, want flow 70 resource-limit", close)
	}
	state, ok := exitSession.validator.FlowState(70)
	if !ok || !state.LocalClosed {
		t.Fatalf("refused duplicate flow state = %+v ok=%t, want local-closed", state, ok)
	}
}
