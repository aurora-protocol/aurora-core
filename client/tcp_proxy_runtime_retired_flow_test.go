package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/wire"
)

// A local socket that fails mid-transfer retires its flow through abortFlow,
// which cannot notify the relay synchronously. The relay therefore keeps
// sending STREAM_DATA and eventually a FLOW_CLOSE for a flow the client has
// already forgotten. Those trailing frames must be dropped: failing the frame
// block tears down RunPacketDuplex and with it every other live flow.
func TestTCPProxyRuntimeDropsRelayFramesForRetiredFlow(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 2, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() { _ = clientConnection.Close() })
	go func() { _ = runtime.serveConnection(context.Background(), serverConnection) }()
	writeResult := make(chan error, 1)
	go func() {
		_, err := io.WriteString(clientConnection, "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n")
		writeResult <- err
	}()
	if response := tcpProxyRuntimeReadExactly(t, clientConnection, len(httpConnectEstablished)); !bytes.Equal(response, httpConnectEstablished) {
		t.Fatalf("CONNECT response = %q, want %q", response, httpConnectEstablished)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	open := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication)
	flowOpen := protocol.DecodeFlowOpen(wire.NewReader(open.Payload))
	if flowOpen.FlowID == 0 {
		t.Fatal("FLOW_OPEN did not contain a flow ID")
	}

	// The local socket failed: runLocalWritePump and readLocalFlow both retire
	// the flow this way when the local peer resets mid-transfer.
	runtime.abortFlow(flowOpen.FlowID)

	data, err := protocol.NewStreamDataFrame(flowOpen.FlowID, []byte("in flight relay bytes"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}); err != nil {
		t.Fatalf("relay data for retired flow err = %v, want nil (drop, not session teardown)", err)
	}

	peerClose, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
		FlowID:                   flowOpen.FlowID,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{peerClose}}); err != nil {
		t.Fatalf("relay close for retired flow err = %v, want nil (drop, not session teardown)", err)
	}
}

// A SOCKS5 UDP association that goes away retires its flows locally, so a
// UDP_TARGET_CONFIRM or datagram already in flight names an unknown flow.
func TestTCPProxyRuntimeDropsUDPFramesForRetiredFlow(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 2, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	confirm, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           9,
		TargetKind:       0x01,
		SelectedIP:       []byte{93, 184, 216, 34},
		SelectedPort:     443,
		DNSAnswerSetHash: make([]byte, 48),
		TTLSeconds:       60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{confirm}}); err != nil {
		t.Fatalf("UDP target confirm for retired flow err = %v, want nil (drop)", err)
	}

	datagram, err := protocol.NewDatagramDataFrame(9, []byte("late datagram"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{datagram}}); err != nil {
		t.Fatalf("relay datagram for retired flow err = %v, want nil (drop)", err)
	}
}
