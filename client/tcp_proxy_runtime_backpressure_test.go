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

// A local peer that stops reading fills its flow's pending-write budget. Relay
// TCP data cannot be replayed, so that one flow has to end -- but the carrier
// duplex must survive, because failing the frame block ends the authenticated
// session and every other flow with it.
func TestTCPProxyRuntimeConfinesLocalBackpressureToItsOwnFlow(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{
		MaxFlows:             2,
		ReadBufferBytes:      1024,
		MaxPendingWriteBytes: minimumTCPProxyReadBufferBytes,
	})
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

	// The local peer never reads, so successive relay writes exhaust the
	// flow's pending-write budget and enqueueLocalWrite reports backpressure.
	payload := bytes.Repeat([]byte("relay bytes "), 8)
	var refused bool
	for attempt := 0; attempt < 16 && !refused; attempt++ {
		data, err := protocol.NewStreamDataFrame(flowOpen.FlowID, payload, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{data}}); err != nil {
			t.Fatalf("local backpressure ended the carrier duplex: %v", err)
		}
		if runtime.flow(flowOpen.FlowID) == nil {
			refused = true
		}
	}
	if !refused {
		t.Fatal("a local peer that never reads did not exhaust its pending-write budget")
	}

	// The refused flow is announced to the relay, so it stops sending for it.
	closeFrame := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication)
	if closeFrame.FlowID != flowOpen.FlowID {
		t.Fatalf("relay close names flow %d, want %d", closeFrame.FlowID, flowOpen.FlowID)
	}

	// Trailing relay frames for the refused flow are dropped, not fatal.
	trailing, err := protocol.NewStreamDataFrame(flowOpen.FlowID, []byte("in flight"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{trailing}}); err != nil {
		t.Fatalf("relay data after refusal err = %v, want nil", err)
	}
}
