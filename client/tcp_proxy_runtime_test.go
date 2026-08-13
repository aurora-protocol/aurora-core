package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/wire"
)

func TestTCPProxyRuntimeForwardsHTTPConnectBytes(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.serveConnection(ctx, serverConnection) }()

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
	if open.FrameType != registry.FrameFlowOpen {
		t.Fatalf("first client frame type = 0x%x, want FLOW_OPEN", open.FrameType)
	}
	flowOpen := protocol.DecodeFlowOpen(wire.NewReader(open.Payload))
	if flowOpen.FlowID == 0 || string(flowOpen.TargetHost) != "target.example" || flowOpen.TargetPort != 443 {
		t.Fatalf("unexpected FLOW_OPEN: %+v", flowOpen)
	}

	if _, err := clientConnection.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	data := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication)
	if data.FrameType != registry.FrameStreamData || data.FlowID != flowOpen.FlowID || !bytes.Equal(data.Payload, []byte("hello")) {
		t.Fatalf("unexpected client data frame: %+v", data)
	}
	response, err := protocol.NewStreamDataFrame(flowOpen.FlowID, []byte("world"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{response}}); err != nil {
		t.Fatal(err)
	}
	if got := tcpProxyRuntimeReadExactly(t, clientConnection, 5); !bytes.Equal(got, []byte("world")) {
		t.Fatalf("local response = %q, want world", got)
	}

	_ = clientConnection.Close()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not stop after local close")
	}
}

func TestTCPProxyRuntimeCompletesLocalCloseWithPeerClose(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() { _ = clientConnection.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.serveConnection(ctx, serverConnection) }()

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

	_ = clientConnection.Close()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not stop after local close")
	}
	if closeFrame := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication); closeFrame.FrameType != registry.FrameFlowClose || closeFrame.FlowID != flowOpen.FlowID {
		t.Fatalf("local close frame = %+v, want FLOW_CLOSE for %d", closeFrame, flowOpen.FlowID)
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
		t.Fatalf("HandleFrameBlock(peer close) = %v, want nil", err)
	}
}

func TestTCPProxyRuntimeForwardsSOCKS5Connect(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() { _ = clientConnection.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.serveConnection(ctx, serverConnection) }()

	if _, err := clientConnection.Write([]byte{socksVersion5, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if response := tcpProxyRuntimeReadExactly(t, clientConnection, 2); !bytes.Equal(response, []byte{socksVersion5, 0x00}) {
		t.Fatalf("SOCKS5 greeting response = %x, want 0500", response)
	}
	request := append([]byte{socksVersion5, socksCommandConnect, 0x00, socksATYPDomain, byte(len("target.example"))}, []byte("target.example")...)
	request = append(request, 0x01, 0xbb)
	if _, err := clientConnection.Write(request); err != nil {
		t.Fatal(err)
	}
	if response := tcpProxyRuntimeReadExactly(t, clientConnection, len(socksSuccessResponse)); !bytes.Equal(response, socksSuccessResponse) {
		t.Fatalf("SOCKS5 CONNECT response = %x, want %x", response, socksSuccessResponse)
	}

	open := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication)
	if open.FrameType != registry.FrameFlowOpen {
		t.Fatalf("first client frame type = 0x%x, want FLOW_OPEN", open.FrameType)
	}
	flowOpen := protocol.DecodeFlowOpen(wire.NewReader(open.Payload))
	if string(flowOpen.TargetHost) != "target.example" || flowOpen.TargetPort != 443 {
		t.Fatalf("unexpected SOCKS5 FLOW_OPEN: %+v", flowOpen)
	}

	_ = clientConnection.Close()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 proxy connection did not stop after local close")
	}
}

func TestTCPProxyRuntimeRepliesToUnsupportedSOCKS5Command(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() { _ = clientConnection.Close() })
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.serveConnection(context.Background(), serverConnection) }()

	if _, err := clientConnection.Write([]byte{socksVersion5, 0x01, socksNoAuth}); err != nil {
		t.Fatal(err)
	}
	if response := tcpProxyRuntimeReadExactly(t, clientConnection, 2); !bytes.Equal(response, []byte{socksVersion5, socksNoAuth}) {
		t.Fatalf("SOCKS5 greeting response = %x, want 0500", response)
	}
	request := append([]byte{socksVersion5, 0x02, 0x00, socksATYPDomain, byte(len("target.example"))}, []byte("target.example")...)
	request = append(request, 0x01, 0xbb)
	if _, err := clientConnection.Write(request); err != nil {
		t.Fatal(err)
	}
	wantFailure := socks5FailureResponse(socksReplyCommandUnsupported)
	if response := tcpProxyRuntimeReadExactly(t, clientConnection, len(wantFailure)); !bytes.Equal(response, wantFailure) {
		t.Fatalf("SOCKS5 failure response = %x, want %x", response, wantFailure)
	}
	if err := <-serveResult; err == nil {
		t.Fatal("unsupported SOCKS5 command unexpectedly succeeded")
	}
	if _, err := clientApplication.TryNextPacket(); !errors.Is(err, session.ErrNoPacket) {
		t.Fatalf("unexpected encrypted frame after rejected SOCKS5 command: %v", err)
	}
}

func TestTCPProxyRuntimeEnforcesFlowLimit(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	firstServer, firstClient := net.Pipe()
	t.Cleanup(func() { _ = firstClient.Close() })
	firstResult := make(chan error, 1)
	go func() { firstResult <- runtime.serveConnection(context.Background(), firstServer) }()
	firstWrite := make(chan error, 1)
	go func() {
		_, err := io.WriteString(firstClient, "CONNECT one.example:443 HTTP/1.1\r\nHost: one.example:443\r\n\r\n")
		firstWrite <- err
	}()
	if response := tcpProxyRuntimeReadExactly(t, firstClient, len(httpConnectEstablished)); !bytes.Equal(response, httpConnectEstablished) {
		t.Fatalf("first CONNECT response = %q, want %q", response, httpConnectEstablished)
	}
	if err := <-firstWrite; err != nil {
		t.Fatal(err)
	}
	if frame := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication); frame.FrameType != registry.FrameFlowOpen {
		t.Fatalf("first client frame type = 0x%x, want FLOW_OPEN", frame.FrameType)
	}

	secondServer, secondClient := net.Pipe()
	t.Cleanup(func() { _ = secondClient.Close() })
	secondResult := make(chan error, 1)
	go func() { secondResult <- runtime.serveConnection(context.Background(), secondServer) }()
	if _, writeErr := io.WriteString(secondClient, "CONNECT two.example:443 HTTP/1.1\r\nHost: two.example:443\r\n\r\n"); writeErr == nil {
		if err := secondClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		if _, err := secondClient.Read(buffer); err == nil {
			t.Fatal("flow-limited CONNECT unexpectedly returned a response")
		}
	} else if !errors.Is(writeErr, io.ErrClosedPipe) {
		t.Fatal(writeErr)
	}
	if err := <-secondResult; !errors.Is(err, ErrTCPProxyFlowLimit) {
		t.Fatalf("second CONNECT error = %v, want flow limit", err)
	}
	if _, err := clientApplication.TryNextPacket(); !errors.Is(err, session.ErrNoPacket) {
		t.Fatalf("flow-limited CONNECT emitted an encrypted frame: %v", err)
	}

	_ = firstClient.Close()
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first proxy connection did not stop after local close")
	}
}

func TestTCPProxyRuntimePeerCloseClosesSocketAndReleasesFlow(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() { _ = clientConnection.Close() })
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.serveConnection(context.Background(), serverConnection) }()
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

	peerClose, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
		FlowID:                   flowOpen.FlowID,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{peerClose}}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	readResult := make(chan error, 1)
	go func() {
		_, err := clientConnection.Read(buffer)
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("peer close did not close local socket")
		}
	case <-time.After(time.Second):
		t.Fatal("peer close left local socket open")
	}
	if _, ok := runtime.proxy.FlowState(flowOpen.FlowID); ok {
		t.Fatal("peer-closed flow remained in the local proxy manager")
	}
	select {
	case <-serveResult:
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not stop after peer close")
	}
}

func TestTCPProxyRuntimeCloseClosesMappedConnections(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}

	serverConnection, clientConnection := net.Pipe()
	t.Cleanup(func() { _ = clientConnection.Close() })
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.serveConnection(context.Background(), serverConnection) }()
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

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, err := clientConnection.Read(make([]byte, 1))
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("runtime close did not close local socket")
		}
	case <-time.After(time.Second):
		t.Fatal("runtime close left local socket open")
	}
	if _, ok := runtime.proxy.FlowState(flowOpen.FlowID); ok {
		t.Fatal("runtime close retained local proxy flow state")
	}
	select {
	case <-serveResult:
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not stop after runtime close")
	}
}

func TestTCPProxyFlowCloseZerosQueuedWrites(t *testing.T) {
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	payload := []byte("queued relay payload")
	flow := &tcpProxyFlow{
		conn:   serverConnection,
		writes: make(chan []byte, 2),
		done:   make(chan struct{}),
	}
	flow.writes <- payload
	if err := flow.close(); err != nil {
		t.Fatal(err)
	}
	if len(flow.writes) != 0 {
		t.Fatal("closed flow retained queued relay writes")
	}
	if !bytes.Equal(payload, make([]byte, len(payload))) {
		t.Fatal("closed flow retained relay payload bytes")
	}
}

func tcpProxyRuntimeApplications(t testing.TB) (*session.Application, *session.Application) {
	t.Helper()
	clientApplication, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Read:            session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
		Limits:          session.Limits{MaxQueuedPackets: 8, MaxQueuedBytes: 64 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayApplication, err := session.NewApplication(session.Config{
		Suite:           registry.SuiteHybrid768AESGCM,
		RouteInstanceID: 1,
		HopLayer:        0,
		Write:           session.DirectionConfig{Direction: 1, Secret: bytes.Repeat([]byte{0x21}, 48), Key: bytes.Repeat([]byte{0x22}, 32), IV: bytes.Repeat([]byte{0x23}, 12)},
		Read:            session.DirectionConfig{Direction: 0, Secret: bytes.Repeat([]byte{0x11}, 48), Key: bytes.Repeat([]byte{0x12}, 32), IV: bytes.Repeat([]byte{0x13}, 12)},
		Limits:          session.Limits{MaxQueuedPackets: 8, MaxQueuedBytes: 64 << 10, ControlReservedPackets: 2, ControlReservedBytes: 8 << 10, ReplayWindow: 64},
	})
	if err != nil {
		_ = clientApplication.Close()
		t.Fatal(err)
	}
	return clientApplication, relayApplication
}

func tcpProxyRuntimeNextRelayFrame(t testing.TB, clientApplication, relayApplication *session.Application) protocol.AuroraFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, err := clientApplication.NextPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := relayApplication.HandlePacket(ctx, time.Now(), packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || len(blocks[0].Frames) != 1 {
		t.Fatalf("unexpected relay frame blocks: %+v", blocks)
	}
	return blocks[0].Frames[0]
}

func tcpProxyRuntimeReadExactly(t testing.TB, connection net.Conn, length int) []byte {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer connection.SetReadDeadline(time.Time{})
	buffer := make([]byte, length)
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	return buffer
}
