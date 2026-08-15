package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/flow"
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

func TestTCPProxyRuntimeForwardsSOCKS5UDPAssociation(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 2, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.Serve(ctx, listener) }()

	control, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if _, err := control.Write([]byte{socksVersion5, 0x01, socksNoAuth}); err != nil {
		t.Fatal(err)
	}
	if response := tcpProxyRuntimeReadExactly(t, control, 2); !bytes.Equal(response, []byte{socksVersion5, socksNoAuth}) {
		t.Fatalf("SOCKS5 greeting response = %x, want 0500", response)
	}
	if _, err := control.Write([]byte{socksVersion5, socksCommandUDP, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	associate := tcpProxyRuntimeReadExactly(t, control, len(socksSuccessResponse))
	if associate[0] != socksVersion5 || associate[1] != 0 || associate[2] != 0 || associate[3] != socksATYPIPv4 {
		t.Fatalf("SOCKS5 UDP ASSOCIATE response = %x", associate)
	}
	udpTarget := &net.UDPAddr{IP: append(net.IP(nil), associate[4:8]...), Port: int(associate[8])<<8 | int(associate[9])}
	udpConnection, err := net.DialUDP("udp4", nil, udpTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	payload := bytes.Repeat([]byte("p"), 4<<10)
	request := append([]byte{0, 0, 0, socksATYPDomain, byte(len("target.example"))}, []byte("target.example")...)
	request = append(request, 0x14, 0xe9)
	request = append(request, payload...)
	if _, err := udpConnection.Write(request); err != nil {
		t.Fatal(err)
	}

	frames := tcpProxyRuntimeNextRelayFrames(t, clientApplication, relayApplication)
	if len(frames) != 2 {
		t.Fatalf("first UDP packet frames = %+v, want FLOW_OPEN and data", frames)
	}
	open := frames[0]
	if open.FrameType != registry.FrameFlowOpen {
		t.Fatalf("first UDP frame type = 0x%x, want FLOW_OPEN", open.FrameType)
	}
	flowOpen := protocol.DecodeFlowOpen(wire.NewReader(open.Payload))
	if flowOpen.FlowID == 0 || flowOpen.FlowKind != flow.FlowKindUDPAssociation || flowOpen.TargetKind != flow.TargetKindDomainName || !bytes.Equal(flowOpen.TargetHost, []byte("target.example")) || flowOpen.TargetPort != 5353 {
		t.Fatalf("unexpected UDP FLOW_OPEN: %+v", flowOpen)
	}
	data := frames[1]
	if data.FrameType != registry.FrameStreamData || data.FlowID != flowOpen.FlowID || !bytes.Equal(data.Payload, payload) {
		t.Fatalf("unexpected UDP data frame: %+v", data)
	}

	confirm, err := protocol.NewUDPTargetConfirmFrame(protocol.UDPTargetConfirm{
		FlowID:           flowOpen.FlowID,
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
	responsePayload := bytes.Repeat([]byte("q"), 4<<10)
	response, err := protocol.NewStreamDataFrame(flowOpen.FlowID, responsePayload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{response}}); err == nil {
		t.Fatal("UDP relay data before target confirmation was accepted")
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{confirm, response}}); err != nil {
		t.Fatal(err)
	}
	wantResponse := append([]byte{0, 0, 0, socksATYPIPv4, 203, 0, 113, 9, 0x14, 0xe9}, responsePayload...)
	if got := tcpProxyRuntimeReadExactly(t, udpConnection, len(wantResponse)); !bytes.Equal(got, wantResponse) {
		t.Fatalf("SOCKS5 UDP response = %x, want %x", got, wantResponse)
	}

	_ = control.Close()
	closeFrame := tcpProxyRuntimeNextRelayFrame(t, clientApplication, relayApplication)
	if closeFrame.FrameType != registry.FrameFlowClose || closeFrame.FlowID != flowOpen.FlowID {
		t.Fatalf("SOCKS5 UDP association close frame = %+v", closeFrame)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 UDP runtime did not stop after close")
	}
}

func TestSOCKSUDPAssociationPeerRequiresControlAddress(t *testing.T) {
	controlPeer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210}
	peer, port, err := socksUDPAssociationPeer("0.0.0.0", 0, controlPeer)
	if err != nil || !peer.Equal(net.IPv4(127, 0, 0, 1)) || port != 0 {
		t.Fatalf("wildcard SOCKS5 UDP peer = %v:%d err=%v", peer, port, err)
	}
	if _, _, err := socksUDPAssociationPeer("127.0.0.2", 0, controlPeer); err == nil {
		t.Fatal("mismatched SOCKS5 UDP peer was accepted")
	}
	if _, _, err := socksUDPAssociationPeer("client.example", 0, controlPeer); err == nil {
		t.Fatal("domain SOCKS5 UDP peer was accepted")
	}
}

func TestSOCKSUDPAssociationListenConfigUsesControlAddressFamily(t *testing.T) {
	tests := []struct {
		name         string
		controlLocal net.Addr
		wantNetwork  string
		wantIP       net.IP
	}{
		{name: "IPv4", controlLocal: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}, wantNetwork: "udp4", wantIP: net.IPv4(127, 0, 0, 1)},
		{name: "IPv6", controlLocal: &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1080}, wantNetwork: "udp6", wantIP: net.ParseIP("::1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network, address, err := socksUDPAssociationListenConfig(test.controlLocal)
			if err != nil || network != test.wantNetwork || address == nil || !address.IP.Equal(test.wantIP) || address.Port != 0 {
				t.Fatalf("SOCKS5 UDP listen config = %q %v err=%v", network, address, err)
			}
		})
	}
}

func TestTCPProxyRuntimeBoundsUDPAssociations(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	first := &udpProxyAssociation{}
	if err := runtime.addUDPAssociation(first); err != nil {
		t.Fatal(err)
	}
	defer runtime.removeUDPAssociation(first)
	if err := runtime.addUDPAssociation(&udpProxyAssociation{}); !errors.Is(err, ErrTCPProxyFlowLimit) {
		t.Fatalf("second UDP association error = %v, want flow limit", err)
	}
}

func TestTCPProxyRuntimeCountsUDPFlowsAgainstSharedLimit(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, opened, err := runtime.udpFlowForTarget(&udpProxyAssociation{}, udpProxyTarget{kind: flow.TargetKindIPv4, host: "203.0.113.8", port: 443}); err != nil || !opened {
		t.Fatalf("open UDP flow error=%v opened=%t", err, opened)
	}
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	if _, err := runtime.openFlow(context.Background(), serverConnection, "target.example", 443); !errors.Is(err, ErrTCPProxyFlowLimit) {
		t.Fatalf("TCP flow after UDP limit error = %v, want flow limit", err)
	}
}

func TestTCPProxyRuntimeCanonicalizesUDPFlowTargets(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 2, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	association := &udpProxyAssociation{}
	upper := append([]byte{0, 0, 0, socksATYPDomain, byte(len("Target.EXAMPLE"))}, []byte("Target.EXAMPLE")...)
	upper = append(upper, 0x01, 0xbb, 0x01)
	lower := append([]byte{0, 0, 0, socksATYPDomain, byte(len("target.example"))}, []byte("target.example")...)
	lower = append(lower, 0x01, 0xbb, 0x02)
	if err := runtime.queueSOCKS5UDPDatagram(context.Background(), association, upper); err != nil {
		t.Fatal(err)
	}
	if err := runtime.queueSOCKS5UDPDatagram(context.Background(), association, lower); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	flowCount := len(runtime.udpFlows)
	runtime.mu.Unlock()
	if flowCount != 1 {
		t.Fatalf("canonical UDP target created %d flows, want 1", flowCount)
	}
}

func TestTCPProxyRuntimeDropsUDPDatagramOnSessionBackpressure(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 2, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	association := &udpProxyAssociation{}
	packet := []byte{0, 0, 0, socksATYPIPv4, 203, 0, 113, 8, 0x01, 0xbb, 0x01}
	if err := runtime.queueSOCKS5UDPDatagram(context.Background(), association, packet); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		frame, err := protocol.NewStreamDataFrame(uint64(100+index), []byte("fill"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := clientApplication.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{frame}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.queueSOCKS5UDPDatagram(context.Background(), association, packet); err != nil {
		t.Fatalf("UDP datagram under expected session backpressure = %v", err)
	}
	runtime.mu.Lock()
	flowCount := len(runtime.udpFlows)
	runtime.mu.Unlock()
	if flowCount != 1 {
		t.Fatalf("UDP flow count after backpressure = %d, want 1", flowCount)
	}
	for index := 0; index < 6; index++ {
		if _, err := clientApplication.TryNextPacket(); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.queueSOCKS5UDPDatagram(context.Background(), association, packet); err != nil {
		t.Fatalf("UDP association did not remain usable after backpressure: %v", err)
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
		if err := secondClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		} else if err == nil {
			buffer := make([]byte, 1)
			if _, err := secondClient.Read(buffer); err == nil {
				t.Fatal("flow-limited CONNECT unexpectedly returned a response")
			}
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

func TestTCPProxyRuntimeDrainsPeerDataBeforePeerClose(t *testing.T) {
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
	data, err := protocol.NewStreamDataFrame(flowOpen.FlowID, []byte("final payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	peerClose, err := protocol.NewFlowCloseFrame(protocol.FlowClose{
		FlowID:                   flowOpen.FlowID,
		CloseCode:                protocol.CloseNormal,
		FinalSequenceHintPresent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.HandleFrameBlock(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{data, peerClose}}); err != nil {
		t.Fatal(err)
	}
	if got := tcpProxyRuntimeReadExactly(t, clientConnection, len("final payload")); !bytes.Equal(got, []byte("final payload")) {
		t.Fatalf("drained peer data = %q, want final payload", got)
	}
	select {
	case <-serveResult:
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not stop after draining peer close")
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

func TestTCPProxyLocalWritePumpAbortsShortWrite(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	local, peer := net.Pipe()
	defer peer.Close()
	flow := &tcpProxyFlow{
		id:                  1,
		conn:                &tcpProxyShortWriteConn{Conn: local},
		writes:              make(chan []byte, 1),
		done:                make(chan struct{}),
		releasePendingBytes: runtime.releasePendingWriteBytes,
	}
	payload := []byte("relay response")
	flow.pendingWrites = len(payload)
	if !runtime.reservePendingWriteBytes(len(payload)) {
		t.Fatal("reservePendingWriteBytes failed")
	}
	flow.writes <- payload
	runtime.flows[flow.id] = flow

	go runtime.runLocalWritePump(flow)

	select {
	case <-flow.done:
	case <-time.After(time.Second):
		t.Fatal("short local write did not abort the proxy flow")
	}
	if runtime.flow(flow.id) != nil {
		t.Fatal("short local write retained the proxy flow")
	}
	if got := runtime.pendingWriteBytes.Load(); got != 0 {
		t.Fatalf("pending write bytes after short write = %d, want 0", got)
	}
	if !bytes.Equal(payload, make([]byte, len(payload))) {
		t.Fatal("short local write retained relay payload bytes")
	}
}

func TestTCPProxyRuntimeRejectsExcessPendingConnections(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	if err := runtime.addPending(firstServer); err != nil {
		t.Fatalf("add first pending connection: %v", err)
	}
	defer runtime.removePending(firstServer)
	defer firstServer.Close()

	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	result := make(chan error, 1)
	go func() { result <- runtime.serveConnection(context.Background(), secondServer) }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrTCPProxyFlowLimit) {
			t.Fatalf("second pending connection error = %v, want flow limit", err)
		}
	case <-time.After(time.Second):
		t.Fatal("excess pending connection was not rejected")
	}
}

func TestTCPProxyRuntimeBoundsAndClearsHandshakeDeadline(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 1, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	recordingConnection := &tcpProxyDeadlineRecordingConn{Conn: serverConnection, cleared: make(chan struct{}, 1)}
	result := make(chan error, 1)
	go func() { result <- runtime.serveConnection(context.Background(), recordingConnection) }()

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
	select {
	case <-recordingConnection.cleared:
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not clear the handshake deadline")
	}
	_ = clientConnection.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy connection did not stop after local close")
	}
	if len(recordingConnection.deadlines) < 2 || recordingConnection.deadlines[0].IsZero() || !recordingConnection.deadlines[len(recordingConnection.deadlines)-1].IsZero() {
		t.Fatalf("handshake deadlines = %v, want bounded then cleared", recordingConnection.deadlines)
	}
}

func TestTCPProxyRuntimeBoundsAggregatePendingWrites(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{MaxFlows: 17, ReadBufferBytes: 1024, MaxPendingWriteBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	for flowID := uint64(1); flowID <= 17; flowID++ {
		serverConnection, clientConnection := net.Pipe()
		defer clientConnection.Close()
		runtime.flows[flowID] = &tcpProxyFlow{id: flowID, conn: serverConnection, writes: make(chan []byte, 1), done: make(chan struct{}), releasePendingBytes: runtime.releasePendingWriteBytes}
	}
	payload := bytes.Repeat([]byte{0x71}, 1<<20)
	for flowID := uint64(1); flowID <= 16; flowID++ {
		if err := runtime.enqueueLocalWrite(flowID, payload); err != nil {
			t.Fatalf("enqueue flow %d: %v", flowID, err)
		}
	}
	if err := runtime.enqueueLocalWrite(17, payload); !errors.Is(err, ErrTCPProxyBackpressure) {
		t.Fatalf("aggregate-cap enqueue error = %v, want backpressure", err)
	}
	if err := runtime.flows[1].close(); err != nil {
		t.Fatal(err)
	}
	if got := runtime.pendingWriteBytes.Load(); got != 15<<20 {
		t.Fatalf("pending write bytes after flow close = %d, want %d", got, 15<<20)
	}
	if err := runtime.enqueueLocalWrite(17, payload); err != nil {
		t.Fatalf("enqueue after releasing aggregate budget: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if got := runtime.pendingWriteBytes.Load(); got != 0 {
		t.Fatalf("pending write bytes after runtime close = %d, want 0", got)
	}
}

type tcpProxyDeadlineRecordingConn struct {
	net.Conn
	deadlines []time.Time
	cleared   chan struct{}
}

type tcpProxyShortWriteConn struct {
	net.Conn
}

func (c *tcpProxyShortWriteConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	return len(payload) - 1, nil
}

func (c *tcpProxyDeadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	err := c.Conn.SetDeadline(deadline)
	if err == nil && deadline.IsZero() {
		select {
		case c.cleared <- struct{}{}:
		default:
		}
	}
	return err
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
	frames := tcpProxyRuntimeNextRelayFrames(t, clientApplication, relayApplication)
	if len(frames) != 1 {
		t.Fatalf("unexpected relay frames: %+v", frames)
	}
	return frames[0]
}

func tcpProxyRuntimeNextRelayFrames(t testing.TB, clientApplication, relayApplication *session.Application) []protocol.AuroraFrame {
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
	if len(blocks) != 1 {
		t.Fatalf("unexpected relay frame blocks: %+v", blocks)
	}
	return blocks[0].Frames
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
