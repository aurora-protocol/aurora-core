package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/session"
)

func TestTCPProxyRuntimeRetriesLocalFlowCloseAfterQueueBackpressure(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{
		MaxFlows:             1,
		ReadBufferBytes:      1024,
		MaxPendingWriteBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	const flowID = 91
	open, err := runtime.proxy.OpenTCPFrame(flowID, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	zeroTCPProxyBytes(open.Payload)
	local, peer := net.Pipe()
	defer peer.Close()
	flow := &tcpProxyFlow{
		id:                  flowID,
		conn:                local,
		writes:              make(chan []byte, 1),
		done:                make(chan struct{}),
		releasePendingBytes: runtime.releasePendingWriteBytes,
	}
	runtime.flows[flowID] = flow

	// The test application accepts six ordinary packets (eight total minus its
	// two reserved control slots). FLOW_CLOSE uses the ordinary frame API, so it
	// encounters deterministic backpressure until one packet drains.
	fillTCPProxyApplicationDataQueue(t, clientApplication)

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- runtime.sendLocalFlowClose(context.Background(), flow)
	}()
	select {
	case err := <-closeResult:
		t.Fatalf("local close returned while the application queue was saturated: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	first, err := clientApplication.TryNextPacket()
	if err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{first}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("local close retry failed after capacity became available: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("local close was not retried after capacity became available")
	}
	for {
		packet, err := clientApplication.TryNextPacket()
		if errors.Is(err, session.ErrNoPacket) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}

	foundClose := false
	for _, packet := range packets {
		blocks, err := relayApplication.HandlePacket(context.Background(), time.Now(), packet)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range blocks {
			for _, frame := range block.Frames {
				if frame.FrameType == registry.FrameFlowClose && frame.FlowID == flowID {
					foundClose = true
				}
			}
		}
	}
	if !foundClose {
		t.Fatal("retried local FLOW_CLOSE did not reach the peer application")
	}
}

func TestTCPProxyRuntimeLocalFlowCloseRetryStopsOnTeardown(t *testing.T) {
	for _, test := range []struct {
		name string
		stop func(*TCPProxyRuntime, context.CancelFunc)
		want error
	}{
		{name: "context cancellation", stop: func(_ *TCPProxyRuntime, cancel context.CancelFunc) { cancel() }, want: context.Canceled},
		{name: "runtime close", stop: func(runtime *TCPProxyRuntime, _ context.CancelFunc) { _ = runtime.Close() }, want: ErrTCPProxyClosed},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
			defer clientApplication.Close()
			defer relayApplication.Close()
			runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{
				MaxFlows:             1,
				ReadBufferBytes:      1024,
				MaxPendingWriteBytes: 1024,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			fillTCPProxyApplicationDataQueue(t, clientApplication)
			frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: 92, CloseCode: protocol.CloseNormal})
			if err != nil {
				t.Fatal(err)
			}
			defer zeroTCPProxyBytes(frame.Payload)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- runtime.queueLocalFlowClose(ctx, frame) }()
			select {
			case err := <-result:
				t.Fatalf("close retry returned before teardown: %v", err)
			case <-time.After(25 * time.Millisecond):
			}
			test.stop(runtime, cancel)
			select {
			case err := <-result:
				if !errors.Is(err, test.want) {
					t.Fatalf("close retry teardown error = %v, want %v", err, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("close retry did not stop on teardown")
			}
		})
	}
}

func TestTCPProxyRuntimeRetriesUDPAssociationCloseAfterQueueBackpressure(t *testing.T) {
	clientApplication, relayApplication := tcpProxyRuntimeApplications(t)
	defer clientApplication.Close()
	defer relayApplication.Close()
	runtime, err := NewTCPProxyRuntime(clientApplication, TCPProxyRuntimeOptions{
		MaxFlows:             1,
		ReadBufferBytes:      1024,
		MaxPendingWriteBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	const flowID = 93
	open, err := runtime.proxy.OpenUDPExplicitFrame(flowID, "203.0.113.8", 443, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	zeroTCPProxyBytes(open.Payload)
	association := &udpProxyAssociation{}
	runtime.mu.Lock()
	runtime.udpFlows[flowID] = &udpProxyFlow{id: flowID, association: association}
	runtime.mu.Unlock()
	fillTCPProxyApplicationDataQueue(t, clientApplication)

	closeResult := make(chan struct{})
	go func() {
		runtime.removeUDPAssociationWithContext(context.Background(), association)
		close(closeResult)
	}()
	select {
	case <-closeResult:
		t.Fatal("UDP association close returned while the application queue was saturated")
	case <-time.After(25 * time.Millisecond):
	}

	first, err := clientApplication.TryNextPacket()
	if err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{first}
	select {
	case <-closeResult:
	case <-time.After(time.Second):
		t.Fatal("UDP association close was not retried after capacity became available")
	}
	for {
		packet, err := clientApplication.TryNextPacket()
		if errors.Is(err, session.ErrNoPacket) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}

	foundClose := false
	for _, packet := range packets {
		blocks, err := relayApplication.HandlePacket(context.Background(), time.Now(), packet)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range blocks {
			for _, frame := range block.Frames {
				if frame.FrameType == registry.FrameFlowClose && frame.FlowID == flowID {
					foundClose = true
				}
			}
		}
	}
	if !foundClose {
		t.Fatal("retried UDP association FLOW_CLOSE did not reach the peer application")
	}
	if runtime.udpFlow(flowID) != nil {
		t.Fatal("UDP association flow remained registered after close")
	}
	if runtime.proxy.HasFlow(flowID) {
		t.Fatal("UDP association proxy state remained registered after close")
	}
}

func fillTCPProxyApplicationDataQueue(t testing.TB, application *session.Application) {
	t.Helper()
	for index := 0; index < 6; index++ {
		if err := application.QueueFrames(context.Background(), protocol.FrameBlock{Frames: []protocol.AuroraFrame{{
			FrameType: registry.FramePadding,
			Payload:   []byte{byte(index)},
		}}}); err != nil {
			t.Fatalf("fill application queue %d: %v", index, err)
		}
	}
}
