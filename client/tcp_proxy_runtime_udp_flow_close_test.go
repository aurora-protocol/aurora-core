package client

// Coverage for the UDP branch of TCPProxyRuntime.handlePeerFlowClose
// (client/tcp_proxy_runtime.go:1110-1120) and removeUDPFlow (:1147-1155).
// A peer FLOW_CLOSE that targets a registered UDP flow (no TCP flow with the
// same identifier) must be forwarded to the portable proxy flow state and must
// drop the runtime's udpFlows entry plus the proxy flow. The existing close
// tests only drive peer closes for TCP flows, so the UDP branch stayed
// untested.
//
// The runtime and session applications are built with the established
// tcpProxyRuntimeApplications helper; the UDP flow is registered exactly like
// TestTCPProxyRuntimeRetriesUDPAssociationCloseAfterQueueBackpressure does
// (OpenUDPExplicitFrame for the proxy state plus a direct udpFlows insert).

import (
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestTCPProxyRuntimeHandlesPeerFlowCloseForUDPFlow(t *testing.T) {
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

	const flowID = 94
	open, err := runtime.proxy.OpenUDPExplicitFrame(flowID, "203.0.113.8", 443, uint64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	zeroTCPProxyBytes(open.Payload)
	association := &udpProxyAssociation{}
	runtime.mu.Lock()
	runtime.udpFlows[flowID] = &udpProxyFlow{id: flowID, association: association}
	runtime.mu.Unlock()

	frame, err := protocol.NewFlowCloseFrame(protocol.FlowClose{FlowID: flowID, CloseCode: protocol.CloseNormal})
	if err != nil {
		t.Fatal(err)
	}
	defer zeroTCPProxyBytes(frame.Payload)
	if err := runtime.handlePeerFlowClose(frame); err != nil {
		t.Fatalf("peer FLOW_CLOSE for UDP flow = %v, want nil", err)
	}
	if runtime.udpFlow(flowID) != nil {
		t.Fatal("UDP flow remained registered after peer close")
	}
	if runtime.proxy.HasFlow(flowID) {
		t.Fatal("UDP proxy state remained registered after peer close")
	}
}
