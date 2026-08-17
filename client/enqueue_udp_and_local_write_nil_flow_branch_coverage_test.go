package client

// Adversarial white-box coverage for two count-0 nil-field guards in the
// client TCP proxy runtime: a nil-flow guard in the UDP write enqueue and a
// nil-flow guard in the local (TCP) write enqueue. Each enqueue looks up the
// target flow by ID and rejects the write when no flow is registered.
//
//   - tcp_proxy_runtime.go:870 (*TCPProxyRuntime).enqueueUDPWrite
//     flow == nil -> return "client: UDP proxy relay data targets an unknown
//     flow" (fires after the :866 empty-payload guard and the :869 r.udpFlow
//     lookup, before the :873 flow.mu.Lock).
//   - tcp_proxy_runtime.go:937 (*TCPProxyRuntime).enqueueLocalWrite
//     flow == nil -> return "client: TCP proxy relay data targets an unknown
//     flow" (fires after the :933 empty-payload guard and the :936 r.flow
//     lookup, before the :940 reservePendingWriteBytes).
//
// The existing client tests drive enqueueUDPWrite / enqueueLocalWrite only on a
// runtime with registered flows, so :870 and :937 stayed count-0 even though
// each is plainly reachable on a zero-value TCPProxyRuntime whose flows / udpFlows
// maps are still nil.
//
// Proof technique (nil-field clean return): a zero-value &TCPProxyRuntime{} has
// flows == nil and udpFlows == nil and a usable zero-value mu. enqueueUDPWrite /
// enqueueLocalWrite pass the empty-payload guard with a one-byte payload, then
// r.udpFlow / r.flow locks r.mu (zero-value mutex, safe) and reads the nil
// udpFlows / flows map (a well-defined no-op that returns nil), so flow is nil
// and :870 / :937 returns the "unknown flow" error before any flow field or
// r.proxy is touched. The non-nil error containing "UDP/TCP proxy relay data
// targets an unknown flow" uniquely proves :871 / :938 ran (each is the only
// site that returns its message). Pure (no IO; the nil-map reads are safe and
// the guards return before r.proxy / flow fields are touched).
//
// No context is involved, so there is no SA1012 surface. In-package
// (package client) because enqueueUDPWrite, enqueueLocalWrite, and TCPProxyRuntime
// are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (TCPProxyRuntime, enqueueUDPWrite, enqueueLocalWrite)
// symbols and the exported protocol.AuroraFrame type, so it adds no U1000 surface.

import (
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestTCPProxyRuntimeEnqueueUDPWriteNilFlowGuard(t *testing.T) {
	// 870: a one-byte payload passes :866; r.udpFlow(flowID) on a zero-value
	// runtime reads the nil udpFlows map and returns nil; :870 returns the
	// "unknown flow" error before :873 touches flow.mu. The message is unique to
	// :871.
	r := &TCPProxyRuntime{}
	err := r.enqueueUDPWrite(protocol.AuroraFrame{FlowID: 1, Payload: []byte{0x01}})
	if err == nil {
		t.Fatal("enqueueUDPWrite(zero runtime) returned nil, want non-nil (:871)")
	}
	if !strings.Contains(err.Error(), "UDP proxy relay data targets an unknown flow") {
		t.Fatalf("enqueueUDPWrite nil-flow err = %q, want \"UDP proxy relay data targets an unknown flow\" (:871)", err.Error())
	}
}

func TestTCPProxyRuntimeEnqueueLocalWriteNilFlowGuard(t *testing.T) {
	// 937: a one-byte payload passes :933; r.flow(flowID) on a zero-value runtime
	// reads the nil flows map and returns nil; :937 returns the "unknown flow"
	// error before :940 reservePendingWriteBytes. The message is unique to :938.
	r := &TCPProxyRuntime{}
	err := r.enqueueLocalWrite(1, []byte{0x01})
	if err == nil {
		t.Fatal("enqueueLocalWrite(zero runtime) returned nil, want non-nil (:938)")
	}
	if !strings.Contains(err.Error(), "TCP proxy relay data targets an unknown flow") {
		t.Fatalf("enqueueLocalWrite nil-flow err = %q, want \"TCP proxy relay data targets an unknown flow\" (:938)", err.Error())
	}
}
