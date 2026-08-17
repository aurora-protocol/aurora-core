package client

// Adversarial white-box coverage for two count-0 nil-field guards in the
// client package: a nil DNS-answers guard in the packet-adapter DNS ingress
// and a nil-flow guard in the TCP proxy runtime's UDP target-confirm handler.
//
//   - packet_adapter.go:653 (*PacketAdapter).ingressDNS
//     dnsAnswers == nil -> return "client: packet adapter local DNS answers are
//     unavailable" (fires after the :646 mu.Lock, the :647 closed guard, the
//     :651 dnsAnswers field copy, and the :652 mu.Unlock, before the :656
//     dnsAnswers callback invocation that reads packet.udp.payload).
//   - tcp_proxy_runtime.go:843 (*TCPProxyRuntime).handleUDPTargetConfirm
//     flow == nil -> return "client: UDP target confirm targets an unknown flow"
//     (fires after the :842 r.udpFlow(flowID) lookup, before the :846
//     r.proxy.ReceiveUDPTargetConfirmFrameAt call).
//
// The existing client tests drive ingressDNS only on an activated adapter with
// a real dnsAnswers callback, and drive handleUDPTargetConfirm only on a runtime
// with a registered UDP flow, so :653 and :843 stayed count-0 even though each
// is plainly reachable on a zero-value receiver whose field/map is still nil.
//
// Proof technique:
//
//   - :653 (nil-field clean return): a zero-value &PacketAdapter{} has
//     closed == false (so the :647 closed guard is skipped) and dnsAnswers == nil.
//     ingressDNS locks the mu at :646, skips the :647 closed branch, copies the
//     nil dnsAnswers at :651, unlocks at :652, and :653 sees dnsAnswers == nil and
//     returns "client: packet adapter local DNS answers are unavailable" before
//     the :656 callback ever reads packet.udp.payload. The non-nil error
//     containing "local DNS answers are unavailable" uniquely proves :654 ran
//     (:654 is the only site that returns that message; closed == false rules
//     out the :649 ErrPacketAdapterClosed path). The zero-value
//     packetAdapterIPPacket is never read (:653 returns before :656), so it is
//     safe. Pure (no IO; it returns before the callback / network).
//
//   - :843 (nil-field clean return): a zero-value &TCPProxyRuntime{} has
//     udpFlows == nil and a usable zero-value mu. handleUDPTargetConfirm calls
//     r.udpFlow(frame.FlowID) at :842, which locks r.mu (zero-value mutex, safe)
//     and reads r.udpFlows[flowID] (a nil-map read, a well-defined no-op that
//     returns nil), so flow is nil. :843 returns "client: UDP target confirm
//     targets an unknown flow" before :846 ever touches r.proxy. The non-nil error
//     containing "UDP target confirm targets an unknown flow" uniquely proves
//     :844 ran (:844 is the only site that returns that message). Pure (no IO;
//     the nil-map read is safe and the guard returns before r.proxy is touched).
//
// Neither guard is a ctx == nil guard (a real context.Background is passed to
// ingressDNS), so there is no SA1012 surface. In-package (package client)
// because ingressDNS, packetAdapterIPPacket, handleUDPTargetConfirm, and
// TCPProxyRuntime are unexported.
//
// This test file adds only TestXxx entry points and references existing
// unexported in-package (PacketAdapter, ingressDNS, packetAdapterIPPacket,
// TCPProxyRuntime, handleUDPTargetConfirm) symbols and the exported
// protocol.AuroraFrame type, so it adds no U1000 surface.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

func TestPacketAdapterIngressDNSNilDNSAnswersGuard(t *testing.T) {
	// 653: a zero-value PacketAdapter has dnsAnswers == nil and closed == false,
	// so the :647 closed guard is skipped and :653 fires, returning the
	// "local DNS answers are unavailable" error before packet.udp.payload is
	// touched at :656. The message is unique to :654 and closed == false rules
	// out the :649 closed path.
	a := &PacketAdapter{}
	err := a.ingressDNS(context.Background(), packetAdapterIPPacket{}, time.Now())
	if err == nil {
		t.Fatal("ingressDNS(zero adapter) returned nil, want non-nil (:654)")
	}
	if !strings.Contains(err.Error(), "local DNS answers are unavailable") {
		t.Fatalf("ingressDNS nil-dnsAnswers err = %q, want \"local DNS answers are unavailable\" (:654)", err.Error())
	}
}

func TestTCPProxyRuntimeHandleUDPTargetConfirmNilFlowGuard(t *testing.T) {
	// 843: a zero-value TCPProxyRuntime has udpFlows == nil and a usable
	// zero-value mu. r.udpFlow(flowID) locks r.mu (safe) and reads r.udpFlows[flowID]
	// (nil-map read returns nil), so flow is nil and :843 returns the
	// "unknown flow" error before :846 ever touches r.proxy.
	r := &TCPProxyRuntime{}
	err := r.handleUDPTargetConfirm(protocol.AuroraFrame{FlowID: 1})
	if err == nil {
		t.Fatal("handleUDPTargetConfirm(zero runtime) returned nil, want non-nil (:844)")
	}
	if !strings.Contains(err.Error(), "UDP target confirm targets an unknown flow") {
		t.Fatalf("handleUDPTargetConfirm nil-flow err = %q, want \"UDP target confirm targets an unknown flow\" (:844)", err.Error())
	}
}
