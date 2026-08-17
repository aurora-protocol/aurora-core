package client

// Adversarial white-box branch coverage for the four count-0 Send/Enqueue TCP
// rejection guards in LocalProxy (client/client.go):
//
//	func (p *LocalProxy) SendTCP(flowID uint64, data []byte, flags uint64) (protocol.AuroraFrame, error) {
//	    state, ok := p.flows.DemuxInbound(flowID)
//	    if !ok {                                              // :270 <-- COUNT 0
//	        return protocol.AuroraFrame{}, fmt.Errorf("client: unknown TCP flow %d", flowID)
//	    }
//	    if state.Kind != flow.FlowKindTCPStream { ... }        // :273 (already covered)
//	    if state.LocalClosed { ... }                          // :276 (already covered)
//	    ...
//	}
//
//	func (p *LocalProxy) EnqueueTCP(flowID uint64, data []byte, flags uint64) error {
//	    state, ok := p.flows.DemuxInbound(flowID)
//	    if !ok {                                              // :284 <-- COUNT 0
//	        return fmt.Errorf("client: unknown TCP flow %d", flowID)
//	    }
//	    if state.Kind != flow.FlowKindTCPStream {              // :287 <-- COUNT 0
//	        return fmt.Errorf("client: flow %d is not TCP", flowID)
//	    }
//	    if state.LocalClosed {                                // :290 <-- COUNT 0
//	        return fmt.Errorf("client: TCP flow %d is closed for local writes", flowID)
//	    }
//	    ...
//	}
//
// SendTCP's not-TCP (:273) and LocalClosed (:276) guards are already covered —
// TestLocalProxyRejectsDataForWrongOrExpiredFlow opens a UDP flow (flow 6) and
// SendTCPs it (-> :273), and TestLocalProxyGracefulClose... opens a TCP flow (40),
// GracefulCloseFrames it, and SendTCPs it (-> :276). But SendTCP's UNKNOWN-flow guard
// (:270) and ALL THREE of EnqueueTCP's rejection guards (:284/:287/:290) stay count 0:
// every existing fixture opens the flow before sending/enqueuing, so the unknown-flow
// path is never taken, and no existing fixture drives EnqueueTCP through the wrong-kind
// or locally-closed states.
//
// p.flows is a concrete *flow.Manager (not an interface), so the guards are driven
// through the real LocalProxy public API only — no internal stubbing:
//
//	- :270 (SendTCP) + :284 (EnqueueTCP) -> a fresh NewLocalProxy() has no flows, so
//	  DemuxInbound(neverOpenedID) returns ok=false and both reject "unknown TCP flow".
//	- :287 (EnqueueTCP not-TCP) -> OpenUDPWithFakeDNS registers a UDP flow (Kind=UDP),
//	  so EnqueueTCP(udpFlowID) hits the not-TCP guard at :287 (mirrors the existing
//	  SendTCP(6) not-TCP setup in client_test.go:610-613).
//	- :290 (EnqueueTCP LocalClosed) -> OpenTCP + GracefulCloseFrame sets LocalClosed=true
//	  (client_test.go:647-658 confirms the flow stays resident with LocalClosed set), so
//	  EnqueueTCP(closedFlowID) hits the LocalClosed guard at :290 (mirrors the existing
//	  SendTCP(40) LocalClosed setup in client_test.go:644-661).
//
// EnqueueTCP's guards fire BEFORE the lazy tcpSchedule init at :293, so no scheduler is
// needed. Fully deterministic, in-package, no context, no crypto. The per-line coverage
// flips (:270 0->1, :284 0->1, :287 0->1, :290 0->1) are the rigorous proof.

import (
	"strings"
	"testing"
)

func TestLocalProxySendEnqueueTCPRejectionGuards(t *testing.T) {
	// :270 (SendTCP) + :284 (EnqueueTCP) — a fresh proxy has no flows, so DemuxInbound
	// returns ok=false and both reject with "unknown TCP flow" before any kind/closed check.
	fresh := NewLocalProxy()
	if _, err := fresh.SendTCP(999, []byte("x"), 0); err == nil {
		t.Fatal("SendTCP(unknown flow) err = nil, want non-nil (:270 unknown-flow guard)")
	} else if !strings.Contains(err.Error(), "unknown TCP flow") {
		t.Fatalf("SendTCP(unknown flow) err = %v, want substring %q (:270)", err, "unknown TCP flow")
	}
	if err := fresh.EnqueueTCP(999, []byte("x"), 0); err == nil {
		t.Fatal("EnqueueTCP(unknown flow) err = nil, want non-nil (:284 unknown-flow guard)")
	} else if !strings.Contains(err.Error(), "unknown TCP flow") {
		t.Fatalf("EnqueueTCP(unknown flow) err = %v, want substring %q (:284)", err, "unknown TCP flow")
	}

	// :287 (EnqueueTCP not-TCP) — a UDP flow registered via OpenUDPWithFakeDNS has
	// Kind=UDP, so EnqueueTCP rejects it with "not TCP". (SendTCP's matching guard :273
	// is already covered by TestLocalProxyRejectsDataForWrongOrExpiredFlow.)
	udpProxy := NewLocalProxy()
	if _, err := udpProxy.OpenUDPWithFakeDNS(6, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatal(err)
	}
	if err := udpProxy.EnqueueTCP(6, []byte("wrong kind"), 0); err == nil {
		t.Fatal("EnqueueTCP(UDP flow) err = nil, want non-nil (:287 not-TCP guard)")
	} else if !strings.Contains(err.Error(), "not TCP") {
		t.Fatalf("EnqueueTCP(UDP flow) err = %v, want substring %q (:287)", err, "not TCP")
	}

	// :290 (EnqueueTCP LocalClosed) — a TCP flow opened then gracefully closed locally has
	// LocalClosed=true, so EnqueueTCP rejects it with "closed for local writes". (SendTCP's
	// matching guard :276 is already covered by TestLocalProxyGracefulClose... .)
	closedProxy := NewLocalProxy()
	if err := closedProxy.OpenTCP(40, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	if _, err := closedProxy.GracefulCloseFrame(40, 42, []byte("done"), 100, 5); err != nil {
		t.Fatal(err)
	}
	if err := closedProxy.EnqueueTCP(40, []byte("late"), 0); err == nil {
		t.Fatal("EnqueueTCP(locally closed TCP) err = nil, want non-nil (:290 LocalClosed guard)")
	} else if !strings.Contains(err.Error(), "closed for local writes") {
		t.Fatalf("EnqueueTCP(locally closed TCP) err = %v, want substring %q (:290)", err, "closed for local writes")
	}
}
