package client

// Adversarial white-box branch coverage for the five count-0 duplicate-FlowID
// error-propagation guards in LocalProxy's Open*Frame / open*Frame helpers
// (client/client.go):
//
//	OpenTCPFromFakeIPFrame  :104 NewFlowOpenFrame(ok) -> :108 p.flows.Open        // <-- COUNT 0
//	openTCPFrame            :132 NewFlowOpenFrame(ok) -> :136 p.flows.Open        // <-- COUNT 0
//	openUDPFrame            :181 NewFlowOpenFrame(ok) -> :185 p.flows.OpenWithOpts // <-- COUNT 0
//	OpenUDPWithFakeDNSFrame :238 NewFlowOpenFrame(ok) -> :242 p.flows.OpenWithOpts // <-- COUNT 0
//	OpenUDPFromFakeIPFrame  :258 NewFlowOpenFrame(ok) -> :262 p.flows.OpenWithOpts // <-- COUNT 0
//
// Every Open*Frame / open*Frame builds a structurally-valid FlowOpen — either from
// localTarget (a well-formed IPv4/IPv6/domain host) or from the DNS mapper
// (OpenMappedFakeIPTCPFlow / OpenFakeIPUDPFlow / OpenMappedFakeIPUDPFlow, which return a
// valid open for a mapped host) — so the NewFlowOpenFrame calls at :104/:132/:181/:238/:258
// always succeed and the adjacent err guards (:105/:133/:182/:239/:259) are dead-by-design.
// The open is then handed to p.flows.Open / OpenWithOptions. flow.Manager.OpenWithOptions
// checks validateOpen FIRST (the open is valid -> passes) then rejects a duplicate FlowID
// at flow/flow.go:114 ("flow: duplicate flow_id %d"). So the SECOND open of the same FlowID
// hits :108/:136/:185/:242/:262 and the err propagates.
//
// The DNS mapper (OpenFakeIPUDPFlow / OpenMappedFakeIP*Flow) does NOT guard a duplicate
// FlowID itself: re-opening the same host with the same FlowID returns a valid open and lets
// flows.Open/OpenWithOptions reject the duplicate (verified by this test — the err is
// "duplicate flow_id", not a DNS-mapper err). p.flows is a concrete *flow.Manager (not an
// interface), so the guards are driven through the real LocalProxy public API only.

import (
	"strings"
	"testing"
)

func TestLocalProxyOpenDuplicateFlowIDErrPropagation(t *testing.T) {
	// :136 — openTCPFrame p.flows.Open err: the second OpenTCPFrame with the same
	// FlowID builds a valid frame (:132 NewFlowOpenFrame ok) then p.flows.Open rejects
	// the duplicate FlowID at flow/flow.go:114 -> :136 propagates.
	tcpProxy := NewLocalProxy()
	if _, err := tcpProxy.OpenTCPFrame(1, "93.184.216.34", 80); err != nil {
		t.Fatalf("first OpenTCPFrame(1) err = %v, want nil", err)
	}
	if _, err := tcpProxy.OpenTCPFrame(1, "93.184.216.34", 80); err == nil {
		t.Fatal("second OpenTCPFrame(1) err = nil, want duplicate-flow_id err (:136)")
	} else if !strings.Contains(err.Error(), "duplicate flow_id") {
		t.Fatalf("second OpenTCPFrame(1) err = %v, want substring %q (:136)", err, "duplicate flow_id")
	}

	// :185 — openUDPFrame p.flows.OpenWithOptions err: same duplicate-FlowID shape for UDP.
	udpProxy := NewLocalProxy()
	if _, err := udpProxy.OpenUDPExplicitFrame(2, "93.184.216.34", 53, 100); err != nil {
		t.Fatalf("first OpenUDPExplicitFrame(2) err = %v, want nil", err)
	}
	if _, err := udpProxy.OpenUDPExplicitFrame(2, "93.184.216.34", 53, 100); err == nil {
		t.Fatal("second OpenUDPExplicitFrame(2) err = nil, want duplicate-flow_id err (:185)")
	} else if !strings.Contains(err.Error(), "duplicate flow_id") {
		t.Fatalf("second OpenUDPExplicitFrame(2) err = %v, want substring %q (:185)", err, "duplicate flow_id")
	}

	// :242 — OpenUDPWithFakeDNSFrame p.flows.OpenWithOptions err: re-opening the same
	// host with the same FlowID returns a valid open from the DNS mapper (:238 ok) and
	// p.flows.OpenWithOptions rejects the duplicate FlowID at flow/flow.go:114 -> :242.
	fakeDNSProxy := NewLocalProxy()
	if _, _, err := fakeDNSProxy.OpenUDPWithFakeDNSFrame(60, "example.com", []string{"93.184.216.34"}, 443, 100); err != nil {
		t.Fatalf("first OpenUDPWithFakeDNSFrame(60) err = %v, want nil", err)
	}
	if _, _, err := fakeDNSProxy.OpenUDPWithFakeDNSFrame(60, "example.com", []string{"93.184.216.34"}, 443, 100); err == nil {
		t.Fatal("second OpenUDPWithFakeDNSFrame(60) err = nil, want duplicate-flow_id err (:242)")
	} else if !strings.Contains(err.Error(), "duplicate flow_id") {
		t.Fatalf("second OpenUDPWithFakeDNSFrame(60) err = %v, want substring %q (:242)", err, "duplicate flow_id")
	}

	// :262 — OpenUDPFromFakeIPFrame p.flows.OpenWithOptions err. Requires a prior
	// ResolveFakeDNS to map the host->fakeIP, then re-opening the same fakeIP with the
	// same FlowID returns a valid open (:258 ok) and p.flows.OpenWithOptions rejects the
	// duplicate FlowID at flow/flow.go:114 -> :262.
	udpFakeIPProxy := NewLocalProxy()
	answer, err := udpFakeIPProxy.ResolveFakeDNS("example.com", []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatalf("ResolveFakeDNS err = %v, want nil", err)
	}
	if _, _, err := udpFakeIPProxy.OpenUDPFromFakeIPFrame(61, answer.FakeIP, 443, 100); err != nil {
		t.Fatalf("first OpenUDPFromFakeIPFrame(61) err = %v, want nil", err)
	}
	if _, _, err := udpFakeIPProxy.OpenUDPFromFakeIPFrame(61, answer.FakeIP, 443, 100); err == nil {
		t.Fatal("second OpenUDPFromFakeIPFrame(61) err = nil, want duplicate-flow_id err (:262)")
	} else if !strings.Contains(err.Error(), "duplicate flow_id") {
		t.Fatalf("second OpenUDPFromFakeIPFrame(61) err = %v, want substring %q (:262)", err, "duplicate flow_id")
	}

	// :108 — OpenTCPFromFakeIPFrame p.flows.Open err: same prior ResolveFakeDNS mapping,
	// then re-opening the same fakeIP with the same FlowID returns a valid open (:104 ok)
	// and p.flows.Open rejects the duplicate FlowID at flow/flow.go:114 -> :108.
	tcpFakeIPProxy := NewLocalProxy()
	tcpAnswer, err := tcpFakeIPProxy.ResolveFakeDNS("example.com", []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatalf("ResolveFakeDNS(tcp) err = %v, want nil", err)
	}
	if _, _, err := tcpFakeIPProxy.OpenTCPFromFakeIPFrame(62, tcpAnswer.FakeIP, 80); err != nil {
		t.Fatalf("first OpenTCPFromFakeIPFrame(62) err = %v, want nil", err)
	}
	if _, _, err := tcpFakeIPProxy.OpenTCPFromFakeIPFrame(62, tcpAnswer.FakeIP, 80); err == nil {
		t.Fatal("second OpenTCPFromFakeIPFrame(62) err = nil, want duplicate-flow_id err (:108)")
	} else if !strings.Contains(err.Error(), "duplicate flow_id") {
		t.Fatalf("second OpenTCPFromFakeIPFrame(62) err = %v, want substring %q (:108)", err, "duplicate flow_id")
	}
}
