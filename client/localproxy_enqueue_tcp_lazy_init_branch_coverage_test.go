package client

// Adversarial white-box coverage for the count-0 lazy-init guard body in
// (*LocalProxy).EnqueueTCP at client.go:294.
//
//   - client.go:293 (*LocalProxy).EnqueueTCP
//     if p.tcpSchedule == nil { p.tcpSchedule = flow.NewScheduler(flow.SchedulerOptions{}) }
//     return p.tcpSchedule.Enqueue(flow.StreamChunk{...})
//
// The :293 *condition* (p.tcpSchedule == nil) is evaluated by every existing
// EnqueueTCP test, but those tests all use a LocalProxy built via
// NewLocalProxy / NewLocalProxyWithOptions, whose constructor (client.go:72)
// sets tcpSchedule non-nil. So the condition is always FALSE in existing tests
// and the :294 lazy-init BODY (NewScheduler) stays count-0 — measured:
// client.go:293.2,293.26 1 8 (condition covered 8x) but :293.26,295.3 1 0 (the
// :294 NewScheduler body, COUNT 0). The sibling
// localproxy_nil_tcp_schedule_branch_coverage_test.go covers the *different*
// :305 NextTCPFrame nil-schedule guard and explicitly notes the EnqueueTCP
// lazy-init at :293 is uncovered ("integration tests always enqueue before
// reading"). This test fills that gap.
//
// Proof: register a real TCP flow via the validated OpenTCP path (so DemuxInbound
// at :283 succeeds and state.Kind/state.LocalClosed pass), then clear the
// scheduler the constructor set (p.tcpSchedule = nil — in-package access; the
// constructor always sets it non-nil, so this is the only way to reach the
// count-0 :294 body), then call EnqueueTCP. :293 sees tcpSchedule == nil, :294
// creates a zero-option Scheduler (maxBufferedBytes == 0 -> Enqueue skips
// backpressure; non-empty data passes the len==0 check), and :296 Enqueues a
// StreamChunk with the flow's PriorityClass. EnqueueTCP returns nil and
// p.tcpSchedule transitions nil -> non-nil — direct proof :294 ran (it is the
// only assignment to p.tcpSchedule on this path).
//
// No context is involved, so there is no SA1012 surface. No network, no
// goroutine — the flow is registered in-process and the scheduler is an
// in-memory queue. In-package (package client) because LocalProxy.tcpSchedule
// is unexported.
//
// This test file adds only a TestXxx entry point and references existing
// in-package (NewLocalProxy, LocalProxy, OpenTCP, EnqueueTCP, tcpSchedule)
// symbols and the standard library testing package, so it adds no U1000 surface.

import "testing"

func TestLocalProxyEnqueueTCPLazilyInitsNilTCPSchedule(t *testing.T) {
	// Register a real TCP flow via the validated OpenTCP path (PriorityInteractive
	// default) so DemuxInbound at :283 succeeds and the Kind/LocalClosed guards
	// at :287/:290 pass. The constructor sets tcpSchedule non-nil, so this alone
	// never reaches the :294 body.
	p := NewLocalProxy()
	if err := p.OpenTCP(20, "example.com", 443); err != nil {
		t.Fatalf("OpenTCP setup err = %v", err)
	}

	// Force the count-0 lazy-init branch: the constructor always sets tcpSchedule
	// non-nil, so clear it in-package to make the :293 condition TRUE.
	p.tcpSchedule = nil

	// EnqueueTCP should :293 see tcpSchedule == nil, :294 create a zero-option
	// Scheduler (maxBufferedBytes == 0 -> no backpressure; non-empty data passes
	// the len==0 check), and :296 Enqueue the StreamChunk. Returns nil.
	if err := p.EnqueueTCP(20, []byte("x"), 0); err != nil {
		t.Fatalf("EnqueueTCP after lazy-init err = %v, want nil (:294 creates a zero-option scheduler; non-empty data Enqueues)", err)
	}

	// Direct proof :294 ran: p.tcpSchedule transitioned nil -> non-nil, and :294
	// is the only assignment to p.tcpSchedule on the EnqueueTCP path.
	if p.tcpSchedule == nil {
		t.Fatal("EnqueueTCP did not lazily initialize p.tcpSchedule (:294 NewScheduler body did not run)")
	}
}
