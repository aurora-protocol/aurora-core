package flow

// Adversarial white-box coverage for the one reachable count-0 branch in
// flow/dns.go: the firstIPTarget-on-stored-answers error guard inside
// DNSForwarder.mappedFakeIPTarget (170-172). The two other count-0 branches in
// this file are dead-by-design and documented below; they are NOT claimed here.
//
// mappedFakeIPTarget(fakeIP) parses fakeIP to IPv4, looks up the stored mapping
// via f.allocator.MappingForFakeIP, then calls firstIPTarget(mapping.Answers)
// at 169 to recover the real target kind/host for a previously-assigned fake
// IP. The :170 guard returns that error if the stored answers contain no
// parseable IP. Reachability hinges on a property of the allocator contract:
// FakeIPAllocator.Assign (flow.go:432) stores the answers it is given WITHOUT
// validating them — it only rejects an empty domain name (434-435). The
// invariant "a stored mapping's answers contain a valid IP" is therefore
// enforced by ResolveFakeA, which runs firstIPTarget(answers) at 68 and
// returns its error before ever calling Assign at 80. The mapped path does
// NOT go through ResolveFakeA; it reads whatever mapping Assign previously
// stored. A caller that invokes the public FakeIPAllocator.Assign directly
// with answers containing no IP (e.g. []string{"not-an-ip"} or []string{}) —
// which Assign accepts, because it does not validate answers — creates a
// mapping whose stored answers have no IP, and the mapped path's firstIPTarget
// fails at 169, firing :170. That is precisely the inconsistent-mapping state
// the :170 guard exists to catch, so reaching it is not contrived: it is the
// guard's purpose. DNSForwarder exposes no allocator setter, so the only way
// to construct this state from a test is white-box access to the unexported
// f.allocator field (Assign is itself exported), which this package's existing
// coverage tests already do for other unexported state.
//
// The :170 test injects a bad-answer mapping via f.allocator.Assign, then
// drives the public OpenMappedFakeIPUDPFlow (which calls mappedFakeIPTarget)
// and asserts the error is the firstIPTarget failure surfaced by :170. A
// happy-path lock first establishes a VALID mapping via ResolveFakeA (which
// validates answers through :68) and confirms OpenMappedFakeIPUDPFlow then
// resolves the real target and returns a populated FlowOpen — so the :170
// rejection is a meaningful contrast, not just a nil-check.
//
// Dead-by-design (documented, NOT covered):
//   - OpenFakeIPUDPFlow:98-100 — the second firstIPTarget(answers) call.
//     ResolveFakeA at 93 already ran firstIPTarget on the SAME answers slice at
//     68 and returned its error at 69 before OpenFakeIPUDPFlow can reach 97, so
//     firstIPTarget at 97 sees the identical, already-validated slice and
//     returns the same (non-error) result. firstIPTarget is a pure
//     deterministic function over the slice content, and OpenFakeIPUDPFlow
//     does not copy or mutate answers between 68 and 97, so there is no
//     non-racy input for which :68 succeeds and :97 fails. (A concurrent
//     mutation of the caller's answers slice between the two calls would be a
//     data race, undefined behavior, not a legitimate coverage path.)
//   - AnswerLocalAQuery:201-203 — the syntheticAResponse error guard.
//     answer.FakeIP comes from ResolveFakeA → FakeIPAllocator.Assign, which
//     always returns an IPv4 string drawn from the forwarder's IPv4 CIDR
//     (default 198.18.0.0/15; a non-IPv4 CIDR makes nextAvailableIPLocked fail
//     at flow.go:476/480, so Assign fails and ResolveFakeA returns at 87
//     before AnswerLocalAQuery ever reaches 200). syntheticAResponse only
//     errors when net.ParseIP(fakeIP).To4() == nil (281-282), i.e. fakeIP is
//     not IPv4, which a valid IPv4 string never is. So :201 cannot fire.
//
// This file adds no helpers (inline forwarders and answer literals), so there
// is no staticcheck U1000 surface. No context.Context (no SA1012 surface), no
// goroutines, no cryptography, no network, no filesystem: mappedFakeIPTarget
// and OpenMappedFakeIPUDPFlow are pure IP-parse + map-lookup + slice logic.

import (
	"strings"
	"testing"
)

func TestOpenMappedFakeIPUDPFlowRejectsMappingWithInvalidAnswers(t *testing.T) {
	// 170-172: a mapping whose stored answers contain no parseable IP makes
	// firstIPTarget fail at 169, and mappedFakeIPTarget (via
	// OpenMappedFakeIPUDPFlow) surfaces that error. The bad mapping is created
	// by calling the public FakeIPAllocator.Assign directly with invalid
	// answers — Assign does not validate answers, only the domain name — which
	// is the exact inconsistent state the :170 guard protects against.
	f := NewDNSForwarder(DNSForwarderOptions{})
	fakeIP, _, err := f.allocator.Assign("bad.example.com", []string{"not-an-ip"})
	if err != nil {
		t.Fatalf("Assign(bad answers) err = %v, want nil (allocator does not validate answers)", err)
	}

	_, _, err = f.OpenMappedFakeIPUDPFlow(1, fakeIP, 443, 0)
	if err == nil {
		t.Fatal("OpenMappedFakeIPUDPFlow(bad-answers mapping) err = nil, want non-nil (:170 should fire)")
	}
	if !strings.Contains(err.Error(), "no IP answer") {
		t.Fatalf("OpenMappedFakeIPUDPFlow(bad-answers mapping) err = %v, want substring \"no IP answer\"", err)
	}
}

func TestOpenMappedFakeIPUDPFlowResolvesValidMapping(t *testing.T) {
	// Happy-path lock so the :170 rejection is a meaningful contrast: a VALID
	// mapping (created through ResolveFakeA, which validates answers via
	// firstIPTarget at 68 before Assign stores them) resolves the real target
	// and returns a populated FlowOpen with no error.
	f := NewDNSForwarder(DNSForwarderOptions{})
	answer, err := f.ResolveFakeA("example.com", []string{"203.0.113.7"}, 0)
	if err != nil {
		t.Fatalf("ResolveFakeA(valid) err = %v, want nil", err)
	}

	open, mapped, err := f.OpenMappedFakeIPUDPFlow(1, answer.FakeIP, 443, 0)
	if err != nil {
		t.Fatalf("OpenMappedFakeIPUDPFlow(valid mapping) err = %v, want nil", err)
	}
	if open.FlowID != 1 || open.FlowKind != FlowKindUDPAssociation {
		t.Fatalf("OpenMappedFakeIPUDPFlow FlowOpen = %+v, want FlowID=1 FlowKind=UDPAssociation", open)
	}
	if open.TargetKind != TargetKindIPv4 {
		t.Fatalf("OpenMappedFakeIPUDPFlow TargetKind = %d, want %d (IPv4)", open.TargetKind, TargetKindIPv4)
	}
	if len(open.TargetHost) != 4 {
		t.Fatalf("OpenMappedFakeIPUDPFlow TargetHost len = %d, want 4 (IPv4)", len(open.TargetHost))
	}
	if mapped.Domain != "example.com" || mapped.FakeIP != answer.FakeIP {
		t.Fatalf("OpenMappedFakeIPUDPFlow mapped answer = %+v, want Domain=example.com FakeIP=%s", mapped, answer.FakeIP)
	}
}
