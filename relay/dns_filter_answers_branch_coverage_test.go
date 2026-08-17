package relay

// Adversarial white-box coverage for the three reachable count-0 branches in
// relay/dns.go's (*SocketEgress).filterDNSAnswers: the wrong-family skip
// (121-122), the duplicate-answer skip (127-128), and the sort comparator
// (133).
//
// filterDNSAnswers is an unexported method on *SocketEgress, so this test
// lives in-package. It is the LAST pure-logic chokepoint in handleDNSMessage's
// answer path: after the resolver returns a []netip.Addr, filterDNSAnswers
// enforces three independent contracts before handing the addresses back to
// the DNS encoder:
//
//  121-122 — `if (queryType == socketDNSTypeA && !answer.Is4()) ||
//     (queryType == socketDNSTypeAAAA && !answer.Is6()) { continue }`. A
//     resolver may return both families for a name; the caller asked for one
//     family (A or AAAA), so answers of the OTHER family are silently
//     skipped. This is a CONTINUE, not a Fail: the answer is dropped but the
//     query still succeeds with the remaining (right-family) answers. The
//     guard is reachable with a single wrong-family answer that is otherwise
//     policy-allowed, so the skip is provably family-gated (the same address
//     under the matching queryType is retained).
//  127-128 — `if _, ok := seen[answer]; ok { continue }`. A resolver may
//     repeat an address (duplicated NS round-robins, merged A/AAAA caches);
//     the second occurrence is dropped via continue, again NOT a Fail. This
//     is reachable with one address supplied twice, both right-family and
//     policy-allowed, so the dedup is provably the cause (two inputs collapse
//     to one output, code stays OK).
//  133 — `sort.Slice(answers, func(i, j int) bool { answers[i].Less(
//     answers[j]) })`. The comparator closure only executes when
//     sort.Slice has at least two elements to compare, i.e. when at least
//     two distinct, right-family, policy-allowed answers survive the
//     earlier filters. Existing coverage never feeds such a pair, so the
//     closure stayed count-0. Feeding two distinct public IPv4 answers in
//     descending order and asserting the output is ascending proves the
//     comparator executed (the order changed).
//
// All three are reachable through filterDNSAnswers alone, which reads ONLY
// e.policy (AllowIP) — it touches no ctx, dialer, resolver, sink, flow map,
// or goroutine. So a white-box &SocketEgress{policy: DefaultExitPolicy()}
// bypasses NewSocketEgress entirely: the method needs nothing but the policy.
// DefaultExitPolicy (AllowPrivate=false) rejects private/loopback/link-local/
// multicast/unspecified addresses and the blockedExitPrefixes set, and allows
// everything else, so a public IPv4 (8.8.8.8 / 1.1.1.1) and a public IPv6
// (2606:4700:4700::1111) pass AllowIP and let each guard's effect be
// isolated: a wrong-family address is skipped (family), a repeated address
// is collapsed (dedup), and a pair is ordered (sort). No network I/O, no
// context, no goroutines, no cryptography.
//
// Dead-by-design / already-covered (NOT claimed here):
//   - 114-115 (`len(resolved) > maximumSocketDNSAnswers` -> Fail) and 124-125
//     (`!AllowIP` -> Fail) are NOT count-0; the existing relay DNS tests
//     already cover the cap-exceed and policy-reject paths.
//   - 119-132 loop body branches 120/130/131 are exercised by any non-empty
//     right-family input (the happy-path lock below touches them).
//
// This file adds one package-level test helper, socketEgressWithDefaultPolicy,
// referenced by all four tests below (4 references, well above the repo's
// >=2-reference U1000 threshold). It reuses DefaultExitPolicy (exported,
// heavily referenced across the package). No context.Context (no SA1012
// surface), no goroutines.

import (
	"net/netip"
	"testing"
)

// socketEgressWithDefaultPolicy builds a white-box *SocketEgress whose only
// populated field is policy. filterDNSAnswers reads e.policy.AllowIP and
// nothing else, so this is sufficient to exercise the method without any
// resolver/dialer/sink/flow wiring. Local to this file (lowercase) so it
// cannot create a package-level U1000 surface.
func socketEgressWithDefaultPolicy() *SocketEgress {
	return &SocketEgress{policy: DefaultExitPolicy()}
}

func TestFilterDNSAnswersSkipsWrongFamilyAnswers(t *testing.T) {
	// 121-122: a public IPv6 answer under an A query is the wrong family and
	// is skipped via continue (NOT a Fail). The same address under an AAAA
	// query is retained, proving the skip is family-gated, not policy-gated.
	e := socketEgressWithDefaultPolicy()
	ipv6 := netip.MustParseAddr("2606:4700:4700::1111") // public IPv6, AllowIP true

	out, code := e.filterDNSAnswers(socketDNSTypeA, []netip.Addr{ipv6})
	if len(out) != 0 {
		t.Fatalf("filterDNSAnswers(typeA, [public IPv6]) out = %v, want empty (:121 wrong-family continue should drop it)", out)
	}
	if code != socketDNSRCodeOK {
		t.Fatalf("filterDNSAnswers(typeA, [public IPv6]) code = %d, want %d (OK; a wrong-family skip is a continue, not a Fail)", code, socketDNSRCodeOK)
	}

	// Contrast: the SAME address under its matching family (AAAA) is
	// retained, so the A-query empty result is attributable to the family
	// mismatch at :121, not to a policy reject at :124.
	out2, code2 := e.filterDNSAnswers(socketDNSTypeAAAA, []netip.Addr{ipv6})
	if len(out2) != 1 || out2[0] != ipv6 {
		t.Fatalf("filterDNSAnswers(typeAAAA, [public IPv6]) out = %v, want [%v] (right family should be retained)", out2, ipv6)
	}
	if code2 != socketDNSRCodeOK {
		t.Fatalf("filterDNSAnswers(typeAAAA, [public IPv6]) code = %d, want %d (OK)", code2, socketDNSRCodeOK)
	}
}

func TestFilterDNSAnswersDeduplicatesRepeatedAnswers(t *testing.T) {
	// 127-128: a right-family, policy-allowed address supplied twice is
	// collapsed to one via the seen-map continue (NOT a Fail). Two inputs
	// produce exactly one output and the code stays OK, which is only
	// possible if the second occurrence took the :127 continue rather than
	// the :124 Fail or a double append.
	e := socketEgressWithDefaultPolicy()
	dup := netip.MustParseAddr("8.8.8.8") // public IPv4, AllowIP true

	out, code := e.filterDNSAnswers(socketDNSTypeA, []netip.Addr{dup, dup})
	if len(out) != 1 {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 8.8.8.8]) len(out) = %d, want 1 (:127 duplicate continue should collapse)", len(out))
	}
	if out[0] != dup {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 8.8.8.8]) out[0] = %v, want %v", out[0], dup)
	}
	if code != socketDNSRCodeOK {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 8.8.8.8]) code = %d, want %d (OK; a duplicate is a continue, not a Fail)", code, socketDNSRCodeOK)
	}
}

func TestFilterDNSAnswersSortsRetainedAnswers(t *testing.T) {
	// 133: with at least two distinct, right-family, policy-allowed answers
	// surviving the earlier filters, sort.Slice invokes its comparator
	// closure. Supplying two public IPv4 answers in DESCENDING order and
	// asserting the output is ASCENDING proves the comparator executed (the
	// order changed); without it, the output would preserve input order.
	e := socketEgressWithDefaultPolicy()
	high := netip.MustParseAddr("8.8.8.8") // public IPv4
	low := netip.MustParseAddr("1.1.1.1")  // public IPv4, < high

	out, code := e.filterDNSAnswers(socketDNSTypeA, []netip.Addr{high, low})
	if len(out) != 2 {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 1.1.1.1]) len(out) = %d, want 2 (both distinct & allowed)", len(out))
	}
	if !out[0].Less(out[1]) {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 1.1.1.1]) out = %v, want ascending (:133 comparator should sort)", out)
	}
	if out[0] != low || out[1] != high {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 1.1.1.1]) out = %v, want [%v %v]", out, low, high)
	}
	if code != socketDNSRCodeOK {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8, 1.1.1.1]) code = %d, want %d (OK)", code, socketDNSRCodeOK)
	}
}

func TestFilterDNSAnswersAcceptsSingleAllowedAnswer(t *testing.T) {
	// Happy-path lock so the three rejections/skips above are meaningful
	// contrasts: a single right-family, policy-allowed answer is retained
	// and the query succeeds with OK.
	e := socketEgressWithDefaultPolicy()
	ans := netip.MustParseAddr("8.8.8.8")

	out, code := e.filterDNSAnswers(socketDNSTypeA, []netip.Addr{ans})
	if len(out) != 1 || out[0] != ans {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8]) out = %v, want [%v]", out, ans)
	}
	if code != socketDNSRCodeOK {
		t.Fatalf("filterDNSAnswers(typeA, [8.8.8.8]) code = %d, want %d (OK)", code, socketDNSRCodeOK)
	}
}
