package flow

// Adversarial coverage for two reachable error-propagation branches in
// flow/dns.go that the existing TestDNSForwarder* and dns_coverage_test.go
// suites do not exercise:
//
//   - OpenFakeIPUDPFlow:94-96 — the `if err != nil` return after ResolveFakeA.
//     Every existing call site (dns_test.go:30,56) passes a non-empty domain,
//     so ResolveFakeA succeeds and the error return at 94 is never reached.
//     Driving OpenFakeIPUDPFlow with an empty domain makes ResolveFakeA return
//     "empty DNS name" (its canonicalDomain=="" guard at dns.go:65), which
//     propagates straight out of OpenFakeIPUDPFlow at 94. This is a live,
//     non-shadowed defensive path: OpenFakeIPUDPFlow is an exported method and a
//     caller is free to pass an empty domain.
//
//   - AnswerLocalAQuery:197-199 — the `if err != nil` return after
//     EncryptedDNSFrame. dns_coverage_test.go documents this as dead-by-design
//     ("NewDNSMessageFrame has no error path for a non-nil []byte query"), but
//     that is incorrect: NewDNSMessageFrame -> ValidateDataFrame rejects a zero
//     FlowID (protocol/frames.go:236, "data frame has zero flow_id"). Every
//     existing AnswerLocalAQuery call uses a non-zero flowID (91..96), so the
//     zero-flowID rejection never fires. Driving AnswerLocalAQuery with flowID
//     = 0 and an otherwise-valid query+answers lets ResolveFakeA succeed (so
//     execution reaches line 196) and then EncryptedDNSFrame(0, query) errors,
//     which propagates at 197. A non-zero-flowID anchor in the same test
//     succeeds, proving the error is attributable to flowID=0 alone.
//
// Dead-by-design (documented, NOT covered here — consistent with the existing
// dns_coverage_test.go analysis, which is sound for these):
//   - OpenFakeIPUDPFlow:98-100 — the second firstIPTarget(answers) call is
//     shadowed by ResolveFakeA's firstIPTarget(answers) at dns.go:68; once
//     ResolveFakeA returns nil the answers hold a usable IP and the re-check
//     cannot fail.
//   - mappedFakeIPTarget:170-172 — firstIPTarget(mapping.Answers). Mappings are
//     seeded in production only via ResolveFakeA -> Assign, which requires
//     firstIPTarget to pass, so a stored mapping's answers always contain a
//     usable IP. (A white-box test could break this invariant by calling
//     f.allocator.Assign directly with non-IP answers, but that exercises a
//     state production cannot reach, so it is not a genuine coverage gain.)
//   - AnswerLocalAQuery:201-203 — syntheticAResponse errors only if the fake
//     IP is not IPv4 (dns.go:281), but the FakeIP allocator always produces a
//     valid IPv4, so this branch cannot fire on the AnswerLocalAQuery path
//     (it is covered directly by TestSyntheticAResponseRejectsNonIPv4).
//
// This file also corrects the now-inaccurate dead-by-design claim for 197 in
// dns_coverage_test.go (that bullet is updated to point here). No new
// package-level helpers are introduced — the existing dnsQuestion helper
// (dns_test.go:265) is reused — so there is nothing for staticcheck U1000.
// No context.Context, no goroutines, no real network or filesystem.

import (
	"strings"
	"testing"
)

func TestOpenFakeIPUDPFlowRejectsEmptyDomain(t *testing.T) {
	// An empty domain makes ResolveFakeA return "empty DNS name" from its
	// canonicalDomain=="" guard (dns.go:65), and OpenFakeIPUDPFlow propagates
	// that error at line 94 before touching firstIPTarget or any flow struct.
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	_, _, err := f.OpenFakeIPUDPFlow(77, "", []string{"93.184.216.34"}, 443, 100)
	if err == nil || !strings.Contains(err.Error(), "empty DNS name") {
		t.Fatalf("OpenFakeIPUDPFlow(empty) err = %v, want substring \"empty DNS name\"", err)
	}
}

func TestAnswerLocalAQueryRejectsZeroFlowID(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	query := dnsQuestion(0x0001, "example.com", 1)

	// flowID = 0: ResolveFakeA succeeds (non-empty domain, valid IPv4 answer,
	// not negative-cached) so execution reaches EncryptedDNSFrame at line 196.
	// EncryptedDNSFrame(0, query) -> NewDNSMessageFrame -> ValidateDataFrame
	// rejects the zero FlowID (protocol/frames.go:236), and the error
	// propagates out of AnswerLocalAQuery at line 197.
	_, err := f.AnswerLocalAQuery(0, query, []string{"93.184.216.34"}, 100)
	if err == nil || !strings.Contains(err.Error(), "data frame has zero flow_id") {
		t.Fatalf("AnswerLocalAQuery(flowID=0) err = %v, want substring \"data frame has zero flow_id\"", err)
	}

	// Anchor: the identical query and answers with a non-zero flowID succeed,
	// proving the failure above is attributable to flowID=0 alone (not the
	// query shape, the answers, or the resolver).
	res, err := f.AnswerLocalAQuery(91, query, []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatalf("AnswerLocalAQuery(flowID=91) err = %v, want nil", err)
	}
	if len(res.Response) == 0 || res.Answer.FakeIP == "" {
		t.Fatalf("AnswerLocalAQuery(flowID=91) produced empty result: %+v", res)
	}
}
