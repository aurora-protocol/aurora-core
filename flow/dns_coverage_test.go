package flow

// Adversarial coverage for the pure DNS parsing/synthesis helpers in dns.go
// that the existing TestDNSForwarder* suite reaches only indirectly through
// the DNSForwarder methods, plus OpenMappedFakeIPTCPFlow (line 139, 0% before),
// whose happy path and error path are never exercised (the suite only covers the
// UDP variant OpenMappedFakeIPUDPFlow):
//   - parseLocalAQuestion (line 223, 66.7% before): the truncated-header,
//     question-count, trailer-truncated, qclass, additional-data, and
//     parseDNSName-error-propagation rejection branches stay uncovered.
//   - parseDNSName (line 252, 77.8% before): the truncated, compressed-name,
//     invalid-label (offset+size>len), and empty-name branches are uncovered.
//   - joinDNSLabels (line 311, 83.3% before): the empty-slice early return.
//   - syntheticAResponse (line 279, 94.1% before): the non-IPv4 rejection.
//   - AddNegative (line 53, 83.3% before): the empty-name / zero-TTL no-op.
//   - ResolveFakeA (line 63, 87.5% before): the empty-name error and the
//     allocator.Assign error propagation (CIDR exhaustion).
//   - mappedFakeIPTarget (line 160, 80% before): the non-IP-string rejection.
//   - OpenMappedFakeIPTCPFlow (line 139, 0% before): full happy + error paths.
//
// The pure parsers are driven directly with crafted []byte inputs; the
// DNSForwarder methods use a cheap NewDNSForwarder (no IO). The existing
// dnsQuestion helper (dns_test.go:265) is reused as the valid A-query base.
//
// Dead-by-design branches (documented, not contrived):
//   - parseDNSName:266 `size > 63` — line 263 (`size&0xc0 != 0`) already rejects
//     every size >= 64 (0x40, 0x80, 0xc0 all have the top two bits set), so when
//     266 executes size is always <= 63 and `size > 63` is false. Only the
//     `offset+size > len(message)` half is reachable; it is covered here.
//   - OpenFakeIPUDPFlow:98-100 — the second firstIPTarget(answers) call. ResolveFakeA
//     (called at 93) already runs firstIPTarget(answers) at 68 and returns its
//     error, so when ResolveFakeA returns nil the answers hold a usable IP and the
//     re-check at 97 cannot fail.
//   - mappedFakeIPTarget:170-172 — firstIPTarget(mapping.Answers). Mappings are
//     seeded only via ResolveFakeA -> Assign, which requires firstIPTarget to
//     pass, so a mapping's answers always contain a usable IP.
//   - AnswerLocalAQuery:197-199 — EncryptedDNSFrame wraps NewDNSMessageFrame, which
//     has no error path for a non-nil []byte query.
//   - AnswerLocalAQuery:201-203 — syntheticAResponse error: answer.FakeIP is always
//     a valid IPv4 produced by the FakeIP allocator, so the ip==nil branch at 281
//     cannot fire on this path (it is covered directly instead).
//
// Coverage is re-measured per target to confirm the intended branch moved
// (no wrong-branch bugs). Each rejection case asserts exactly one error so the
// failure is attributable to the perturbed input alone. New helpers are each
// referenced by >=2 tests so there is no U1000. No context.Context, no deprecated
// APIs.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestParseLocalAQuestionRejectsEachMalformedQuery(t *testing.T) {
	valid := dnsQuestion(0x0001, "example.com", 1)

	// Header + a compressed DNS name pointer (0xc0 0x0c) + A/IN trailer. The name
	// parser rejects the compression pointer before the trailer is inspected.
	compressed := make([]byte, 12)
	binary.BigEndian.PutUint16(compressed[4:6], 1) // qdcount = 1
	compressed = append(compressed, 0xc0, 0x0c)
	compressed = binary.BigEndian.AppendUint16(compressed, 1) // qtype = A
	compressed = binary.BigEndian.AppendUint16(compressed, 1) // qclass = IN

	trailerTruncated := append([]byte(nil), valid...)
	trailerTruncated = trailerTruncated[:len(trailerTruncated)-2] // drop qclass

	qclassNotIN := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(qclassNotIN[len(qclassNotIN)-2:], 2) // qclass != IN

	qdcountTwo := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(qdcountTwo[4:6], 2) // qdcount != 1

	cases := []struct {
		name    string
		query   []byte
		wantSub string
	}{
		{"truncated header", make([]byte, 8), "DNS query header is truncated"},
		{"question count not one", qdcountTwo, "must contain exactly one question"},
		{"parseDNSName error propagates", compressed, "compressed DNS question names are unsupported"},
		{"trailer truncated", trailerTruncated, "DNS question trailer is truncated"},
		{"qclass not IN", qclassNotIN, "only accepts IN class"},
		{"unsupported additional data", append(valid, 0x00), "unsupported additional data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseLocalAQuestion(tc.query)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestParseLocalAQuestionAcceptsValidQuery(t *testing.T) {
	domain, end, err := parseLocalAQuestion(dnsQuestion(0x0001, "Example.COM", 1))
	if err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
	if domain != "example.com" || end != len(dnsQuestion(0x0001, "example.com", 1)) {
		t.Fatalf("parsed query = %q end=%d, want example.com at full length", domain, end)
	}
}

func TestParseDNSNameRejectsEachMalformedName(t *testing.T) {
	cases := []struct {
		name    string
		message []byte
		offset  int
		wantSub string
	}{
		{"truncated name", []byte{0x00}, 1, "DNS name is truncated"},
		{"compressed name", []byte{0xc0, 0x0c, 0x00, 0x00}, 0, "compressed DNS question names are unsupported"},
		{"label runs past end", []byte{10, 0x01, 0x02}, 0, "DNS label is invalid"},
		{"empty name (root only)", []byte{0x00}, 0, "DNS question name is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseDNSName(tc.message, tc.offset)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantSub)
			}
		})
	}
}

func TestParseDNSNameAcceptsValidName(t *testing.T) {
	message := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	domain, offset, err := parseDNSName(message, 0)
	if err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	if domain != "example.com" || offset != len(message) {
		t.Fatalf("parsed name = %q offset=%d, want example.com at %d", domain, offset, len(message))
	}
}

func TestJoinDNSLabelsHandlesEmptyAndJoins(t *testing.T) {
	if got := joinDNSLabels(nil); got != "" {
		t.Fatalf("joinDNSLabels(nil) = %q, want empty", got)
	}
	if got := joinDNSLabels([]string{"a", "b", "c"}); got != "a.b.c" {
		t.Fatalf("joinDNSLabels = %q, want a.b.c", got)
	}
}

func TestSyntheticAResponseRejectsNonIPv4(t *testing.T) {
	query := dnsQuestion(0x0001, "example.com", 1)
	if _, err := syntheticAResponse(query, len(query), "not-an-ip"); err == nil ||
		!strings.Contains(err.Error(), "synthetic DNS answer must be IPv4") {
		t.Fatalf("syntheticAResponse(non-ipv4) err = %v, want IPv4 error", err)
	}
	// Happy path: a valid IPv4 produces a response longer than the question by
	// the A-record trailer (name pointer + type + class + ttl + rdlen + 4-byte IP).
	resp, err := syntheticAResponse(query, len(query), "203.0.113.9")
	if err != nil {
		t.Fatalf("syntheticAResponse(ipv4) failed: %v", err)
	}
	if len(resp) != len(query)+16 {
		t.Fatalf("synthetic A response length = %d, want %d", len(resp), len(query)+16)
	}
}

func TestDNSForwarderAddNegativeIsNoOpForEmptyOrZeroTTL(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	f.AddNegative("", 100, 30)  // empty canonical name -> no-op
	f.AddNegative("x.", 100, 0) // zero TTL -> no-op
	if len(f.negative) != 0 {
		t.Fatalf("AddNegative no-op paths populated the cache: %v", f.negative)
	}
	// Sanity: a real entry is still stored.
	f.AddNegative("real.example", 100, 30)
	if len(f.negative) != 1 {
		t.Fatalf("AddNegative real entry not stored: %v", f.negative)
	}
}

func TestDNSForwarderResolveFakeARejectsEmptyNameAndExhaustedCIDR(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	if _, err := f.ResolveFakeA("", []string{"93.184.216.34"}, 100); err == nil ||
		!strings.Contains(err.Error(), "empty DNS name") {
		t.Fatalf("ResolveFakeA(empty) err = %v, want empty-name error", err)
	}

	// A /30 CIDR yields only 2 usable fake IPs; resolving 5 distinct domains must
	// exhaust the allocator, surfacing the Assign error propagation at line 81
	// (a non-negative-cache error after firstIPTarget already validated answers).
	// The first two domains consume the usable IPs; every later domain fails with
	// the CIDR-exhaustion error, so the fifth call's error is asserted.
	exhausted := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/30"})
	var err error
	for i := 0; i < 5; i++ {
		_, err = exhausted.ResolveFakeA(domainWithSuffix(t, i), []string{"93.184.216.34"}, 100)
	}
	if err == nil {
		t.Fatal("ResolveFakeA accepted a domain beyond the exhausted CIDR")
	}
	if errors.Is(err, ErrNegativeCached) {
		t.Fatalf("CIDR exhaustion surfaced as ErrNegativeCached: %v", err)
	}
}

func TestDNSForwarderMappedFakeIPTargetRejectsNonIPString(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	_, _, err := f.OpenMappedFakeIPUDPFlow(81, "not-an-ip", 443, 100)
	if !errors.Is(err, ErrUnknownFakeIP) {
		t.Fatalf("OpenMappedFakeIPUDPFlow(non-ip) err = %v, want ErrUnknownFakeIP", err)
	}
}

func TestDNSForwarderOpenMappedFakeIPTCPFlowRejectsUnknownMapping(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	_, _, err := f.OpenMappedFakeIPTCPFlow(82, "198.18.0.99", 443)
	if !errors.Is(err, ErrUnknownFakeIP) {
		t.Fatalf("OpenMappedFakeIPTCPFlow(unknown) err = %v, want ErrUnknownFakeIP", err)
	}
}

func TestDNSForwarderOpenMappedFakeIPTCPFlowResolvesSeededMapping(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	answer, err := f.ResolveFakeA("example.com", []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatalf("ResolveFakeA: %v", err)
	}
	open, mapped, err := f.OpenMappedFakeIPTCPFlow(83, answer.FakeIP, 443)
	if err != nil {
		t.Fatalf("OpenMappedFakeIPTCPFlow: %v", err)
	}
	if open.FlowID != 83 || open.FlowKind != FlowKindTCPStream ||
		open.UDPFQDNMode != UDPFQDNNoneIPAuthoritative ||
		open.LocalBindingMode != LocalBindingTransparentFakeIP ||
		open.PriorityClass != PriorityInteractive {
		t.Fatalf("mapped TCP flow used wrong fields: %+v", open)
	}
	if open.TargetKind != TargetKindIPv4 || net.IP(open.TargetHost).String() != "93.184.216.34" {
		t.Fatalf("mapped TCP flow target = %v, want real answer 93.184.216.34", open.TargetHost)
	}
	if net.IP(open.TargetHost).String() == answer.FakeIP {
		t.Fatalf("mapped TCP flow sent the fake IP as the exit target: %s", answer.FakeIP)
	}
	if mapped.Domain != "example.com" || mapped.FakeIP != answer.FakeIP {
		t.Fatalf("mapped TCP flow metadata changed: %+v", mapped)
	}
	if !bytes.Equal(open.NameBindingID, answer.NameBindingID) || !bytes.Equal(open.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("mapped TCP flow did not preserve answer binding")
	}
}

// domainWithSuffix returns a distinct canonical domain per index so the CIDR
// exhaustion test can resolve many names without reusing an allocation.
func domainWithSuffix(t *testing.T, i int) string {
	t.Helper()
	return "host" + string(rune('a'+i)) + ".example"
}
