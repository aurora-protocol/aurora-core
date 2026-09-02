package labfixture

// Coverage for labDNSResolver.ExchangeDNS (serve.go:560), the in-process lab
// DNS exchange used for DNS_MESSAGE flows. The lab server tests only exercise
// address lookups through labEgressResolver, so the DNS message echo path
// (response-flag bit set on a verbatim copy, short-query rejection) was never
// covered. The resolver is hermetic: it performs no network IO, so a direct
// call is the honest test.

import (
	"bytes"
	"context"
	"testing"
)

func TestLabDNSResolverExchangeDNSEchoesQueryWithResponseFlag(t *testing.T) {
	query := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: recursion desired, response bit clear
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	}
	response, err := labDNSResolver{}.ExchangeDNS(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), query...)
	want[2] |= 0x80
	if !bytes.Equal(response, want) {
		t.Fatalf("ExchangeDNS response = %x, want %x", response, want)
	}
	// The response must be an independent copy: mutating the query afterwards
	// must not rewrite the returned message.
	for i := range query {
		query[i] = 0xff
	}
	if bytes.Equal(response, query) {
		t.Fatal("ExchangeDNS response aliases the caller's query buffer")
	}
}

func TestLabDNSResolverExchangeDNSRejectsShortQuery(t *testing.T) {
	for _, query := range [][]byte{nil, {}, bytes.Repeat([]byte{0x00}, 11)} {
		if _, err := (labDNSResolver{}).ExchangeDNS(context.Background(), query); err == nil {
			t.Fatalf("ExchangeDNS accepted %d-byte query, want invalid-query error", len(query))
		}
	}
}
