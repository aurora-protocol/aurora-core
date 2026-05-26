package flow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/aurora-protocol/aurora-core/registry"
)

func TestDNSForwarderCachesNegativeResponses(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	f.AddNegative("Missing.Example.", 100, 30)
	if _, err := f.ResolveFakeA("missing.example", []string{"93.184.216.34"}, 110); !errors.Is(err, ErrNegativeCached) {
		t.Fatalf("active negative cache not used: %v", err)
	}
	answer, err := f.ResolveFakeA("missing.example", []string{"93.184.216.34"}, 131)
	if err != nil {
		t.Fatalf("expired negative cache still blocked resolution: %v", err)
	}
	if answer.FakeIP == "" || len(answer.NameBindingID) != 16 || len(answer.DNSAnswerSetHash) != 48 {
		t.Fatalf("invalid synthetic answer: %+v", answer)
	}
}

func TestDNSForwarderBuildsFakeIPUDPFlowWithoutRawDomainLeak(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	open, answer, err := f.OpenFakeIPUDPFlow(77, "Example.COM.", []string{"93.184.216.34"}, 443, 100)
	if err != nil {
		t.Fatal(err)
	}
	if open.FlowID != 77 || open.FlowKind != FlowKindUDPAssociation || open.TargetKind != TargetKindIPv4 {
		t.Fatalf("unexpected fake-IP UDP flow: %+v", open)
	}
	if open.UDPFQDNMode != UDPFQDNClientResolvedNameBinding || open.LocalBindingMode != LocalBindingTransparentFakeIP {
		t.Fatalf("flow did not use client-resolved fake-IP mode: %+v", open)
	}
	if len(open.OriginalDomainHint) != 0 || bytes.Contains(open.TargetHost, []byte("example.com")) {
		t.Fatalf("fake-IP flow leaked raw domain in visible flow fields: %+v", open)
	}
	if !bytes.Equal(open.NameBindingID, answer.NameBindingID) || !bytes.Equal(open.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("flow binding fields do not match synthetic answer")
	}
	if net.IP(open.TargetHost).String() != "93.184.216.34" {
		t.Fatalf("flow target %v is not the resolved real IP", open.TargetHost)
	}
	if net.IP(open.TargetHost).String() == answer.FakeIP {
		t.Fatalf("fake IP was sent as the exit target: %s", answer.FakeIP)
	}
}

func TestDNSForwarderBuildsFakeIPUDPFlowWithIPv6Target(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	open, _, err := f.OpenFakeIPUDPFlow(78, "Example.COM.", []string{"2001:4860:4860::8888"}, 443, 100)
	if err != nil {
		t.Fatal(err)
	}
	if open.TargetKind != TargetKindIPv6 {
		t.Fatalf("IPv6 fake-IP flow target_kind = 0x%x, want IPv6", open.TargetKind)
	}
	if len(open.TargetHost) != 16 || net.IP(open.TargetHost).String() != "2001:4860:4860::8888" {
		t.Fatalf("IPv6 fake-IP flow target host = %x", open.TargetHost)
	}
	if open.UDPFQDNMode != UDPFQDNClientResolvedNameBinding || open.LocalBindingMode != LocalBindingTransparentFakeIP {
		t.Fatalf("IPv6 fake-IP flow used wrong binding mode: %+v", open)
	}
}

func TestDNSForwarderOpensUDPFlowFromFakeIPMap(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	answer, err := f.ResolveFakeA("Example.COM.", []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	open, mapped, err := f.OpenMappedFakeIPUDPFlow(79, answer.FakeIP, 443, 101)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Domain != "example.com" || mapped.FakeIP != answer.FakeIP {
		t.Fatalf("fake-IP mapping metadata changed: %+v", mapped)
	}
	if open.FlowID != 79 || open.FlowKind != FlowKindUDPAssociation || open.TargetKind != TargetKindIPv4 {
		t.Fatalf("unexpected mapped fake-IP UDP flow: %+v", open)
	}
	if net.IP(open.TargetHost).String() != "93.184.216.34" {
		t.Fatalf("mapped fake-IP flow target = %s, want real answer", net.IP(open.TargetHost))
	}
	if net.IP(open.TargetHost).String() == answer.FakeIP || len(open.OriginalDomainHint) != 0 {
		t.Fatalf("mapped fake-IP flow leaked fake IP or raw domain hint: %+v", open)
	}
	if !bytes.Equal(open.NameBindingID, answer.NameBindingID) || !bytes.Equal(open.DNSAnswerSetHash, answer.DNSAnswerSetHash) {
		t.Fatalf("mapped fake-IP flow did not preserve answer binding")
	}
}

func TestDNSForwarderRejectsUnknownFakeIPMap(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	if _, _, err := f.OpenMappedFakeIPUDPFlow(80, "198.18.0.99", 443, 100); err == nil {
		t.Fatalf("unknown fake-IP mapping was accepted")
	}
}

func TestDNSAnswerSetHashIsOrderIndependent(t *testing.T) {
	first := DNSAnswerSetHash([]string{"93.184.216.34", "2001:4860:4860::8888"})
	second := DNSAnswerSetHash([]string{"2001:4860:4860::8888", "93.184.216.34"})
	if !bytes.Equal(first, second) {
		t.Fatalf("DNS answer set hash depends on answer order: %x vs %x", first, second)
	}
}

func TestDNSForwarderUsesDNSMessageFramesForEncryptedForwarding(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{})
	frame, err := f.EncryptedDNSFrame(9, []byte{0x12, 0x34, 0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if frame.FrameType != registry.FrameDNSMessage || frame.FlowID != 9 {
		t.Fatalf("DNS was not carried in DNS frame: %+v", frame)
	}
	if !bytes.Equal(frame.Payload, []byte{0x12, 0x34, 0x01, 0x00}) {
		t.Fatalf("DNS payload changed: %x", frame.Payload)
	}
}

func TestDNSForwarderAnswersLocalAQueryWithFakeIPAndEncryptedFrame(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	query := dnsQuestion(0x1234, "Example.COM", 1)

	result, err := f.AnswerLocalAQuery(91, query, []string{"93.184.216.34"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Frame.FrameType != registry.FrameDNSMessage || result.Frame.FlowID != 91 || !bytes.Equal(result.Frame.Payload, query) {
		t.Fatalf("local DNS query was not carried inside a DNS frame: %+v", result.Frame)
	}
	if result.Answer.Domain != "example.com" || result.Answer.FakeIP == "" {
		t.Fatalf("local DNS answer did not record canonical fake-IP mapping: %+v", result.Answer)
	}
	if result.Answer.FakeIP == "93.184.216.34" {
		t.Fatalf("local DNS response exposed the real answer as the synthetic address")
	}
	response := result.Response
	if len(response) < len(query)+16 {
		t.Fatalf("local DNS response too short: %x", response)
	}
	if binary.BigEndian.Uint16(response[0:2]) != 0x1234 {
		t.Fatalf("local DNS response changed query id: %x", response[:2])
	}
	if flags := binary.BigEndian.Uint16(response[2:4]); flags != 0x8180 {
		t.Fatalf("local DNS response flags = 0x%x, want standard no-error response", flags)
	}
	if qd, an := binary.BigEndian.Uint16(response[4:6]), binary.BigEndian.Uint16(response[6:8]); qd != 1 || an != 1 {
		t.Fatalf("local DNS response counts qd=%d an=%d", qd, an)
	}
	if !bytes.Equal(response[12:len(query)], query[12:]) {
		t.Fatalf("local DNS response did not preserve the original question")
	}
	answer := response[len(query):]
	if !bytes.Equal(answer[:2], []byte{0xc0, 0x0c}) || binary.BigEndian.Uint16(answer[2:4]) != 1 || binary.BigEndian.Uint16(answer[4:6]) != 1 {
		t.Fatalf("local DNS response answer header was not A/IN with question pointer: %x", answer[:6])
	}
	if ttl := binary.BigEndian.Uint32(answer[6:10]); ttl == 0 || ttl > 300 {
		t.Fatalf("local DNS response TTL out of bounds: %d", ttl)
	}
	if rdlen := binary.BigEndian.Uint16(answer[10:12]); rdlen != 4 {
		t.Fatalf("local DNS response A record rdlength = %d", rdlen)
	}
	if got := net.IP(answer[12:16]).String(); got != result.Answer.FakeIP {
		t.Fatalf("local DNS response address = %s, want fake IP %s", got, result.Answer.FakeIP)
	}
}

func TestDNSForwarderAnswersNegativeCachedLocalAQueryWithoutFrame(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	f.AddNegative("Missing.Example.", 100, 30)
	query := dnsQuestion(0x1237, "Missing.Example", 1)

	result, err := f.AnswerLocalAQuery(94, query, []string{"93.184.216.34"}, 110)
	if err != nil {
		t.Fatal(err)
	}
	if result.Frame.FrameType != 0 || result.Frame.FlowID != 0 || len(result.Frame.Payload) != 0 {
		t.Fatalf("negative-cache DNS query emitted an Aurora frame: %+v", result.Frame)
	}
	if result.Answer.Domain != "missing.example" || result.Answer.FakeIP != "" {
		t.Fatalf("negative-cache DNS result allocated a fake IP: %+v", result.Answer)
	}
	response := result.Response
	if len(response) != len(query) {
		t.Fatalf("negative-cache response length = %d, want original question length %d: %x", len(response), len(query), response)
	}
	if binary.BigEndian.Uint16(response[0:2]) != 0x1237 {
		t.Fatalf("negative-cache response changed query id: %x", response[:2])
	}
	if flags := binary.BigEndian.Uint16(response[2:4]); flags != 0x8183 {
		t.Fatalf("negative-cache response flags = 0x%x, want NXDOMAIN response", flags)
	}
	if qd, an := binary.BigEndian.Uint16(response[4:6]), binary.BigEndian.Uint16(response[6:8]); qd != 1 || an != 0 {
		t.Fatalf("negative-cache response counts qd=%d an=%d", qd, an)
	}
	if ns, ar := binary.BigEndian.Uint16(response[8:10]), binary.BigEndian.Uint16(response[10:12]); ns != 0 || ar != 0 {
		t.Fatalf("negative-cache response leaked authority/additional records ns=%d ar=%d", ns, ar)
	}
	if !bytes.Equal(response[12:], query[12:]) {
		t.Fatalf("negative-cache response did not preserve the original question")
	}
}

func TestDNSForwarderExpiresNegativeCachedLocalAQuery(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{FakeIPCIDR: "198.18.0.0/15"})
	f.AddNegative("Missing.Example.", 100, 30)
	query := dnsQuestion(0x1238, "Missing.Example", 1)

	result, err := f.AnswerLocalAQuery(95, query, []string{"93.184.216.34"}, 131)
	if err != nil {
		t.Fatal(err)
	}
	if result.Frame.FrameType != registry.FrameDNSMessage || result.Frame.FlowID != 95 || !bytes.Equal(result.Frame.Payload, query) {
		t.Fatalf("expired negative-cache query was not forwarded in a DNS frame: %+v", result.Frame)
	}
	if result.Answer.Domain != "missing.example" || result.Answer.FakeIP == "" {
		t.Fatalf("expired negative-cache query did not allocate a fake IP: %+v", result.Answer)
	}
	if flags := binary.BigEndian.Uint16(result.Response[2:4]); flags != 0x8180 {
		t.Fatalf("expired negative-cache response flags = 0x%x, want standard no-error response", flags)
	}
	if qd, an := binary.BigEndian.Uint16(result.Response[4:6]), binary.BigEndian.Uint16(result.Response[6:8]); qd != 1 || an != 1 {
		t.Fatalf("expired negative-cache response counts qd=%d an=%d", qd, an)
	}
}

func TestDNSForwarderRejectsUnsupportedLocalDNSQuestion(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{})
	if _, err := f.AnswerLocalAQuery(92, dnsQuestion(0x1235, "example.com", 28), []string{"93.184.216.34"}, 100); err == nil {
		t.Fatalf("local DNS forwarder accepted non-A question")
	}
}

func TestDNSForwarderRejectsLocalDNSQueryWithAdditionalRecords(t *testing.T) {
	f := NewDNSForwarder(DNSForwarderOptions{})
	query := dnsQuestion(0x1236, "example.com", 1)
	binary.BigEndian.PutUint16(query[10:12], 1)
	if _, err := f.AnswerLocalAQuery(93, query, []string{"93.184.216.34"}, 100); err == nil {
		t.Fatalf("local DNS forwarder accepted nonzero additional-record count")
	}
}

func dnsQuestion(id uint16, domain string, qtype uint16) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100)
	binary.BigEndian.PutUint16(out[4:6], 1)
	for _, label := range bytes.Split([]byte(domain), []byte(".")) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, 1)
	return out
}
