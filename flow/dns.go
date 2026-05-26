package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

var ErrNegativeCached = errors.New("flow: negative DNS response cached")

type DNSForwarderOptions struct {
	FakeIPCIDR string
}

type DNSForwarder struct {
	mu        sync.Mutex
	allocator *FakeIPAllocator
	negative  map[string]uint64
}

type SyntheticAnswer struct {
	Domain           string
	FakeIP           string
	NameBindingID    []byte
	DNSAnswerSetHash []byte
}

type LocalDNSResult struct {
	Response []byte
	Frame    protocol.AuroraFrame
	Answer   SyntheticAnswer
}

func NewDNSForwarder(opts DNSForwarderOptions) *DNSForwarder {
	cidr := opts.FakeIPCIDR
	if cidr == "" {
		cidr = "198.18.0.0/15"
	}
	return &DNSForwarder{
		allocator: NewFakeIPAllocator(cidr),
		negative:  make(map[string]uint64),
	}
}

func (f *DNSForwarder) AddNegative(domain string, now uint64, ttlSeconds uint64) {
	name := canonicalDomain(domain)
	if name == "" || ttlSeconds == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.negative[name] = now + ttlSeconds
}

func (f *DNSForwarder) ResolveFakeA(domain string, answers []string, now uint64) (SyntheticAnswer, error) {
	name := canonicalDomain(domain)
	if name == "" {
		return SyntheticAnswer{}, fmt.Errorf("flow: empty DNS name")
	}
	f.mu.Lock()
	if validUntil, ok := f.negative[name]; ok {
		if now <= validUntil {
			f.mu.Unlock()
			return SyntheticAnswer{}, ErrNegativeCached
		}
		delete(f.negative, name)
	}
	f.mu.Unlock()
	fakeIP, binding, err := f.allocator.Assign(name, answers)
	if err != nil {
		return SyntheticAnswer{}, err
	}
	return SyntheticAnswer{
		Domain:           name,
		FakeIP:           fakeIP,
		NameBindingID:    binding,
		DNSAnswerSetHash: DNSAnswerSetHash(answers),
	}, nil
}

func (f *DNSForwarder) OpenFakeIPUDPFlow(flowID uint64, domain string, answers []string, port uint16, now uint64) (protocol.FlowOpen, SyntheticAnswer, error) {
	answer, err := f.ResolveFakeA(domain, answers, now)
	if err != nil {
		return protocol.FlowOpen{}, SyntheticAnswer{}, err
	}
	targetKind, targetHost, err := firstIPTarget(answers)
	if err != nil {
		return protocol.FlowOpen{}, SyntheticAnswer{}, err
	}
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       targetKind,
		TargetHost:       targetHost,
		TargetPort:       port,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    append([]byte(nil), answer.NameBindingID...),
		DNSAnswerSetHash: append([]byte(nil), answer.DNSAnswerSetHash...),
		LocalBindingMode: LocalBindingTransparentFakeIP,
		PriorityClass:    PriorityRealtime,
	}
	return open, answer, nil
}

func (f *DNSForwarder) OpenMappedFakeIPUDPFlow(flowID uint64, fakeIP string, port uint16, now uint64) (protocol.FlowOpen, SyntheticAnswer, error) {
	ip := net.ParseIP(fakeIP).To4()
	if ip == nil {
		return protocol.FlowOpen{}, SyntheticAnswer{}, fmt.Errorf("flow: fake IP must be IPv4")
	}
	mapping, ok := f.allocator.MappingForFakeIP(ip.String())
	if !ok {
		return protocol.FlowOpen{}, SyntheticAnswer{}, fmt.Errorf("flow: unknown fake IP mapping")
	}
	targetKind, targetHost, err := firstIPTarget(mapping.Answers)
	if err != nil {
		return protocol.FlowOpen{}, SyntheticAnswer{}, err
	}
	answer := SyntheticAnswer{
		Domain:           mapping.Domain,
		FakeIP:           ip.String(),
		NameBindingID:    bindingID(mapping.Domain, mapping.Answers),
		DNSAnswerSetHash: DNSAnswerSetHash(mapping.Answers),
	}
	open := protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           flowID,
		FlowKind:         FlowKindUDPAssociation,
		TargetKind:       targetKind,
		TargetHost:       targetHost,
		TargetPort:       port,
		UDPFQDNMode:      UDPFQDNClientResolvedNameBinding,
		NameBindingID:    append([]byte(nil), answer.NameBindingID...),
		DNSAnswerSetHash: append([]byte(nil), answer.DNSAnswerSetHash...),
		LocalBindingMode: LocalBindingTransparentFakeIP,
		PriorityClass:    PriorityRealtime,
	}
	return open, answer, nil
}

func (f *DNSForwarder) AnswerLocalAQuery(flowID uint64, query []byte, answers []string, now uint64) (LocalDNSResult, error) {
	domain, questionEnd, err := parseLocalAQuestion(query)
	if err != nil {
		return LocalDNSResult{}, err
	}
	answer, err := f.ResolveFakeA(domain, answers, now)
	if err != nil {
		return LocalDNSResult{}, err
	}
	frame, err := f.EncryptedDNSFrame(flowID, query)
	if err != nil {
		return LocalDNSResult{}, err
	}
	response, err := syntheticAResponse(query, questionEnd, answer.FakeIP)
	if err != nil {
		return LocalDNSResult{}, err
	}
	return LocalDNSResult{Response: response, Frame: frame, Answer: answer}, nil
}

func firstIPTarget(answers []string) (uint8, []byte, error) {
	for _, answer := range answers {
		if ip := net.ParseIP(answer).To4(); ip != nil {
			return TargetKindIPv4, append([]byte(nil), ip...), nil
		}
		if ip := net.ParseIP(answer).To16(); ip != nil {
			return TargetKindIPv6, append([]byte(nil), ip...), nil
		}
	}
	return 0, nil, fmt.Errorf("flow: no IP answer for fake-IP UDP flow")
}

func (f *DNSForwarder) EncryptedDNSFrame(flowID uint64, dnsMessage []byte) (protocol.AuroraFrame, error) {
	return protocol.NewDNSMessageFrame(flowID, dnsMessage)
}

func parseLocalAQuestion(query []byte) (string, int, error) {
	if len(query) < 12 {
		return "", 0, fmt.Errorf("flow: DNS query header is truncated")
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 {
		return "", 0, fmt.Errorf("flow: local DNS query must contain exactly one question")
	}
	if binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 || binary.BigEndian.Uint16(query[10:12]) != 0 {
		return "", 0, fmt.Errorf("flow: local DNS query must not include answer, authority, or additional records")
	}
	domain, offset, err := parseDNSName(query, 12)
	if err != nil {
		return "", 0, err
	}
	if len(query) < offset+4 {
		return "", 0, fmt.Errorf("flow: DNS question trailer is truncated")
	}
	if qtype := binary.BigEndian.Uint16(query[offset : offset+2]); qtype != 1 {
		return "", 0, fmt.Errorf("flow: local DNS forwarder only synthesizes A records")
	}
	if qclass := binary.BigEndian.Uint16(query[offset+2 : offset+4]); qclass != 1 {
		return "", 0, fmt.Errorf("flow: local DNS forwarder only accepts IN class")
	}
	if offset+4 != len(query) {
		return "", 0, fmt.Errorf("flow: local DNS query contains unsupported additional data")
	}
	return domain, offset + 4, nil
}

func parseDNSName(message []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	for {
		if offset >= len(message) {
			return "", 0, fmt.Errorf("flow: DNS name is truncated")
		}
		size := int(message[offset])
		offset++
		if size == 0 {
			break
		}
		if size&0xc0 != 0 {
			return "", 0, fmt.Errorf("flow: compressed DNS question names are unsupported")
		}
		if size > 63 || offset+size > len(message) {
			return "", 0, fmt.Errorf("flow: DNS label is invalid")
		}
		labels = append(labels, string(message[offset:offset+size]))
		offset += size
	}
	domain := canonicalDomain(joinDNSLabels(labels))
	if domain == "" {
		return "", 0, fmt.Errorf("flow: DNS question name is empty")
	}
	return domain, offset, nil
}

func syntheticAResponse(query []byte, questionEnd int, fakeIP string) ([]byte, error) {
	ip := net.ParseIP(fakeIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("flow: synthetic DNS answer must be IPv4")
	}
	out := make([]byte, questionEnd, questionEnd+16)
	copy(out, query[:questionEnd])
	binary.BigEndian.PutUint16(out[2:4], 0x8180)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 1)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	out = append(out, 0xc0, 0x0c)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, 60)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = append(out, ip...)
	return out, nil
}

func joinDNSLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	out := labels[0]
	for _, label := range labels[1:] {
		out += "." + label
	}
	return out
}
