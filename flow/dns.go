package flow

import (
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
