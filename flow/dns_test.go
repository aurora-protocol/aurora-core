package flow

import (
	"bytes"
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
