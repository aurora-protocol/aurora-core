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
	if net.IP(open.TargetHost).String() != answer.FakeIP {
		t.Fatalf("flow target %v does not match fake IP %s", open.TargetHost, answer.FakeIP)
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
