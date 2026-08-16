package client

// Adversarial coverage for the pure helpers in client/conformance.go that the
// existing TestRunProxyFlowConformanceCoversP6Requirements suite reaches only
// indirectly through the happy-path RunProxyFlowConformance call:
//   - addCase (line 39, ~50% before): the !passed finding branch (45-48). The
//     conformance helpers only ever addCase with passed=true, so the failure
//     accumulator stays uncovered.
//   - dnsRCode (line 275, ~66.7% before): the short-message guard (276-277).
//   - decodeConformanceFlowOpen (line 242, ~63.6% before): the wrong-frame-type
//     rejection (243-244) and the ValidateFlowManagementFrame rejection (246-248).
//   - FormatProxyFlowConformanceReport (line 282, 0% before): the case and
//     finding loops, never reached because no test formats a populated report.
//
// Coverage is re-measured per group to confirm the intended branch moved
// (no wrong-branch bugs).
//
// Dead by design (documented, not contrived) in decodeConformanceFlowOpen:
//   - 251-252 (r.Err() after validation): ValidateFlowManagementFrame (called at
//     246) already decodes the same payload and checks r.Err() (frames.go:662)
//     and !r.EOF() (frames.go:665). When it returns nil the payload is guaranteed
//     to decode cleanly with no trailing bytes, so the re-decode at 249-250 can
//     never hit r.Err().
//   - 254-255 (!r.EOF() after validation): same guarantee — ValidateFlowManagementFrame
//     returns "trailing flow-management payload bytes" (frames.go:666) if any
//     trailing bytes exist, so reaching 254 with !r.EOF() is impossible.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

func TestProxyFlowConformanceReportAddCaseRecordsFailure(t *testing.T) {
	t.Run("failure sets finding", func(t *testing.T) {
		report := ProxyFlowConformanceReport{Passed: true}
		report.addCase("tcp_handshake", false, "handshake timed out")
		if report.Passed {
			t.Fatal("addCase(false) did not clear Passed")
		}
		if len(report.Cases) != 1 || report.Cases[0].Name != "tcp_handshake" || report.Cases[0].Passed {
			t.Fatalf("case = %+v, want a single failed tcp_handshake case", report.Cases)
		}
		if len(report.Findings) != 1 || report.Findings[0] != "tcp_handshake failed" {
			t.Fatalf("findings = %v, want [tcp_handshake failed]", report.Findings)
		}
	})
	t.Run("pass preserves Passed", func(t *testing.T) {
		report := ProxyFlowConformanceReport{Passed: true}
		report.addCase("udp_mode", true, "ok")
		if !report.Passed {
			t.Fatal("addCase(true) cleared Passed")
		}
		if len(report.Findings) != 0 {
			t.Fatalf("pass produced findings: %v", report.Findings)
		}
		if len(report.Cases) != 1 || !report.Cases[0].Passed {
			t.Fatalf("case = %+v, want a single passed udp_mode case", report.Cases)
		}
	})
}

func TestDnsRCodeHandlesShortMessageAndMasksRCode(t *testing.T) {
	t.Run("short message returns sentinel", func(t *testing.T) {
		if got := dnsRCode([]byte{0x01, 0x02}); got != 0xffff {
			t.Fatalf("dnsRCode(short) = 0x%x, want 0xffff", got)
		}
	})
	t.Run("rcode is masked to low nibble", func(t *testing.T) {
		// bytes[2:4] = 0x0005 -> rcode 5.
		if got := dnsRCode([]byte{0x00, 0x00, 0x00, 0x05}); got != 5 {
			t.Fatalf("dnsRCode = %d, want 5", got)
		}
		// bytes[2:4] = 0xffff -> rcode 0x000f (masked).
		if got := dnsRCode([]byte{0x00, 0x00, 0xff, 0xff}); got != 0x000f {
			t.Fatalf("dnsRCode = 0x%x, want 0x000f", got)
		}
	})
}

func TestFormatProxyFlowConformanceReportEmitsSummaryCasesAndFindings(t *testing.T) {
	t.Run("populated report", func(t *testing.T) {
		report := ProxyFlowConformanceReport{
			Passed: false,
			Cases: []ProxyFlowConformanceCase{
				{Name: "tcp_handshake", Passed: true, Detail: "ok"},
				{Name: "udp_mode", Passed: false, Detail: "missing"},
			},
			Findings: []string{"udp_mode failed"},
		}
		out := FormatProxyFlowConformanceReport(report)
		for _, want := range []string{
			"flow_check passed=false cases=2 failures=1",
			"flow_case tcp_handshake passed=true detail=\"ok\"",
			"flow_case udp_mode passed=false detail=\"missing\"",
			"flow_finding udp_mode failed",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("FormatProxyFlowConformanceReport missing %q:\n%s", want, out)
			}
		}
	})
	t.Run("empty report", func(t *testing.T) {
		out := FormatProxyFlowConformanceReport(ProxyFlowConformanceReport{})
		if !strings.Contains(out, "flow_check passed=false cases=0 failures=0") {
			t.Fatalf("empty report = %q, want summary with cases=0", out)
		}
	})
}

func TestDecodeConformanceFlowOpenRejectsWrongFrameType(t *testing.T) {
	frame := protocol.AuroraFrame{FrameType: 0x00, FlowID: 10, Payload: []byte{0x00}}
	_, err := decodeConformanceFlowOpen(frame)
	if err == nil || !strings.Contains(err.Error(), "expected FLOW_OPEN frame") {
		t.Fatalf("err = %v, want \"expected FLOW_OPEN frame\"", err)
	}
}

func TestDecodeConformanceFlowOpenRejectsInvalidFlowOpen(t *testing.T) {
	// Encode a FlowOpen with FlowID==0 so ValidateFlowOpen (inside
	// ValidateFlowManagementFrame) rejects it at decodeConformanceFlowOpen:246-248.
	badOpen := validConformanceFlowOpen()
	badOpen.FlowID = 0
	payload, err := protocol.Encode(badOpen)
	if err != nil {
		t.Fatalf("encode bad FlowOpen: %v", err)
	}
	frame := protocol.AuroraFrame{FrameType: registry.FrameFlowOpen, FlowID: 0, Payload: payload}
	_, err = decodeConformanceFlowOpen(frame)
	if err == nil || !strings.Contains(err.Error(), "zero flow_id") {
		t.Fatalf("err = %v, want \"zero flow_id\"", err)
	}
}

func TestDecodeConformanceFlowOpenAcceptsValid(t *testing.T) {
	open := validConformanceFlowOpen()
	frame, err := protocol.NewFlowOpenFrame(open)
	if err != nil {
		t.Fatalf("NewFlowOpenFrame: %v", err)
	}
	got, err := decodeConformanceFlowOpen(frame)
	if err != nil {
		t.Fatalf("decodeConformanceFlowOpen: %v", err)
	}
	if got.FlowID != open.FlowID || got.FlowKind != open.FlowKind || string(got.TargetHost) != string(open.TargetHost) {
		t.Fatalf("decoded FlowOpen = %+v, want %+v", got, open)
	}
}

// validConformanceFlowOpen returns a FlowOpen that passes ValidateFlowOpen and
// round-trips through NewFlowOpenFrame / decodeConformanceFlowOpen. Mirrors the
// fixture in protocol/frames_test.go:208.
func validConformanceFlowOpen() protocol.FlowOpen {
	return protocol.FlowOpen{
		FlowOpenVersion:  registry.Version20,
		FlowID:           10,
		FlowKind:         0x01,
		TargetKind:       0x03,
		TargetHost:       []byte("example.com"),
		TargetPort:       443,
		UDPFQDNMode:      0x00,
		NameBindingID:    bytes.Repeat([]byte{0x11}, 16),
		DNSAnswerSetHash: bytes.Repeat([]byte{0x22}, 48),
		LocalBindingMode: 0x00,
		PriorityClass:    0x01,
	}
}
