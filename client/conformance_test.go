package client

import "testing"

func TestRunProxyFlowConformanceCoversP6Requirements(t *testing.T) {
	report, err := RunProxyFlowConformance()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("proxy-flow conformance report failed: %+v", report)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("proxy-flow conformance report had findings: %+v", report.Findings)
	}

	want := map[string]bool{
		"tcp_open_scheduler_backpressure_close": false,
		"udp_native_and_stream_fallback":        false,
		"udp_target_confirm_demux_ttl_idle":     false,
		"udp_fqdn_policy_and_fake_ip":           false,
		"realtime_stale_drop":                   false,
		"dns_forwarder_privacy_negative_cache":  false,
	}
	for _, c := range report.Cases {
		if _, ok := want[c.Name]; !ok {
			t.Fatalf("unexpected proxy-flow conformance case %q in %+v", c.Name, report.Cases)
		}
		if !c.Passed {
			t.Fatalf("proxy-flow conformance case %q failed: %+v", c.Name, c)
		}
		want[c.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("proxy-flow conformance report missing %q: %+v", name, report.Cases)
		}
	}
}
