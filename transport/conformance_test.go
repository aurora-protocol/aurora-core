package transport

import "testing"

func TestRunCarrierConformanceCoversP7Requirements(t *testing.T) {
	report, err := RunCarrierConformance()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("carrier conformance report failed: %+v", report)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("carrier conformance report had findings: %+v", report.Findings)
	}

	want := map[string]bool{
		"h2_baseline_first":       false,
		"h1_websocket_fallback":   false,
		"shadow_origin_slot":      false,
		"h3_ext_datagram_gated":   false,
		"masque_visible_opt_in":   false,
		"shared_opaque_core_path": false,
	}
	for _, c := range report.Cases {
		if _, ok := want[c.Name]; !ok {
			t.Fatalf("unexpected carrier conformance case %q in %+v", c.Name, report.Cases)
		}
		if !c.Passed {
			t.Fatalf("carrier conformance case %q failed: %+v", c.Name, c)
		}
		want[c.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("carrier conformance report missing %q: %+v", name, report.Cases)
		}
	}
}
