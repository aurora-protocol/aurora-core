package route

import "testing"

func TestRunSplitRouteConformanceCoversP5Requirements(t *testing.T) {
	report, err := RunSplitRouteConformance()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("split-route conformance report failed: %+v", report)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("split-route conformance report had findings: %+v", report.Findings)
	}

	want := map[string]bool{
		"route_prelude_wrap_replay":    false,
		"route_hop_binding_separation": false,
		"route_capsule_hop_privacy":    false,
		"split2_forward_opaque_entry":  false,
		"split2_backward_opaque_entry": false,
		"packet_ad_route_hop_binding":  false,
		"route_rotation_drain_window":  false,
		"split2_independent_counters":  false,
	}
	for _, c := range report.Cases {
		if _, ok := want[c.Name]; !ok {
			t.Fatalf("unexpected split-route conformance case %q in %+v", c.Name, report.Cases)
		}
		if !c.Passed {
			t.Fatalf("split-route conformance case %q failed: %+v", c.Name, c)
		}
		want[c.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("split-route conformance report missing %q: %+v", name, report.Cases)
		}
	}
}
