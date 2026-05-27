package vectors

import "testing"

func TestGenerateNegativeVectorReportCoversP2RequiredFailures(t *testing.T) {
	report, err := GenerateNegativeVectorReport()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("negative vector report did not pass: %+v", report)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("negative vector report had findings: %+v", report.Findings)
	}

	want := map[string]bool{
		"malformed_public_key": false,
		"wrong_key_encoding":   false,
		"wrong_signature":      false,
		"wrong_aead_tag":       false,
		"replay":               false,
		"wrong_token":          false,
	}
	for _, c := range report.Cases {
		if _, ok := want[c.Name]; !ok {
			t.Fatalf("unexpected negative vector case %q in %+v", c.Name, report.Cases)
		}
		if !c.Rejected {
			t.Fatalf("negative vector case %q was accepted: %+v", c.Name, c)
		}
		if c.Error == "" {
			t.Fatalf("negative vector case %q did not record a rejection error/detail: %+v", c.Name, c)
		}
		want[c.Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("negative vector report missing %q: %+v", name, report.Cases)
		}
	}
}
