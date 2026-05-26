package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestActiveProbesCommandPrintsBaselineReport(t *testing.T) {
	var out bytes.Buffer
	if err := activeProbes(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"active_probe_baseline passed=true cases=13\n",
		"canonical http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case bad-access-hint passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
		"case malformed-key-update passed=true http_status=0 close_code=0 tls_alert=0 quic_close=0 websocket_close=0 timing_class= reflected_log=\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("active-probes output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "passed=false") {
		t.Fatalf("active-probes output contains failing case:\n%s", text)
	}
}

func TestVectorsCommandPrintsFlowManagementVectors(t *testing.T) {
	var out bytes.Buffer
	if err := vectors(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"flow_open: 420007020100045db8d82201bb01515151515151515151515151515151510000525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252020300\n",
		"udp_target_confirm: 070100045db8d82201bb5252525252525252525252525252525252525252525252525252525252525252525252525252525252525252525252520000003c0100\n",
		"flow_close: 07000100000000000000630004646f6e6500\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("vectors output missing %q:\n%s", want, text)
		}
	}
}
