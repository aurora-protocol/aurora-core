package protocol

import "testing"

// TestEmptyClientTransportHintsIsZero covers the zero-value constructor.
func TestEmptyClientTransportHintsIsZero(t *testing.T) {
	got := EmptyClientTransportHints()
	if got.HintFlags != 0 || got.ObservedPathMTUBucket != 0 || got.RecentQUICResult != 0 ||
		got.RecentH2Result != 0 || got.CongestionClass != 0 || got.MaxDatagramPayloadHint != 0 ||
		got.NetworkCohortHint != nil || got.Padding != nil || len(got.Extensions) != 0 {
		t.Fatalf("EmptyClientTransportHints = %+v, want zero value", got)
	}
}

// TestClientTransportHintsNormalizePrototypeClampsResults covers the clamp
// boundary: results <= 0x05 are preserved, results > 0x05 are reset to 0x00.
func TestClientTransportHintsNormalizePrototypeClampsResults(t *testing.T) {
	cases := []struct {
		quic, h2, wantQUIC, wantH2 uint8
	}{
		{0x00, 0x00, 0x00, 0x00},
		{0x05, 0x05, 0x05, 0x05},
		{0x06, 0x06, 0x00, 0x00},
		{0xff, 0x00, 0x00, 0x00},
	}
	for _, tc := range cases {
		h := ClientTransportHints{RecentQUICResult: tc.quic, RecentH2Result: tc.h2}
		got := h.NormalizePrototype()
		if got.RecentQUICResult != tc.wantQUIC || got.RecentH2Result != tc.wantH2 {
			t.Fatalf("NormalizePrototype(quic=0x%02x,h2=0x%02x) = (0x%02x,0x%02x), want (0x%02x,0x%02x)",
				tc.quic, tc.h2, got.RecentQUICResult, got.RecentH2Result, tc.wantQUIC, tc.wantH2)
		}
	}
}
