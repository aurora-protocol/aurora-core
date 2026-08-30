package registry

import "testing"

func TestSuiteConstants(t *testing.T) {
	cases := []struct {
		name string
		val  uint64
	}{
		{"SuiteHybrid768AESGCM", SuiteHybrid768AESGCM},
		{"SuiteHybrid768P256AESGCM", SuiteHybrid768P256AESGCM},
		{"SuiteHybrid1024AESGCM", SuiteHybrid1024AESGCM},
		{"SuiteHybrid768ChaCha20", SuiteHybrid768ChaCha20},
		{"SuiteHybrid768P256ChaCha20", SuiteHybrid768P256ChaCha20},
		{"SuiteHybrid1024ChaCha20", SuiteHybrid1024ChaCha20},
		{"SuiteLabClassical", SuiteLabClassical},
	}
	for _, tc := range cases {
		if tc.val == 0 {
			t.Errorf("%s must not be zero", tc.name)
		}
	}
	if SuiteHybrid768AESGCM == SuiteHybrid768P256AESGCM {
		t.Error("suite constants must be distinct")
	}
}

func TestPolicyConstants(t *testing.T) {
	policies := []uint64{
		PolicyFastWeb, PolicyBalancedWeb, PolicyAdversarialDPI,
		PolicyAdversarialStrict, PolicyEmergencyWeb, PolicyLab,
	}
	seen := make(map[uint64]bool)
	for _, p := range policies {
		if p == 0 {
			t.Error("policy constant must not be zero")
		}
		if seen[p] {
			t.Errorf("policy constant 0x%x is not distinct", p)
		}
		seen[p] = true
	}
}

func TestRouteConstants(t *testing.T) {
	routes := []uint64{
		RouteFast1, RouteSplit2, RouteSafe3, RouteBridgeSplit, RouteAuto,
	}
	seen := make(map[uint64]bool)
	for _, r := range routes {
		if r == 0 {
			t.Error("route constant must not be zero")
		}
		if seen[r] {
			t.Errorf("route constant 0x%x is not distinct", r)
		}
		seen[r] = true
	}
}

func TestFrameConstants(t *testing.T) {
	frames := []struct {
		name string
		val  uint64
	}{
		{"FrameStreamData", FrameStreamData},
		{"FrameDatagramData", FrameDatagramData},
		{"FrameIPPacket", FrameIPPacket},
		{"FrameDNSMessage", FrameDNSMessage},
		{"FrameControl", FrameControl},
		{"FramePathProbe", FramePathProbe},
		{"FrameKeyUpdate", FrameKeyUpdate},
		{"FramePadding", FramePadding},
		{"FrameClose", FrameClose},
		{"FrameRouteForward", FrameRouteForward},
		{"FramePriorityUpdate", FramePriorityUpdate},
		{"FrameAckHint", FrameAckHint},
		{"FrameKeyUpdateAck", FrameKeyUpdateAck},
		{"FrameKeyUpdateRequest", FrameKeyUpdateRequest},
		{"FrameFlowOpen", FrameFlowOpen},
		{"FrameUDPTargetConfirm", FrameUDPTargetConfirm},
		{"FrameFlowClose", FrameFlowClose},
	}
	seen := make(map[uint64]bool)
	for _, f := range frames {
		if f.val == 0 {
			t.Errorf("%s must not be zero", f.name)
		}
		if seen[f.val] {
			t.Errorf("%s (0x%x) is not distinct", f.name, f.val)
		}
		seen[f.val] = true
	}
}

func TestVersion20(t *testing.T) {
	if Version20 != 0x000200 {
		t.Errorf("Version20 = 0x%x, want 0x000200", Version20)
	}
}

func TestUsageAllKnownAuthority(t *testing.T) {
	expected := UsageMaySignDirectoryConsensus |
		UsageMaySignBridgeBundle |
		UsageMaySignSignedSeedRecord |
		UsageMaySignIssuerMetadata |
		UsageMayDelegatePrivateBridge |
		UsageMayRotateDirectoryAuthority
	if UsageAllKnownAuthority != expected {
		t.Errorf("UsageAllKnownAuthority = 0x%x, want 0x%x", UsageAllKnownAuthority, expected)
	}
}
